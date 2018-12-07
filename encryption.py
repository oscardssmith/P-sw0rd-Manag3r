from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from passlib.hash import argon2

def hash(str, salt=None):
    ''' Returns (digest, digest)'''
    if salt is not None:
        salt = b64decode(salt.encode('utf-8')).rstrip(b'=')
        hash = argon2.using(rounds=4, salt=salt).hash(str)
    else:
        hash = argon2.using(rounds=4).hash(str)
    salt, digest = hash.split('$')[-2:]
    return b64decode(digest+'===='), b64decode(salt+'====')

def verify_hash(str, salt1, salt2, digest):
    x = hash(hash(str, salt1)[0], salt2)
    y = (b64decode(digest.encode('utf-8')).rstrip(b'='),
        b64decode(salt2.encode('utf-8')).rstrip(b'='))
    return x == y

def createDatabase(path, password):
    key, salt1 = hash(password)
    password = None
    digest, salt2 = hash(key)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    key = None
    parts = [b64encode(part).decode('utf-8') for part in (salt1, salt2, digest, iv)]
    data = '|'.join(parts) + '\n'
    with open(path, 'w') as dbFile:
        dbFile.write(data)
        data,tag = cipher.encrypt_and_digest(b'')
        dbFile.write(b64encode(data).decode('utf-8'))
        dbFile.write('\n')
        dbFile.write(b64encode(tag).decode('utf-8'))

    return iv

def encryptDatabase(path, db, key, database_iv):
    db_lines = []
    for entry in db:
        parts = [b64encode(part.encode('utf-8')) for part in entry]
        db_lines.append(b'|'.join(parts))
    db_string = b'\n'.join(db_lines)


    cipher = AES.new(key, AES.MODE_GCM, nonce=b64decode(database_iv))
    key = None
    with open(path, 'r') as dbFile:
        salt1, salt2, digest, _ = dbFile.readline().split('|')
        first_line = '|'.join((salt1, salt2, digest, database_iv))

    with open(path, 'w') as dbFile:
        dbFile.write(first_line)
        data, tag = cipher.encrypt_and_digest(db_string)
        dbFile.write(b64encode(data).decode('utf-8'))
        dbFile.write('\n')
        dbFile.write(b64encode(tag).decode('utf-8'))

def createAccount(db, dbName, username, url, pwd, masterpwd):
    #get salt1 then get key from masterpassworddatadatabase_ivdatabase_ivbase_iv
    with open(dbName, 'r') as dbFile:
        salt1, salt2, digest, database_iv = dbFile.readline().split('|')
    key = hash(masterpwd, salt1)[0]
    masterpwd = None

    #get random IV
    iv = get_random_bytes(16)
    #Encrypt with the new key and iv
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    username_enc = b64encode(username.encode('utf-8'))
    url_enc = b64encode(url.encode('utf-8'))
    pwd_enc = b64encode(pwd.encode('utf-8'))

    pwd, tag = cipher.encrypt_and_digest(b'|'.join((username_enc, url_enc, pwd_enc)))

    #append to existing db
    iv = b64encode(iv).decode('utf-8')
    pwd = b64encode(pwd).decode('utf-8')
    tag = b64encode(tag).decode('utf-8')
    db.append((username, url, iv, pwd, tag))

    #encrypt the whole db again
    encryptDatabase(dbName, db, key, database_iv)
