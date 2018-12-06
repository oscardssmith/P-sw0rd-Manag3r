
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from passlib.hash import argon2
from Crypto.Random import get_random_bytes

def hash(str, salt=None):
    ''' Returns (salt, digest)'''
    if salt is not None:
        salt = b64decode(salt.encode('ascii')).rstrip(b'=')
        hash = argon2.using(rounds=4, salt=salt).hash(str)
    else:
        hash = argon2.using(rounds=4).hash(str)
    salt, digest = hash.split('$')[-2:]
    return b64decode(digest+'===='), b64decode(salt+'====')

def verify_hash(str, salt1, salt2, digest):
    x = hash(hash(str, salt1)[0], salt2)
    y = (b64decode(digest.encode('ascii')).rstrip(b'='),
        b64decode(salt2.encode('ascii')).rstrip(b'='))
    return x == y

def createDatabase(path, password):
    key, salt1 = hash(password)
    password = None
    digest, salt2 = hash(key)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    key = None
    parts = [b64encode(part).decode('ascii') for part in (salt1, salt2, digest, iv)]
    data = '|'.join(parts) + '\n'
    with open(path, 'w') as dbFile:
        dbFile.write(data)
        data,tag = cipher.encrypt_and_digest(b'')
        dbFile.write(b64encode(data).decode('ascii'))
        dbFile.write('\n')
        dbFile.write(b64encode(tag).decode('ascii'))

    return iv

def encryptDatabase(path, db, password, database_iv):
    db_lines = []
    for entry in db:
        print(entry)
        parts = [b64encode(part.encode('ascii')) for part in entry]
        db_lines.append(b'|'.join(parts))
    db_string = b'\n'.join(db_lines)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    with open(path, 'r') as dbFile:
        salt1, salt2, digest, _ = dbFile.readLine().split('|')
        first_line = '|'.join((salt1, salt2, digest, database_iv))+'\n'

    with open(path, 'w') as dbFile:
        dbFile.write(first_line)
        data,tag = cipher.encrypt_and_digest(db_string)
        dbFile.write(b64encode(data.encode('ascii')).decode('ascii'))
        dbFile.write('\n')
        dbFile.write(b64encode(tag.encode('ascii')).decode('ascii'))

# def encryptAccount(username, url, iv, key, password):
#     username_enc = b64encode(username)
#     url_enc = b64encode(url)
#     # key = hash(password, salt2)[0]
#     #password = None
#     cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
#     key = None
#
#     return cipher.encrypt_and_digest('|'.join(username, url, password))

def createAccount(db, dbName, username, url, pwd, masterpwd):
    #get salt1 then get key from masterpassword
    with open(dbName, 'r') as dbFile:
        salt1, salt2, digest, database_iv = dbFile.readline().split('|')
    key = hash(masterpwd, salt1)[0]

    #get random IV
    iv = get_random_bytes(16)
    #Encrypt with the new key and iv
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    username_enc = b64encode(username.encode('ascii'))
    url_enc = b64encode(url.encode('ascii'))
    pwd_enc = b64encode(pwd.encode('ascii'))

    enc_pwd, tag = cipher.encrypt_and_digest(b'|'.join((username_enc, url_enc, pwd_enc)))

    #append to existing db
    iv = b64encode(iv).decode('ascii')
    db.append((username, url, iv, enc_pwd, tag))

    #encrypt the whole db again
    encryptDatabase(dbName, db, masterpwd, database_iv)
