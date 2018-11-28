from passlib.hash import argon2
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

def hash(str, salt=None):
    ''' Returns (salt, digest)'''
    if salt is not None:
        salt = salt.encode('utf-8')
        print(salt)
        hash = argon2.using(rounds=4, salt=salt).hash(str)
    else:
        hash = argon2.using(rounds=4).hash(str)
    salt, digest = hash.split('$')[-2:]
    return salt.encode('utf-8'), digest.encode('utf-8')

def verify_hash(str, salt, digest):
    return hash(str, salt) == (salt, digest)

def createDatabase(path, password):
    salt1, key = hash(password)
    password = None
    salt2, digest = hash(key)
    salt1, salt2 =  salt1.decode('utf-8'), salt2.decode('utf-8')
    digest = digest.decode('utf-8')
    key = None
    iv = get_random_bytes(16)
    iv = b64encode(iv).decode('utf-8')
    data = '|'.join((salt1, salt2, digest, iv)) + '\n'
    with open(path, 'w') as dbFile:
        dbFile.write(data)
    return iv

def encryptDatabase(path, db, password, database_iv):
    db_lines = []
    for entry in db:
        username, url, iv, enc = entry
        username_enc = b64encode(username)
        url_enc = b64encode(url)
        db_lines.append('|'.join((username_enc, url_enc, iv, enc)))
    db_string = '\n'.join(db_lines)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    with open(path, 'r') as dbFile:
        salt1, salt2, hash, _ = dbFile.readLine().split('|')
        first_line = '|'.join((salt1, salt2, hash, database_iv))+'\n'

    with open(path, 'w') as dbFile:
        dbFile.write(first_line)
        dbFile.write(cipher.encrypt_and_digest(db_string))

def enryptAccount(entry, password):
    username, url, _, enc = entry
    username_enc = b64encode(username)
    url_enc = b64encode(url)
    key = hash(password, salt2, digest)[1]
    password = None
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.encrypt_and_digest('|'.join(username, url, enc))
