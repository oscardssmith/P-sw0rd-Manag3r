from base64 import b64decode, b64encode

from Crypto.Cipher import AES

import encryption

def verifyMasterPassword(dbname, password):
    with open(dbname, 'r') as dbFile:
        salt1, salt2, digest, iv = dbFile.readline().split('|')
    return encryption.verify_hash(password, salt1, salt2, digest)

def decryptDatabase(path, password):
    ''' Returns a list of (username, url, iv, enc)
        as well as the database_iv'''
    db = []
    with open(path, 'r') as dbFile:
        salt1, salt2, digest, database_iv = dbFile.readline()[:-1].split('|')
        key = encryption.hash(password, salt1)[0]
        database_iv= b64decode(database_iv)
        password = None
        cipher = AES.new(key, AES.MODE_GCM, nonce=database_iv)
        key = None
        data = b64decode(dbFile.readline())
        tag = b64decode(dbFile.readline())
    decrypted = cipher.decrypt_and_verify(data,tag)
    decrypted = decrypted.decode('utf-8')
    if decrypted == '':
        return [], database_iv
    for line in decrypted.split('\n'):
        parts = line.split('|')
        username, url, iv, enc, tag = [b64decode(part).decode('utf-8') for part in parts]
        db.append((username, url, iv, enc, tag))
    return db, database_iv

def decryptAccount(entry, dbName, password):
    with open(dbName, 'r') as dbFile:
        salt1, salt2, digest, database_iv = dbFile.readline().split('|')

    username, url, iv, pwd, tag = entry
    key = encryption.hash(password, salt1)[0]
    password = None
    cipher = AES.new(key, AES.MODE_GCM, nonce=b64decode(iv))
    key = None
    tag = b64decode(tag)
    pwd = b64decode(pwd)

    enc_pwd = cipher.decrypt_and_verify(pwd, tag)
    name, url, app_pw = enc_pwd.split(b'|')
    return b64decode(app_pw).decode('utf-8')
