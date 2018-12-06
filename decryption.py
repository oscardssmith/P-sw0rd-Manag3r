from Crypto.Cipher import AES
from base64 import b64decode
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
    decrypted = decrypted.decode('ascii')[:-1]
    if decrypted == '':
        return [], database_iv
    for line in decrypted.split('\n'):
        name, url, iv, enc = line.split('|')
        url = b64decode(url)
        username_db = b64decode(username)
        db.append((username, url, iv, enc))
    return db, database_iv

def decryptAccount(entry, password):
    _, _, iv, enc = entry
    key = encryption.hash(password, salt1)[0]
    password = None
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    key = None
    cipher.decrypt_and_verify(enc)
    name, url, app_pw = line.split(b'|')
    return b64decode(app_pw).decode('ascii')
