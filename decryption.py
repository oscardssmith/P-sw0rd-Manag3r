from Crypto.Cipher import AES
from base64 import b64decode
import encryption

def verifyMasterPassword(dbname, password):
    with open(dbname, 'r') as dbFile:
        salt1, salt2, digest, iv = dbFile.readline().split('|')
    return encryption.verify_hash(encryption.hash(password, salt1), salt2, digest)

def decryptDatabase(path, password):
    ''' Returns a list of (username, url, iv, enc)
        as well as the database_iv'''
    db = []
    with open(path, 'r') as dbFile:
        salt1, salt2, hash, database_iv = dbFile.readLine()[:-1].split('|')
        key = hash(password, salt2, digest)[1]
        password = None
        cipher = AES.new(key, AES.MODE_GCM, nonce=database_iv)
        key = None
        decrypted = cipher.decrypt_and_verify(db_file.read())

    for line in decrypted.split('\n'):
        name, url, iv, enc = line.split('|')
        url = b64decode(url)
        username_db = b64decode(username)
        db.append((username, url, iv, enc))
    return db, database_iv

def decryptAccount(entry, password):
    _, _, iv, enc = entry
    key = hash(password, salt2, digest)[1]
    password = None
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    key = None
    cipher.decrypt_and_verify(enc)
    name, url, app_pw = line.split('|')
    return app_pw
