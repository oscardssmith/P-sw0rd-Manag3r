from Crypto.Cipher import AES
from base64 import base64decode

def decryptDatabase(path, password):
    ''' Returns a list of (username, url, iv, enc)
        as well as the database_iv'''
    db = []
    with open(path) as dbFile:
        salt1, salt2, hash, database_iv = dbFile.readLine().split('|')
        key = hash(password, salt2, digest)[1]
        password = None
        cipher = AES.new(key, AES.MODE_GCM, nonce=database_iv)
        key = None
        decrypted = cipher.decrypt_and_verify(db_file.read())

    for line in decrypted.split('\n'):
        name, url, iv, enc = line.split('|')
        url = base64decode(url)
        username_db = base64decode(username)
        db.append((username, url, iv enc))
    return db, database_iv
