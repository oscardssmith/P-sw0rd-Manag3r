from passlib.hash import argon2
from base64 import base64encode

def hash(str, salt=None):
    ''' Returns (salt, digest)'''
    if salt is not None:
        hash = argon2.using(rounds=4).hash(str, salt=salt)
    else:
        hash = argon2.using(rounds=4).hash(str)
    return hash.split('$')[-2:]

def verify_hash(str, salt, digest):
    return hash(str) == (salt, digest)


def encryptDatabase(path, db, password, iv):
    db_lines = []
    for entry in db:
        url_db[base64decode(url)] = (iv, enc)
        username_db[base64decode(username)] = (iv, enc)
        db_lines.append('|'.join(name, url, iv, enc))
    db_string = '\n'.join(db_lines)

    password = None
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    with open(path, 'w') as dbFile:
        dbFile.write()
        salt1, salt2, hash, iv = dbFile.readLine().split('|')
        key = hash(password, salt2, digest)[1]
        key = None
        decrypted = cipher.decrypt_and_verify(db_file.read())
    lines = decrypted.split('\n')
    return (url_db, username_db)
