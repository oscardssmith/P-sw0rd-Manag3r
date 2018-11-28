import os

def isGoodPassword(password):
    if len(password) <= 8:
        return False
    with open('passwords.txt') as bad_passwords:
        bad_passwords = set(line[:-1] for line in bad_passwords)
        return _process(password) not in bad_passwords

def _process(password):
    subs = {'0':'o',
            '3':'e',
            '5':'s',
            '$':'s',
            '(':'c',
            '@':'a',
            }
    password = password.lower()
    for k, v in subs.items():
        password.replace(k, v)
    return password

if __name__ == '__main__':
    print(isGoodPassword('96675091asdfasdfasfd'))
