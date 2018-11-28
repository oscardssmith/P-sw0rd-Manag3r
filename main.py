import password_check
from os import path
import encryption
from Crypto import Random
import sys

def main():
    while True:
        print('Welcome to P@sw0rd Manag3r')
        openOrCreateDB()
        searchOrAddAccount()

def openOrCreateDB():
    ans = input("Press n to create a n3w @cc0unt, o to open, or q to quit")
    while ans.lower() not in ('n', 'o', 'q'):
        print('Command not found')
        ans = input("Press n to create a n3w @cc0unt, o to open, or q to quit")
    ans = ans.lower()

    if (ans == 'q'):
        sys.exit()
    elif(ans == 'n'):
        db, iv = createDatabase()
    elif (ans == 'o'):
        db, iv = signIn()
        ans = input("Press s to search for a password, n to enter a new account, or q to exit.")

def searchOrAddAccount():
    while True:
        ans = input("Press s to search, press n to create a new account, or q to log out")
        while ans.lower() not in ('s', 'n', 'q'):
            print('Command not found')
            ans = input("Press n to create a n3w @cc0unt, o to open, or q to log out")

        ans = ans.lowercase()
        if ans == 'q':
            return
        elif ans == 'n':
            newAccount(iv)
        elif ans == 's':
            searchDatabase(db)

def createDatabase():
    print("You are now creating a new super secure password database")
    username = input("Please enter your username")
    print("Checking for database with username ", username, " ...")

    dbname = 'Passwords/' + username + ".pwd"
    if path.exists(dbname):
        print "Username already taken"
        main()

    else:
        print("Creating your database")
        with open(dbname, 'w') as dbFile:
            masterpwd = input("Please enter your masterpassword (Choose the most complicated name that you can remember)")
            salt1, key = hash(masterpwd)
            salt2, digest = hash(key)
            key = None
            iv = get_random_bytes(16)
            data = '|'.join(salt1, salt2, digest, iv)
            dbFile.write(data)
            print("Database created")
        return [], iv


def signIn():
    while True:
        username = input("Please enter username")
        print("Checking for database with username ", username, " ...")
        dbname = 'Passwords/' + username + ".pwd"
        if(path.exists(dbname)):
            break
        ans = input("Username not found. To reenter your username press o, to create an account with this username press n, or to quit press q.")
        while ans.lower() not in ('n', 'o', 'q'):
            print('Command not found')
            ans = input("Press n to create a n3w @cc0unt, o to reenter username, or q to quit")
        ans = ans.lower()
        if ans == 'n':
            createDatabase()
        elif ans == 'q':
            return
    masterpwd = input("Username found.  Please enter your password.")
    print("Password being verified...")
    while not verifyMasterPassword(dbname, masterpwd):
        print("Password incorrect")
        ans = input("To reenter your password press p, or press q to quit.")
        while ans.lower() not in ('p', 'q'):
            print('Command not found')
            ans = input("To reenter your password press p, or press q to quit.")
        ans = ans.lower()
        if ans == 'q':
            return
        masterpwd = input("Please enter your password.")
        print("Password being verified...")
    print("Password verified.")
    print("Decrypting database...")
    url_db, username_db = decryptDatabase(dnname, masterpwd)
    print("Decryption successful.")
    print("Welcome ", username, " to your p@ssw0rd database")
    return database

def verifyMasterPassword(dbname, password):
    with open(dbname) as dbFile:
        storedpasswordhash = dbFile.readLine()
    salt1, salt2, hash, iv = dbFile.readLine().split('|')
    return verify_hash(hash(password, salt1), salt2)

def searchDatabase(db):
    search = input("Please enter a url or username")
    while True:
        location = 0
        counter = 0
        for entry in db:
            if entry[0] == search or entry[1] == search:
                location = 0
                counter += 1
        if counter == 0:
            print("Url or username did not match any stored in the database")
            return
        elif counter == 2:




if __name__ == '__main__':
    main()
