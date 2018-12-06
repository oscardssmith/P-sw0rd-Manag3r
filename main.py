#!/usr/bin/python3

import password_check
from os import path
import encryption
from getpass import getpass
import sys, pyperclip

import encryption
import decryption

def main():
    while True:
        print('Welcome to P@sw0rd Manag3r')
        db, iv, dbName = openOrCreateDB()
        if(db == None and iv == None and dbName == None):
            sys.exit()
        searchOrAddAccount(db, iv, dbName)

def openOrCreateDB():
    ans = input("Press n to create a n3w @cc0unt, o to open, or q to quit\n")
    while ans.lower() not in ('n', 'o', 'q'):
        print('Command not found')
        ans = input("Press n to create a n3w @cc0unt, o to open, or q to quit\n")
    ans = ans.lower()

    if (ans == 'q'):
        return None, None, None
    elif(ans == 'n'):
        return createDatabase()
    elif (ans == 'o'):
        return signIn()

def searchOrAddAccount(db, iv, dbName):
    while True:
        ans = input("Press s to search, press n to create a new account, or q to log out\n")
        while ans.lower() not in ('s', 'n', 'q'):
            print('Command not found')
            ans = input("Press n to create a n3w @cc0unt, o to open, or q to log out\n")

        ans = ans.lower()
        if ans == 'q':
            return
        elif ans == 'n':
            newAccount(db, iv, dbName)
        elif ans == 's':
            searchDatabase(db)

def createDatabase():
    print("You are now creating a new super secure password database")
    username = input("Please enter your username \n")

    dbname = 'Passwords/' + username + ".pwd"
    if path.exists(dbname):
        print("Username already taken")
        main()

    else:
        print("Creating your database.")
        while True:
            masterpwd = getpass("Please enter your masterpassword (Choose the most complicated name that you can remember) \n")
            if(password_check.isGoodPassword(masterpwd)):
                print("Password accepted...")
                break
            else:
                print("Password ", masterpwd, " is not complex enough.")
        iv = encryption.createDatabase(dbname, masterpwd)
        print("Database created")
        return [], iv, dbname

def signIn():
    dbName = ""
    while True:
        username = input("Please enter username ")
        dbname = 'Passwords/' + username + ".pwd"
        if(path.exists(dbname)):
            dbName = dbname
            break
        ans = input("Username not found. To reenter your username press o, to create an account with this username press n, or to quit press q. \n")
        while ans.lower() not in ('n', 'o', 'q'):
            print('Command not found')
            ans = input("Press n to create a n3w @cc0unt, o to reenter username, or q to quit \n")
        ans = ans.lower()
        if ans == 'n':
            return createDatabase()
        elif ans == 'q':
            return

    masterpwd = getpass("Username found.  Please enter your password. \n")

    while not decryption.verifyMasterPassword(dbname, masterpwd):
        print("Password incorrect")
        ans = input("To reenter your password press p, or press q to quit. \n")
        while ans.lower() not in ('p', 'q'):
            print('Command not found')
            ans = input("To reenter your password press p, or press q to quit. \n")
        ans = ans.lower()
        if ans == 'q':
            return
        masterpwd = input("Please enter your password. \n")
    print("Password verified.")
    db, iv = decryption.decryptDatabase(dbName, masterpwd)
    print("Decryption successful.")
    print("Welcome ", username, " to your p@ssw0rd database")
    return db, iv, dbName

def searchDatabase(db):
    search = input("Please enter a url or username \n")
    while True:
        matches = []
        for entry in db:
            if entry[0] == search or entry[1] == search:
                matches.append(entry)
        if len(matches) == 1:
            getAccountPassword(matches)
            return
        elif len(matches) > 1 :
            print("More than one entry found with your username or url. Please enter your username and then url")
            username = input("Username: ")
            url = input("Url: ")
            for entry in matches:
                if entry[0] == username and entry[1] == url:
                    getAccountPassword(matches)
                    return
        else:
            print("Url and/or username did not match any stored in the database")
            return

def getAccountPassword():
    print("Entry found")
    masterpwd = getpass("Please enter your master password \n")
    while not decryption.verifyMasterPassword(dbname, masterpwd):
        print("Password incorrect")
        ans = input("To reenter your master password press p, or press q to quit. \n")
        while ans.lower() not in ('p', 'q'):
            print('Command not found')
            ans = input("To reenter your master password press p, or press q to quit. \n")
        ans = ans.lower()
        if ans == 'q':
            return
        masterpwd = getpass("Please enter your master password. \n")
    print("Master password verified.")
    print(decryption.decryptAccount(matches[0], masterpwd))
    print("Account password verified.")
    pyperclip.copy(decryption.decryptAccount(db[location], masterpwd))
    print(pyperclip.paste())
    print("Account password copied to clipboard")

def newAccount(db, iv, dbName):
    print("Please enter the account username and url for your new account or press q to exit \n")
    username = input("Username: ")
    if username == 'q':
        return
    url = input("Url: ")
    if username == 'q':
        return
    for entry in db:
        if entry[0] == username and entry[1] == url:
            ans = input("Password already exists for this username and url.  Would you like to create a new password? (y/n): ")
            while ans.lower() not in ('y', 'n'):
                print('Command not found')
                ans = input("Please enter y to create a new password or n to return")
            ans = ans.lower()
            if ans == 'n':
                print("Returning to menu...")
                return
            if ans == 'y':
                break
    len = getNumInput("Please enter the length for this password\n")

    forbidden_char = input("Please enter unallowed characters\n")
    masterpwd = getpass("Please enter your master password \n")
    while not decryption.verifyMasterPassword(dbName, masterpwd):
        print("Password incorrect")
        ans = input("To reenter your master password press p, or press q to quit. \n")
        while ans.lower() not in ('p', 'q'):
            print('Command not found')
            ans = input("To reenter your master password press p, or press q to quit. \n")
        ans = ans.lower()
        if ans == 'q':
            return
        masterpwd = getpass("Please enter your master password. \n")
    print("Master password verified.")
    #masterpwd = None
    print("Creating new password...")
    pwd = password_check.generateRandomPassword(len, set(forbidden_char))
    encryption.createAccount(db, dbName, username, url, pwd, masterpwd)
    pyperclip.copy(decrypt.decryptAccount(db[location], masterpwd))
    print("Account password copied to clipboard")

def getNumInput(str):
    try:
        return int(input(str))
    except valueError:
        return getNumInput(str)

if __name__ == '__main__':
    main()
