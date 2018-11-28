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
        db, iv = openOrCreateDB()
        searchOrAddAccount(db, iv)

def openOrCreateDB():
    ans = input("Press n to create a n3w @cc0unt, o to open, or q to quit\n")
    while ans.lower() not in ('n', 'o', 'q'):
        print('Command not found')
        ans = input("Press n to create a n3w @cc0unt, o to open, or q to quit\n")
    ans = ans.lower()

    if (ans == 'q'):
        sys.exit()
    elif(ans == 'n'):
        return createDatabase()
    elif (ans == 'o'):
        return signIn()

def searchOrAddAccount(db, iv):
    while True:
        ans = input("Press s to search, press n to create a new account, or q to log out\n")
        while ans.lower() not in ('s', 'n', 'q'):
            print('Command not found')
            ans = input("Press n to create a n3w @cc0unt, o to open, or q to log out\n")

        ans = ans.lower()
        if ans == 'q':
            return
        elif ans == 'n':
            newAccount(iv)
        elif ans == 's':
            searchDatabase(db)

def createDatabase():
    print("You are now creating a new super secure password database")
    username = input("Please enter your username \n")
    print("Checking for database with username ", username, " ...")

    dbname = 'Passwords/' + username + ".pwd"
    if path.exists(dbname):
        print("Username already taken")
        main()

    else:
        print("Creating your database")
        masterpwd = getpass("Please enter your masterpassword (Choose the most complicated name that you can remember) \n")
        iv = encryption.createDatabase(dbname, masterpwd)
        print("Database created")
        return [], iv

def signIn():
    while True:
        username = input("Please enter username ")
        print("Checking for database with username ", username, " ...")
        dbname = 'Passwords/' + username + ".pwd"
        if(path.exists(dbname)):
            break
        ans = input("Username not found. To reenter your username press o, to create an account with this username press n, or to quit press q. \n")
        while ans.lower() not in ('n', 'o', 'q'):
            print('Command not found')
            ans = input("Press n to create a n3w @cc0unt, o to reenter username, or q to quit \n")
        ans = ans.lower()
        if ans == 'n':
            createDatabase()
        elif ans == 'q':
            return

    masterpwd = getpass("Username found.  Please enter your password. \n")
    print("Password being verified...")

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
        print("Password being verified...")
    print("Password verified.")
    print("Decrypting database...")
    url_db, username_db = decryption.decryptDatabase(dnname, masterpwd)
    print("Decryption successful.")
    print("Welcome ", username, " to your p@ssw0rd database")
    return database

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
            print("More than one entry found with your username or url. Please enter your username and then url \n")
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
        print("Master password being verified...")
    print("Master password verified.")
    print("Decrypting...")
    print(decryption.decryptAccount(matches[0], masterpwd))
    print("Account password verified.")
    print("Copying account password to clipboard...")
    pyperclip.copy(decryption.decryptAccount(db[location], masterpwd))
    print(pyperclip.paste())
    print("Account password copied to clipboard")

def newAccount(db, iv):
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
            ans = ans.lower()
            if ans == 'y':
                break
            elif ans == 'n':
                print("Returning to menu...")
                return
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
        print("Master password being verified...")
    print("Master password verified.")
    print("Creating new password...")
    createaccount(username, url)
    print("Copying account password to clipboard...")
    pyperclip.copy(decrypt.decryptAccount(db[location], masterpwd))
    print("Account password copied to clipboard")

if __name__ == '__main__':
    main()
