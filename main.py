#!/usr/bin/python3

from os import path
import sys, time

from getpass import getpass
import pyperclip

import encryption
import decryption
import password_check

def main():
    while True:
        print('Welcome to P@sw0rd Manag3r')
        db, iv, dbName = openOrCreateDB()
        if(db == None or iv == None or dbName == None):
            return
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
    prompt = "Press s to search, press n to create a new account, or q to log out\n"
    while True:
        ans = input(prompt)
        while ans.lower() not in ('s', 'n', 'q'):
            print('Command not found')
            ans = input(prompt)
        ans = ans.lower()
        if ans == 'q':
            return
        elif ans == 'n':
            newAccount(db, iv, dbName)
        elif ans == 's':
            searchDatabase(db, dbName)

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

    masterpwd = getMasterPassword(dbName)
    db, iv = decryption.decryptDatabase(dbName, masterpwd)
    print("Decryption successful.")
    print("Welcome ", username, " to your p@ssw0rd database")
    return db, iv, dbName

def searchDatabase(db, dbName):
    search = input("Please enter a url or username \n")
    while True:
        matches = []
        for entry in db:
            if entry[0] == search or entry[1] == search:
                matches.append(entry)
        if len(matches) == 1:
            print("Entry found")
            getAccountPassword(entry, dbName)
            break
        elif len(matches) > 1 :
            print("More than one entry found with your username or url. Please enter your username and then url")
            username = input("Username: ")
            url = input("Url: ")
            for entry in matches:
                if entry[0] == username and entry[1] == url:
                    getAccountPassword(entry, dbName)
                    break
        else:
            print("Url and/or username did not match any stored in the database")
            break

def getAccountPassword(entry, dbName, masterpwd = None):
    if masterpwd == None:
        masterpwd = getMasterPassword(dbName)
    pyperclip.copy(decryption.decryptAccount(entry, dbName, masterpwd))
    masterpwd = None
    print("Account password copied to clipboard. It will be cleared in 30 seconds")
    time.sleep(30)
    pyperclip.copy('')

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
    masterpwd = getMasterPassword(dbName)
    pwd = password_check.generateRandomPassword(len, set(forbidden_char))
    encryption.createAccount(db, dbName, username, url, pwd, masterpwd)
    getAccountPassword(entry, dbName, masterpwd = masterpwd)

def getMasterPassword(dbName):
    PWD_ENTER_PROMPT = "Please enter your master password \n"
    PWD_RE_ENTER_PROMPT = "To reenter your password press p, or press q to quit. \n"
    masterpwd = getpass(PWD_ENTER_PROMPT)
    while not decryption.verifyMasterPassword(dbName, masterpwd):
        print("Password incorrect")
        ans = input(PWD_RE_ENTER_PROMPT)
        while ans.lower() not in ('p', 'q'):
            print('Command not found')
            ans = input(PWD_RE_ENTER_PROMPT)
        ans = ans.lower()
        if ans == 'q':
            return
        masterpwd = getpass(PWD_ENTER_PROMPT)
    print("Master password verified.")
    return masterpwd

def getNumInput(str):
    try:
        return int(input(str))
    except valueError:
        return getNumInput(str)

if __name__ == '__main__':
    main()
