# Tridium Niagara Password Cracker
By VenomInfoSec


## Purpose
An online password cracker that brute forces passwords for the Tridium Niagara platform.
* Hydra didn't work with the target due to multiple redirects, custom encoding scheme, and CSRF tokens.
* Currently only supports HTTP but the testCreds() method can be modified to support HTTPS since it just uses the requests module

## Help
```
C:\>python NiagaraPswd.py -h
usage: NiagaraPswd.py [-h] -l LIST -u USERNAME -f FAILURE [-r] target

Brute force Tridium Niagara AX Web Login

positional arguments:
  target                The IP or root URL of the Tridium Niagara AX Webpage

optional arguments:
  -h, --help            show this help message and exit
  -l LIST, --list LIST  The path of the wordlist to be used
  -u USERNAME, --username USERNAME
                        The username to try
  -f FAILURE, --failure FAILURE
                        The path of the webpage that illustrates what a failed
                        login attempt is
  -r, --resume          If the last attempt resulted in unexpected program
                        failure, use this option to resume from the last
                        credentail tried
  -s SCHEME, --scheme SCHEME
                        Scheme of base URL, default: http.
```

## Example
```
C:\>python NiagaraPswd.py -l phpbb-rules.txt -u admin -f default.html -s https 127.0.0.1
 [*] Initializing wordlist...

 [-] admin:YeBs2wu992 is incorrect
 [-] admin:avKNwJ2938 is incorrect
 [-] admin:dAGwAKn976 is incorrect
 [-] admin:XeesHfy623 is incorrect
 [-] admin:S8Ydn4l735 is incorrect
 [!] Keyboard Interrupt, saving last tried creds

```

## TODO
- [ ] Add support for threading
