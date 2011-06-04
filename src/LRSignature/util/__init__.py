'''
Copyright 2011 SRI International

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Created on Apr 27, 2011

@author: jklo
'''

import urllib2
import re
import gnupg
import os


def fetchkeys(url):
    '''
    Fetches one or more PGP public key from URL
    '''

    req = urllib2.Request(url)
    res = urllib2.urlopen(req)
    
    response = res.read()
    
    obj = re.finditer("((?!<.*)(-----BEGIN PGP PUBLIC KEY BLOCK-----\\n[^-]+-----END PGP PUBLIC KEY BLOCK-----))+", response, re.MULTILINE | re.DOTALL)
    
    rawKeys = []
    for o in obj:
        rawKeys.append(response[o.start():o.end()])
    return rawKeys

def storekey(keydata, gnupghome=os.path.expanduser(os.path.join("~", ".gnupg")), gpgbin="/usr/local/bin/gpg"):
    gpg = gnupg.GPG(gpgbinary=gpgbin, gnupghome=gnupghome)
    
    result = gpg.import_keys(keydata)
    return result.imported


if __name__ == "__main__":
    keyURLs = ["http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=0xA8A790EA220403B7",
              "http://sites.google.com/site/learningregistrytestdata/home/multiple-public-pgp-keys"]
    for url in keyURLs:
        
        keys = fetchkeys(url)
        print "Key count: {0}; URL:{1}".format(len(keys),url)
        for key in keys:
            print key
    