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

Created on May 11, 2011

@author: jklo
'''
import unittest, os, errno
import gnupg
from LRSignature import util as util

class Test(unittest.TestCase):
    '''Unit test cases for testing utility methods'''
    
    def mkdir_p(self, path):
        try:
            os.makedirs(path)
        except OSError as exc: # Python >2.5
            if exc.errno == errno.EEXIST:
                pass
            else: raise
    def rm_rf(self, path):
        for r,d,f in os.walk(path):
            for files in f:
                os.remove ( os.path.join(r,files) )
            os.removedirs( r ) 
            
    def chmod(self, path, mode):
        try:
            os.chmod(path, mode)
        except:
            pass

    def setUp(self):
        self.gnupghome =  os.path.expanduser(os.path.abspath(os.path.join("..", "gnupg_home")))
        self.gpgbin = 'gpg'
        
        self.rm_rf(self.gnupghome)
        self.mkdir_p(self.gnupghome)
        
        self.gpg = gnupg.GPG(gnupghome=self.gnupghome, gpgbinary=self.gpgbin)
        
        self.sampleKeyId="A8A790EA220403B7"
        self.sampleKeyFingerprint="E8BCBCB8994A293C10DDCBC5A8A790EA220403B7"
        self.sampleKey = '''-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: PGP Universal 2.9.1 (Build 347)

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
Mi8vo0LKU7qAlMXpAa5+tw==
=aCWc
-----END PGP PUBLIC KEY BLOCK-----'''
        


    def tearDown(self):
        self.rm_rf(self.gnupghome)
        pass

    def checkKey(self, key, keysource=""):
        '''Utility method to check to see if fetched key is valid by importing into GPG keyring'''
        keys = self.gpg.list_keys(secret=False)
        numkeys = len(keys)
        
        result = self.gpg.import_keys(key)
        assert result != None and result.imported == 1, "GPG import does not indicate key import occurred for {0}.".format(keysource)
        
        keys = self.gpg.list_keys(secret=False)
        assert len(keys) == numkeys+1, "Imported key did not get added to keyring for {0}.".format(keysource)
        
    def testPGPFetchKey(self):
        '''Attempt to retrieve key via HTTP GET from Symantec's PGP keyserver'''
        keyURL = "http://keyserver.pgp.com/vkd/DownloadKey.event?keyid=0xA8A790EA220403B7"
        fetchedKeys = util.fetchkeys(keyURL)
        assert len(fetchedKeys) == 1, "key could not be retrieved from URL"
        
        self.checkKey(fetchedKeys[0], keysource="PGP sourced key")
        
        
    def testSKSFetchKey(self):
        '''Attempt to retrieve key via HTTP GET from SKS keyserver'''
        keyURL = "http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=0xA8A790EA220403B7"
        fetchedKeys = util.fetchkeys(keyURL)
        assert len(fetchedKeys) == 1, "key could not be retrieved from URL"
        
        self.checkKey(fetchedKeys[0], keysource="SKS source key")
        
    def testWebSiteFetchKey(self):
        '''Attempt to retrieve key via HTTP GET that is a part of an HTML web page'''
        keyURL = "http://sites.google.com/site/learningregistrytestdata/home/single-public-pgp-key"
        fetchedKeys = util.fetchkeys(keyURL)
        assert len(fetchedKeys) == 1,  "key could not be retrieved from URL"
        
        self.checkKey(fetchedKeys[0], keysource="HTML Web Page sourced key")
        
    def testHTTPFetchKey(self):
        '''Attempt to retrieve key via HTTP GET that is a part of a file download request'''
        keyURL = "http://sites.google.com/site/learningregistrytestdata/home/single-public-pgp-key/key0xA8A790EA220403B7.asc?attredirects=0&d=1"
        fetchedKeys = util.fetchkeys(keyURL)
        assert len(fetchedKeys) == 1, "key could not be retrieved from URL"
        
        self.checkKey(fetchedKeys[0], keysource="HTTP Download sourced key")
        
    def testMultipleFetchKey(self):
        '''Attempt to retrieve multiple keys via HTTP GET that is a part of a file download request'''
        keyURL = "http://sites.google.com/site/learningregistrytestdata/home/multiple-public-pgp-keys"
        fetchedKeys = util.fetchkeys(keyURL)
        assert len(fetchedKeys) == 2, "keys could not be retrieved from URL"
        
        self.checkKey(fetchedKeys[0], keysource="HTTP Download sourced key 1")
        self.checkKey(fetchedKeys[1], keysource="HTTP Download sourced key 2")
        
    def testGoogleDocFetchKey(self):
        '''Attempt to retrieve key via HTTP file download via Google Docs'''
        keyURL = "https://docs.google.com/uc?id=0ByJYdR0YE41yNDg2ZTkzYTItNmJjNC00YTgwLTkyYzctZTNiMzAwYzhjYTdh&export=download&hl=en"
        fetchedKeys = util.fetchkeys(keyURL)
        assert len(fetchedKeys) == 1, "key could not be retrieved from URL"
        
        self.checkKey(fetchedKeys[0], keysource="Google Doc source key")

    
    def testStoreKey(self):
        '''Use a known ASCII Armored key and store it via util.storekey(...)'''
        
        keys = self.gpg.list_keys(secret=False)
        for key in keys:
            assert key['keyid'] != self.sampleKeyId, "Imported sample key already in keyring"
        
        numkeys = len(keys)
        
        numImported = util.storekey(self.sampleKey, gnupghome=self.gnupghome, gpgbin=self.gpgbin)
        
        assert numImported == 1, "sample key not imported into keyring"
        
        keys = self.gpg.list_keys(secret=False)
        
        assert len(keys) == 1, "no key found matching id"
        for key in keys:
            assert key['keyid'] == self.sampleKeyId, "exported key is not expected"
            
            
    
    def testStoreExistingKey(self):
        '''Use a known ASCII Armored key and try storing it twice.  It should not get imported a second time'''
        
        keys = self.gpg.list_keys(secret=False)
        for key in keys:
            assert key['keyid'] != self.sampleKeyId, "Imported sample key already in keyring"
        
        numkeys = len(keys)
        
        numImported = util.storekey(self.sampleKey, gnupghome=self.gnupghome, gpgbin=self.gpgbin)
        
        assert numImported == 1, "sample key not imported into keyring"
        
        numImported = util.storekey(self.sampleKey, gnupghome=self.gnupghome, gpgbin=self.gpgbin)
        
        assert numImported == 0, "sample key imported when it shouldn't have been into keyring"
        
        keys = self.gpg.list_keys(secret=False)
        
        assert len(keys) == 1, "no key found matching id"
        for key in keys:
            assert key['keyid'] == self.sampleKeyId, "exported key is not expected"
    

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testFetchKey']
    unittest.main()