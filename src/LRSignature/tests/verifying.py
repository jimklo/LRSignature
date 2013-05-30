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

Created on May 9, 2011

@author: jklo
'''
import unittest, calendar, copy, logging, os
import json
from gnupg import GPG
import time
from LRSignature.sign.Sign import Sign_0_21
from LRSignature.verify.Verify import Verify_0_21
from LRSignature import errors as errors

#logging.basicConfig(level=logging.DEBUG,format="%(asctime)s %(levelname)-5s %(name)-10s %(threadName)-10s %(message)s")

log =  logging.getLogger(__name__)


class Test(unittest.TestCase):
    '''Unit tests for validating signed envelopes from the Learning Registry''' 
    def __init__(self, methodName="runTest"):
        self.sampleJSON = '''
            {
                "_id":"00e3f67232e743b6bc2a079bd98ff55a",
                "_rev":"1-8163d32f6cc9996f2b7228d8b5db7962",
                "doc_type":"resource_data",
                "update_timestamp":"2011-03-14 13:36:04.617999",
                "resource_data":"<oai_dc:dc xmlns:oai_dc=\\"http://www.openarchives.org/OAI/2.0/oai_dc/\\" xmlns:dc=\\"http://purl.org/dc/elements/1.1/\\" xmlns:xsi=\\"http://www.w3.org/2001/XMLSchema-instance\\" xmlns=\\"http://www.openarchives.org/OAI/2.0/\\" xsi:schemaLocation=\\"http://www.openarchives.org/OAI/2.0/oai_dc/                          http://www.openarchives.org/OAI/2.0/oai_dc.xsd\\">\\n<dc:title>A chat about America. October and November, 1884.</dc:title>\\n<dc:creator>J. P.</dc:creator>\\n<dc:subject>United States--Description and travel.</dc:subject>\\n<dc:description>\\"Printed for private circulation only.\\"</dc:description>\\n<dc:description>Electronic reproduction. Washington, D.C. : Library of Congress, [2002-2003]</dc:description>\\n<dc:publisher>Manchester, Palmer &amp; Howe</dc:publisher>\\n<dc:date>1885</dc:date>\\n<dc:type>text</dc:type>\\n<dc:identifier>http://hdl.loc.gov/loc.gdc/lhbtn.12281</dc:identifier>\\n<dc:language>eng</dc:language>\\n<dc:coverage>United States</dc:coverage>\\n</oai_dc:dc>\\n      ",
                "keys":["United States--Description and travel.","eng"],
                "submitter_type":"agent",
                "resource_data_type":"metadata",
                "payload_schema_locator":"http://www.openarchives.org/OAI/2.0/oai_dc/ http://www.openarchives.org/OAI/2.0/oai_dc.xsd",
                "payload_placement":"inline",
                "submitter":"NSDL 2 LR Data Pump",
                "payload_schema":["oai_dc"],
                "node_timestamp":"2011-03-14 13:36:04.617999",
                "doc_version":"0.10.0",
                "create_timestamp":"2011-03-14 13:36:04.617999",
                "active":true,
                "publishing_node":"string",
                "resource_locator":"http://hdl.loc.gov/loc.gdc/lhbtn.12281",
                "doc_ID":"00e3f67232e743b6bc2a079bd98ff55a",
                "TOS": {
                    "submission_TOS": "http://example.com/tos/unknown",
                    "submission_attribution": "unidentified"
                }
            }
            '''
        
        self.sampleKeyLocations = [
                                   "http://example.com/mykey",
                                   "http://example2.com/mykey"
                                   ]
        
        self.gpgbin="gpg"
        self.gnupgHome = os.path.expanduser(os.path.abspath(os.path.join("..", "gnupg_home")))
        self.gpg = None
        
        self.testDataDir = None
        self.testDataUnicode = None

        configFile = os.path.join("config.cfg")
        if os.path.exists(configFile):
            config = json.load(file(configFile))
            
            if config.has_key("global"):
                if config["global"].has_key("testdata") and os.path.exists(config["global"]["testdata"]):
                    self.testDataDir = config["global"]["testdata"]

                if config["global"].has_key("testdata_unicode") and os.path.exists(config["global"]["testdata_unicode"]):
                    self.testDataUnicode = config["global"]["testdata_unicode"]
        
        unittest.TestCase.__init__(self, methodName)


    def setUp(self):
        
        now = time.localtime()
        now = calendar.timegm(now)
        

        try:
            for root, dirs, files in os.walk(self.gnupgHome):
                for filename in files:
                    try:
                        os.unlink(os.path.join(root, filename))
                    except:
                        pass
                os.removedirs( root )
        except:
            pass

        os.makedirs(self.gnupgHome)


        self.gpg = GPG(gpgbinary=self.gpgbin, gnupghome=self.gnupgHome)

        
        self.privateEmail = "privateTest-{0}@learningregistry.org".format(now)
        self.privateEmail2 = "privateTest2-{0}@learningregistry.org".format(now)
        self.genericPassphrase = "supersecret"
        
        input = self.gpg.gen_key_input(name_email=self.privateEmail, passphrase=self.genericPassphrase)
        self.privateKey = self.gpg.gen_key(input)
        
       
        

        input = self.gpg.gen_key_input(name_email=self.privateEmail2, passphrase=self.genericPassphrase)
        self.privateKey2 = self.gpg.gen_key(input)
        
        self.privExport = self.gpg.export_keys([self.privateKey.fingerprint, self.privateKey2.fingerprint], secret=True)
        self.pubExport = self.gpg.export_keys([self.privateKey.fingerprint, self.privateKey2.fingerprint], secret=False)
        
        pass


    def tearDown(self):
        self.gpg.delete_keys([self.privateKey.fingerprint, self.privateKey2.fingerprint], secret=True)
        self.gpg.delete_keys([self.privateKey.fingerprint, self.privateKey2.fingerprint], secret=False)
        pass


    def testGetSignatureBlock(self):
        '''Check that signature block validation correctly returns a structurally valid response'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "envelope did not sign correctly"
        
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        sigInfo = verifytool._getSignatureInfo(signed)
        
        assert sigInfo != None, "signature extraction from envelope failed"
        
        assert sigInfo.has_key("signing_method") and sigInfo["signing_method"] == verifytool.signatureMethod, "signing_method is missing from signature block"
        
        assert sigInfo.has_key("signature") and sigInfo["signature"] != None and len(sigInfo["signature"]) > 0, "signature field is missing, null or is empty"
        
        assert sigInfo.has_key("key_location") and sigInfo["key_location"] == self.sampleKeyLocations, "key_location field is not correct"
        
        assert sigInfo.has_key("key_owner") and sigInfo["key_owner"] == signtool._get_privatekey_owner(), "key_owner field does not match signing key"

    def testBadSignatureBlockMissingLocation(self):
        '''Check that signature block validation correctly checks for missing key_location field'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=None)
        signed = signtool.sign(unsigned)
        assert signed != None, "Envelope not signed correctly"
        
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        
        with self.assertRaises(errors.BadSignatureFormat, msg="Expected exception not raised.") as caught:
            sigInfo = verifytool._getSignatureInfo(signed)
        
        assert caught.exception.message == errors.MISSING_KEY_LOCATION, "Exception not formatted with correct message" 
        
        
    def testBadSignatureBlockMissingSignatureMethod(self):
        '''Check signature block for missing signature_method detection'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "Envelope not signed correctly."
        
        del signed["digital_signature"]["signing_method"]
        
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        
        with self.assertRaises(errors.UnsupportedSignatureAlgorithm, msg="Expected exception not raised.") as caught:
            sigInfo = verifytool._getSignatureInfo(signed)
        
        assert caught.exception.alg == None, "Raised exception not formatted correctly" 
        
        
    def testBadSignatureBlockBadSignatureMethod(self):
        '''Check signature block for detecting unsupported algorithm use'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None
        
        signed["digital_signature"]["signing_method"] = signtool.signatureMethod+"+BAD_SIGNATURE_METHOD"
        
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        
        with self.assertRaises(errors.UnsupportedSignatureAlgorithm, msg="Expected exception not raised.") as caught:
            sigInfo = verifytool._getSignatureInfo(signed)
        
        assert caught.exception.alg == signed["digital_signature"]["signing_method"], "Exception not raised correctly."
        
    def testBadSignatureBlockBadKeyOwner(self):
        '''Check signature block for a bad key_owner field'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "Envelope not signed correctly"
        
        signed["digital_signature"]["key_owner"] = ["John Q. Public <johnqpublic@learningregistry.org>"]
        
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        
        with self.assertRaises(errors.BadSignatureFormat, msg="Expected exception not raised.") as caught:
            sigInfo = verifytool._getSignatureInfo(signed)
        
        assert caught.exception.message == errors.BAD_KEY_OWNER, "Wrong exception"
        
        
    def testBadSignatureBlockMissingNullEmptySignature(self):
        '''Check signature block validation with missing/null or empty signature'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "Envelope signing did not succeed correctly."
                
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        
        signed["digital_signature"]["signature"] = ""
        with self.assertRaises(errors.BadSignatureFormat, msg="Expected exception not raised.") as caught:
            sigInfo = verifytool._getSignatureInfo(signed)
        assert caught.exception.message == errors.MISSING_SIGNATURE, "Wrong exception raised"
        
        signed["digital_signature"]["signature"] = None
        with self.assertRaises(errors.BadSignatureFormat, msg="Expected exception not raised.") as caught:
            sigInfo = verifytool._getSignatureInfo(signed)
        assert caught.exception.message == errors.MISSING_SIGNATURE, "Wrong exception raised"
        
        del signed["digital_signature"]["signature"] 
        with self.assertRaises(errors.BadSignatureFormat, msg="Expected exception not raised.") as caught:
            sigInfo = verifytool._getSignatureInfo(signed)
        assert caught.exception.message == errors.MISSING_SIGNATURE, "Wrong exception raised"
    
    
    def testValidSignature(self):
        '''Check for valid signature'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "Envelope did not sign correctly"
                
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        verified = verifytool.verify(signed)
        assert verified == True, "Envelope signature verification did not succeed, even though it should"
        
    def testMissingPublicKey(self):
        '''Check for appropriate response when public key for signature is missing'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "Envelope did not sign correctly"
        
        self.gpg.delete_keys([self.privateKey.fingerprint], secret=True)
        self.gpg.delete_keys([self.privateKey.fingerprint], secret=False)
                
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        
        with self.assertRaises(errors.MissingPublicKey, msg="Expected exception not raised.") as caught:
            verified = verifytool.verify(signed)
            assert verified == False, "Envelope verified, despite missing public key."
    
    def testCorruptEnvelope(self):
        '''Modify a signed envelope and check for validity'''
        unsigned = json.loads(self.sampleJSON)
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "envelope did not get signed correctly"
        
        signed["X_corrupted"] = "Corrupted Envelope"
        
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)

        verified = verifytool.verify(signed)
        
        assert verified == False, "corrupted envelope verified as good"
        
        
    def testWrongSignature(self):
        '''Test using a mis-matched signature, using a signature from a different valid envelope'''
        unsigned = json.loads(self.sampleJSON)
        altered = copy.deepcopy(unsigned)
        altered["X_corrupted"] = "Altered Envelope"
        
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signtool2 = Sign_0_21(privateKeyID=self.privateKey2.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        
        signed = signtool.sign(unsigned)
        alt_signed = signtool2.sign(altered)
        
        assert signed != None, "original did not get signed"
        assert alt_signed != None, "modified copy did not get signed"
        
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        
        verified = verifytool.verify(signed)
        assert verified == True, "signature did not verify, even though it should."
        verified = verifytool.verify(alt_signed)
        assert verified == True, "signature did not verify, even though it should."
        
        signed["digital_signature"] = alt_signed["digital_signature"]
        
        verified = verifytool.verify(signed)
        assert verified == False, "swapped signature block validated envelope as good."
        
    def testCorruptSignature(self):
        '''Test using a corrupted signature, replace the hash within a signature with a hash from a different envelope'''
        unsigned = json.loads(self.sampleJSON)
        
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        signed = signtool.sign(unsigned)
        assert signed != None, "baseline signing failed"
        
        # validate original with good signature
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)
        verified = verifytool.verify(signed)
        assert verified == True, "baseline validation failed"
        
        # manipulate the hash portion of a signature block
        altered = copy.deepcopy(unsigned)
        altered["X_corrupted"] = "Altered Envelope"
        altered_hash = signtool.get_message(altered)
        
        validHash = verifytool._extractHashFromSignature(signed["digital_signature"]["signature"])
        alt_signed = copy.deepcopy(signed)
        
        alt_signed["digital_signature"]["signature"] = signed["digital_signature"]["signature"].replace(validHash, altered_hash)
        assert alt_signed["digital_signature"]["signature"] != signed["digital_signature"]["signature"], "envelopes should not be equal after deliberate modificaton"
        
        verified = verifytool.verify(alt_signed)
        assert verified == False, "verification failed, corrupted signature block verified as good"
        
    def testSignLRTestData(self):
        '''Test using LR Test Data, if available'''
        if self.testDataDir == None:
            log.info("Skipping test, test data directory not set.")
            return
        
        import codecs
        
        signtool = Sign_0_21(privateKeyID=self.privateKey.fingerprint, passphrase=self.genericPassphrase, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=self.sampleKeyLocations)
        verifytool = Verify_0_21(gpgbin=self.gpgbin, gnupgHome=self.gnupgHome)

        allfiles = os.listdir(self.testDataDir)
        for root, dirs, files in os.walk(self.testDataDir):

            for fileName in files:
                log.info("Trying to sign %s" % (fileName, ))
                
                unsigned = json.load(codecs.open(os.path.join(root, fileName), "r", "utf-8-sig"))
                
                signed = signtool.sign(unsigned)
                
                assert signed.has_key("digital_signature"), "missing digital_signature"
                
                verified = verifytool.verify(signed)
                assert verified == True, "baseline validation failed"
        
        
        
            
        
    


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testGetSignatureBlock']
    unittest.main()