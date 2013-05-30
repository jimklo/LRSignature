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
from gnupg import GPG
from LRSignature.sign.Sign import Sign_0_21
from LRSignature.errors import *
import types, re, copy, os, sys
import cStringIO

class Verify_0_21(Sign_0_21):
    '''
    classdocs
    '''


    def __init__(self, gpgbin="/usr/local/bin/gpg", gnupgHome=os.path.expanduser(os.path.join("~", ".gnupg"))):
        '''
        Constructor
        '''
        self.gnupgHome = gnupgHome
        self.gpgbin = gpgbin
        Sign_0_21.__init__(self, privateKeyID=None, passphrase=None, gnupgHome=self.gnupgHome, gpgbin=self.gpgbin, publicKeyLocations=[])
        
    
    def _getSignatureInfo(self, envelope={}):
            sigInfo = None
            
            if envelope.has_key("digital_signature"):
                sigInfo = envelope["digital_signature"]
                if sigInfo.has_key("signing_method"): 
                    if sigInfo["signing_method"] == self.signatureMethod:
                        if not sigInfo.has_key("signature") or sigInfo["signature"] == None or len(sigInfo["signature"]) == 0:
                            raise BadSignatureFormat(MISSING_SIGNATURE)
                        elif not (sigInfo.has_key("key_location") and isinstance(sigInfo["key_location"], types.ListType) and len(sigInfo["key_location"]) > 0 ):
                            raise BadSignatureFormat(MISSING_KEY_LOCATION)
                        elif sigInfo.has_key("key_owner") and not isinstance(sigInfo["key_owner"], types.StringTypes):
                            raise BadSignatureFormat(BAD_KEY_OWNER)
                    else:
                        raise UnsupportedSignatureAlgorithm(sigInfo["signing_method"])
                else:
                    raise UnsupportedSignatureAlgorithm(None)
            
            
            return sigInfo
    
    def _extractHashFromSignature(self, signatureBlock=""):
        
        def removeHead(mesg=[]):
            status = 0
            mcopy = copy.deepcopy(mesg)
            for line in mesg:
                if re.match("^-----BEGIN PGP (SIGNED ){0,1}MESSAGE-----$", line) != None:
                    status = 1
                elif (status == 1 or status == 2) and re.match("^[^:]+: .+$", line) != None:
                    status = 2
                elif (status == 1 or status == 2) and line == "":
                    status = 3
                
                mcopy.pop(0)
                
                if status == 3:
                    break
                
            return mcopy

        def removeTail(mesg=[]):
            msgOnly = ""
            for line in mesg:
                if re.match("^-----BEGIN PGP SIGNATURE-----$", line):
                    break
                msgOnly += line
            return msgOnly
        
        if sys.version_info > (2, 7): 
            sig = re.split("\r\n|\r|\n", signatureBlock, flags=re.MULTILINE)
        else:
            sig = re.split("\r\n|\r|\n", signatureBlock)
            
        hash = removeTail(removeHead(sig))
        
        return hash
        
    def get_and_verify(self, envelope):
        '''
        Get the OpenPGP validation info and Verify integrity of the provided envelope.
        
        Returns: 
            None if no signature block exists
            gnupg.Verify object if signature & integrity check pass        
        Raises:
            BadSignatureFormat if signature & integrity check do not pass
            MissingPublicKey if public key for signed document is missing
        '''
        
        sigInfo = self._getSignatureInfo(envelope)
        
        if sigInfo != None:

            verified = self.gpg.verify(sigInfo["signature"])
            if verified.valid == True:
                verifiedHash = self._extractHashFromSignature(sigInfo["signature"])
                
                if self.get_message(envelope) == verifiedHash:
                    return verified
                else:
                    raise BadSignatureFormat("valid signature, envelope hash bad match.")
            elif verified.valid == False and verified.status == 'no public key':
                raise MissingPublicKey(message=verified.data, keyid=verified.key_id)
            else:
                raise BadSignatureFormat("invalid signature")
        return None

    def verify(self, envelope):
        '''
        Verify integrity of the provided envelope.
        
        Returns: 
            None if no signature block exists
            True if signature & integrity check pass
            False if signature & integrity check do not pass
        
        Raises:
            MissingPublicKey if public key for signed document is missing
        '''
        
        sigInfo = self._getSignatureInfo(envelope)
        
        if sigInfo != None:

            verified = self.gpg.verify(sigInfo["signature"])
            if verified.valid == True:
                verifiedHash = self._extractHashFromSignature(sigInfo["signature"])
                
                if self.get_message(envelope) == verifiedHash:
                    return True
                else:
                    return False
            elif verified.valid == False and verified.status == 'no public key':
                raise MissingPublicKey(message=verified.data, keyid=verified.key_id)
            else:
                return False
        return None

if __name__ == "__main__":
    verify = Verify_0_21()
    pass
        