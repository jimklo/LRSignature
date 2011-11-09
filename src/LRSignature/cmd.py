'''
Created on Jun 14, 2011

@author: jklo
'''
import types
import sys

class InvalidJSONError(ValueError):
    def __init__(self, msg):
        ValueError.__init__(self)
        self.message = msg


class PipeTool(object):

    def __init__(self):

        self.args = self.parseArgs()



    def run(self):
        from sign.Sign import Sign_0_21
        from LRSignature.verify.Verify import Verify_0_21

        import json

        rawInput = self.readInput()
        envelopeList = self.parseInput(rawInput)

        if self.args.mode == "sign":
            self.signtool = Sign_0_21(privateKeyID=self.args.key,
                              passphrase=self.args.passphrase,
                              gnupgHome=self.args.gnupghome,
                              gpgbin=self.args.gpgbin, publicKeyLocations=self.args.key_location)

            is_test_data_opt = self.args.lr_test_data.lower() in ["true", "yes", "t", "y"]

            signedList = self.signEnvelopes(envelopeList, is_test_data=is_test_data_opt)

            if self.args.publish_url != None:
                self.publishEnvelopes(signedList)
            else:
                print json.dumps({ "documents": signedList })

        elif self.args.mode == "verify":
            self.verifytool = Verify_0_21(gpgbin=self.args.gpgbin, gnupgHome=self.args.gnupghome)
            resultList = self.validateEnvelopes(envelopeList)
            print json.dumps({"results": resultList})




    def _set_test_key(self, envelope, remove=True):
        rmcount = 0

        if envelope.has_key("keys"):
            for item in envelope["keys"]:
                if item == "lr-test-data":
                    rmcount += 1
        if remove:
            while rmcount > 0:
                try:
                    envelope["keys"].remove("lr-test-data")
                except:
                    pass
                rmcount += -1
        elif not remove and rmcount == 0:
            envelope["keys"].append("lr-test-data")

        return envelope

    def _chunkList(self, fullList = [], chunkSize=10):
        numElements = len(fullList)
        for start in range(0, numElements, chunkSize):
            end = start+chunkSize
            if end > numElements:
                end = numElements
            yield fullList[start:end]


    def _validate_digital_signature(self, doc):
        from LRSignature import util
        from LRSignature import errors


        result = {}
        result = {"verified": False}
        if doc.has_key("doc_ID"):
            result["doc_ID"] = doc["doc_ID"]
        if doc.has_key("resource_locator"):
            result["resource_locator"] = doc["resource_locator"]

        try:
            result["verified"] = self.verifytool.verify(doc)

        except errors.MissingPublicKey:

            locations = doc['digital_signature']['key_location']
            numImported = 0
            for location in locations:
                rawKeys = util.fetchkeys(location)
                for rawKey in rawKeys:
                    numImported += util.storekey(self.sampleKey, gpgbin=self.args.gpgbin, gnupgHome=self.args.gnupghome)
                if numImported > 0:
                    break

            try:
                result["verified"] = self.verifytool.verify(doc)


            except errors.MissingPublicKey:
                result["verified"] = False
                result["error"] = "No available public key to validate."

        except errors.BadSignatureFormat as e:
            result["verified"] = False
            result["error"] = e.message

        except errors.UnknownKeyException as e:
            result["verified"] = False
            result["error"] = e.message

        except errors.UnsupportedSignatureAlgorithm as e:
            result["verified"] = False
            result["error"] = e.message

        except Exception as e:
            result["verified"] = False
            result["error"] = e.message

        return result

    def validateEnvelopes(self, envelopes):
        result = []
        for envelope in envelopes:
            result.append(self._validate_digital_signature(envelope))
        return result


    def publishEnvelopes(self, envelopes):
        import urllib2,json
        req = urllib2.Request(self.args.publish_url, headers={"Content-type": "application/json; charset=utf-8"})
        if self.args.publish_username and self.args.publish_password:
            import base64
            base64string = base64.encodestring('%s:%s' % (self.args.publish_username, self.args.publish_password))[:-1]
            req.add_header("Authorization", "Basic %s" % base64string)
        status = []
        for chunk in self._chunkList(envelopes, self.args.publish_chunksize):
            res = urllib2.urlopen(req, data=json.dumps({ "documents":chunk }), timeout=self.args.publish_timeout)
            status.append(json.load(res))

        print json.dumps(status)

    def signEnvelopes(self, envelopes, is_test_data=True):
        signedEnvelopes = []
        for envelope in envelopes:
            self._set_test_key(envelope, remove=not is_test_data)
            signed = self.signtool.sign(envelope)
            signedEnvelopes.append(signed)
        return signedEnvelopes

    def parseArgs(self):
        import argparse, json
        parser = argparse.ArgumentParser(description='Sign files for Learning Registry')
        subparsers = parser.add_subparsers(help="sub-command help")

        sign_parser = subparsers.add_parser('sign')
        sign_parser.add_argument('--key', help='PGP Private Key ID', required=True)
        sign_parser.add_argument('--key-location', help='Location the PGP Public Key can be downloaded from', required=True, action="append")
        sign_parser.add_argument('--passphrase', help='Passphrase for PGP Private Key', default=None)
        sign_parser.add_argument('--lr-test-data', help='Publish as lr test data, default is True', default="True")
        sign_parser.add_argument('--publish-url', help='URL of publish service on node to send envelopes, default STDOUT', default=None)
        sign_parser.add_argument('--publish-chunksize', help='publish chunksize, default 25', type=int, default=25)
        sign_parser.add_argument('--publish-timeout', help='publish timeout in seconds, default 300', type=int, default=300)
        sign_parser.add_argument('--publish-username', help='publish userame for basic HTTP auth', default=None)
        sign_parser.add_argument('--publish-password', help='publish password for basic HTTP auth', default=None)
        sign_parser.add_argument('--gpgbin', help='Path to GPG binary')
        sign_parser.add_argument('--gnupghome', help='Path to GPG home directory')
        sign_parser.set_defaults(mode="sign")

        verify_parser = subparsers.add_parser('verify')
        verify_parser.set_defaults(mode="verify")
        verify_parser.add_argument('--gpgbin', help='Path to GPG binary')
        verify_parser.add_argument('--gnupghome', help='Path to GPG home directory')

        parser.add_argument('--gpgbin', help='Path to GPG binary', default="gpg")
        parser.add_argument('--gnupghome', help='Path to GPG home directory', default="~/.gnupg")
    #        parser.add_argument('--config', help='JSON Configuration file', default=None, type=argparse.FileType('r'))
        args = parser.parse_args()#

        return args


    def parseInput(self, input=None):
        import json

        def getHarvestRecords(obj):
            def harvestGetRecordGenerator(results):
                for item in results:
                    if "resource_data" in item:
                        yield item["resource_data"]

            def harvestListRecordsGenerator(results):
                for item in results:
                    if "record" in item and "resource_data" in item["record"]:
                        yield item["record"]["resource_data"]

            try:
                root = obj["getrecord"]["record"]
                return harvestGetRecordGenerator(root)
            except:
                pass

            try:
                root = obj["listrecords"]
                return harvestListRecordsGenerator(root)
            except:
                pass

            return None


        if input is not None:
            try:
                jsobject = json.loads(input)

                records = getHarvestRecords(jsobject)
                if records != None:
                    return records
                if isinstance(jsobject, types.DictionaryType):
                    if jsobject.has_key("documents") and isinstance(jsobject["documents"], types.ListType):
                        return jsobject["documents"]
                    return [jsobject]
                elif isinstance(jsobject, types.ListType):
                    return jsobject

            except Exception, e:
                raise InvalidJSONError(e.message)
        return None



    def readInput(self):
        import json
        pipedInput = ''
        try:
            while True:
                pipedInput += raw_input()

        except EOFError:
            pass

        return pipedInput


if __name__ == "__main__":
    tool = PipeTool()
    tool.run()
