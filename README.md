Learning Registry Envelope Signing and Validation Module
=========================================================

This is a Python module that may be used to sign, verify, and retrieve
PGP keys for Learning Registry envelopes.


License & Copyright
===================

Copyright 2011 SRI International

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and


Installation
============

1. Install [GNU Privacy Guard](http://www.gnupg.org/)

2. Download the latest release from the [src/dist](./LRSignature/tree/master/src/dist)

3. Install with pip
        
        pip install LRSignature-<version>.tar.gz
        
4. There is no step four! Done.


Usage
=====

    #!/usr/bin/env python

    from LRSignature.sign.Sign  import Sign_0_21
    from LRSignature.verify.Verify  import Verify_0_21
    import simplejson as json
    
    envelope = '''
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
    origJson = json.loads(envelope)
    privateKeyLocation = ["http://www.example.com/example.asc"]
    keyid = "C37C805D164B052C"
    passphrase = "my passphrase"

    signtool = Sign_0_21(keyid, passphrase=passphrase, publicKeyLocations=privateKeyLocation)
    signed = signtool.sign(origJson)
    
    verifytool = Verify_0_21()
    verified = verifytool.verify(signed)
    assert verified == True
    
    
LRSignature.util module contains functionality to fetch and store public keys into the 
local PGP keyring.


Dependencies
============

External:

- GnuPG: http://www.gnupg.org/


Other Python Dependencies:

- Python-gnupg: http://pypi.python.org/pypi/python-gnupg/


Versions
========

0.1.8 - Modified to handle new variant of Basic Harvest getrecord and listrecords response. Additional error handling.

0.1.7 - Bug fix for Python versions < 2.7 and added some flexibility to command line use.

0.1.6 - New Feature.

        * Enhanced command line usage.
            
            - Added envelope signature validation
            
            - Command line arguments modified to have modes, sign & verify

0.1.5 - New Feature.
 
        * Ability to use LRSignature via command line to pipe envelopes from STDIN and output to STDOUT or publish to specified publish service URL:
        
            python -m LRSignature --help

0.1.4 - Minor enhancement.
 
        * Updated __init__.py files to import the right submodules
          so package visibility is not obfuscated. No functionality changes.
        

0.1.3 - Bug Fix [PT #14231273](https://www.pivotaltracker.com/story/show/14231273)

        * Bittorrent-python does not encode unicode strings.  Repackaged LRSignature
          with modified Bittorrent-python package which can handle UTF-8 strings.
        
        * License for Bittorrent-python code is [Bittorrent Open Source License](http://www2.bittorrent.com/legal/bittorrent-open-source-license)
        
        * Removed external dependency for Bittorrent-python module.
        
        * Reverted changes from 0.1.2.

0.1.2 - Bug Fix [PT #14231273](https://www.pivotaltracker.com/story/show/14231273)

        * UTF-8 encoded envelopes failed to sign.
         
            - Unicode strings are now UTF-8 encoded before bencoding.
        
            
0.1.1 - Minor Bug Fix

        * When gnupgHome is not defined, default option creates a directory named "~".
        
        
0.1.0 - Initial Release
