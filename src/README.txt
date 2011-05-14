================================================
LRSignature - Learning Registry Signature module
================================================

The Learning Registry module allows you to sign and minimally validate 
Learning Registry envelopes::

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
- BitTorrent-bencode: http://pypi.python.org/pypi/BitTorrent-bencode/5.0.8.1



