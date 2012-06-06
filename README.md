Learning Registry Envelope Signing and Validation Module
=========================================================

This is a Python module that may be used to sign, verify, and retrieve
PGP keys for Learning Registry envelopes.

For information on use, see the [LRSignature Wiki](https://github.com/jimklo/LRSignature/wiki).

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
limitations under the License.


Dependencies
============

External:

- GnuPG: http://www.gnupg.org/


Other Python Dependencies:

- Python-gnupg: http://pypi.python.org/pypi/python-gnupg/


Versions
========
0.1.10 - Fixed an issue with PipeTool not honoring the --lr-test-data argument.

0.1.9 - Added contribution from ISKME that adds basic HTTP Authentication for publish.

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
