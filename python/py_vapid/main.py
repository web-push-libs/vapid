# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import os
import json

from py_vapid import Vapid


def main():
    parser = argparse.ArgumentParser(description="VAPID tool")
    parser.add_argument('--sign', '-s', help='claims file to sign')
    parser.add_argument('--validate', '-v', help='dashboard token to validate')
    args = parser.parse_args()
    if not os.path.exists('private_key.pem'):
        print "No private_key.pem file found."
        answer = None
        while answer not in ['y', 'n']:
            answer = raw_input("Do you want me to create one for you? (Y/n)")
            if not answer:
                answer = 'y'
            answer = answer.lower()[0]
            if answer == 'n':
                print "Sorry, can't do much for you then."
                exit
            if answer == 'y':
                break
        Vapid().save_key('private_key.pem')
    vapid = Vapid('private_key.pem')
    if not os.path.exists('public_key.pem'):
        print "No public_key.pem file found. You'll need this to access "
        print "the developer dashboard."
        answer = None
        while answer not in ['y', 'n']:
            answer = raw_input("Do you want me to create one for you? (Y/n)")
            if not answer:
                answer = 'y'
            answer = answer.lower()[0]
            if answer == 'y':
                vapid.save_public_key('public_key.pem')
    claim_file = args.sign
    if claim_file:
        if not os.path.exists(claim_file):
            print "No %s file found." % claim_file
            print """
The claims file should be a JSON formatted file that holds the
information that describes you. There are three elements in the claims
file you'll need:

    "aud" This is your site's URL (e.g. "https://example.com")
    "sub" This is your site's admin email address
          (e.g. "mailto:admin@example.com")
    "exp" This is the expiration time for the claim in seconds. If you don't
          have one, I'll add one that expires in 24 hours.

For example, a claims.json file could contain:

{"aud": "https://example.com", "sub": "mailto:admin@example.com"}
"""
            exit
        try:
            claims = json.loads(open(claim_file).read())
            result = vapid.sign(claims)
        except Exception, exc:
            print "Crap, something went wrong: %s", repr(exc)

        print "Include the following headers in your request:\n"
        for key, value in result.items():
            print "%s: %s" % (key, value)
        print "\n"

    token = args.validate
    if token:
        print "signed token for dashboard validation:\n"
        print vapid.validate(token)
        print "\n"


if __name__ == '__main__':
    main()
