# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import os
import json

from py_vapid import Vapid01, Vapid02


def main():
    parser = argparse.ArgumentParser(description="VAPID tool")
    parser.add_argument('--sign', '-s', help='claims file to sign')
    parser.add_argument('--gen', '-g', help='generate new key pairs',
                        default=False, action="store_true")
    parser.add_argument('--validate', '-v', help='dashboard token to validate')
    parser.add_argument('--version2', '-2', help="use VAPID spec Draft-02",
                        default=False, action="store_true")
    parser.add_argument('--version1', '-1', help="use VAPID spec Draft-01",
                        default=True, action="store_true")
    parser.add_argument('--json',  help="dump as json",
                        default=False, action="store_true")
    args = parser.parse_args()
    Vapid = Vapid01
    if args.version2:
        Vapid = Vapid02
    if args.gen or not os.path.exists('private_key.pem'):
        if not args.gen:
            print("No private_key.pem file found.")
            answer = None
            while answer not in ['y', 'n']:
                answer = input("Do you want me to create one for you? (Y/n)")
                if not answer:
                    answer = 'y'
                answer = answer.lower()[0]
                if answer == 'n':
                    print("Sorry, can't do much for you then.")
                    exit
        print("Generating private_key.pem")
        Vapid().save_key('private_key.pem')
    vapid = Vapid('private_key.pem')
    if args.gen or not os.path.exists('public_key.pem'):
        if not args.gen:
            print("No public_key.pem file found. You'll need this to access "
                  "the developer dashboard.")
            answer = None
            while answer not in ['y', 'n']:
                answer = input("Do you want me to create one for you? (Y/n)")
                if not answer:
                    answer = 'y'
                answer = answer.lower()[0]
                if answer == 'n':
                    print("Exiting...")
                    exit
        print("Generating public_key.pem")
        vapid.save_public_key('public_key.pem')
    claim_file = args.sign
    if claim_file:
        if not os.path.exists(claim_file):
            print("No {} file found.".format(claim_file))
            print("""
The claims file should be a JSON formatted file that holds the
information that describes you. There are three elements in the claims
file you'll need:

    "sub" This is your site's admin email address
          (e.g. "mailto:admin@example.com")
    "exp" This is the expiration time for the claim in seconds. If you don't
          have one, I'll add one that expires in 24 hours.

You're also welcome to add additional fields to the claims which could be
helpful for the Push Service operations team to pass along to your operations
team (e.g. "ami-id": "e-123456", "cust-id": "a3sfa10987"). Remember to keep
these values short to prevent some servers from rejecting the transaction due
to overly large headers. See https://jwt.io/introduction/ for details.

For example, a claims.json file could contain:

{"sub": "mailto:admin@example.com"}
""")
            exit
        try:
            claims = json.loads(open(claim_file).read())
            result = vapid.sign(claims)
        except Exception as exc:
            print("Crap, something went wrong: {}".format(repr(exc)))
            raise exc
        if args.json:
            print(json.dumps(result))
            return
        print("Include the following headers in your request:\n")
        for key, value in result.items():
            print("{}: {}\n".format(key, value))
        print("\n")

    token = args.validate
    if token:
        print("signed token for dashboard validation:\n")
        print(vapid.validate(token))
        print("\n")


if __name__ == '__main__':
    main()
