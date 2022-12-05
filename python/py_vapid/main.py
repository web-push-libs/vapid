# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import os
import json

from cryptography.hazmat.primitives import serialization

from py_vapid import Vapid01, Vapid02, b64urlencode


def prompt(prompt):
    # Not sure why, but python3 throws and exception if you try to
    # monkeypatch for this. It's ugly, but this seems to play nicer.
    try:
        return input(prompt)
    except NameError:
        return raw_input(prompt)  # noqa: F821


def main():
    parser = argparse.ArgumentParser(description="VAPID tool")
    parser.add_argument('--sign', '-s', help='claims file to sign')
    parser.add_argument('--gen', '-g', help='generate new key pairs',
                        default=False, action="store_true")
    parser.add_argument('--version2', '-2', help="use RFC8292 VAPID spec",
                        default=True, action="store_true")
    parser.add_argument('--version1', '-1', help="use VAPID spec Draft-01",
                        default=False, action="store_true")
    parser.add_argument('--json',  help="dump as json",
                        default=False, action="store_true")
    parser.add_argument('--no-strict', help='Do not be strict about "sub"',
                        default=False, action="store_true")
    parser.add_argument('--applicationServerKey',
                        help="show applicationServerKey value",
                        default=False, action="store_true")
    parser.add_argument('--private-key', '-k', help='private key pem file',
                        default="private_key.pem")
    args = parser.parse_args()

    # Added to solve 2.7 => 3.* incompatibility
    Vapid = Vapid02
    if args.version1:
        Vapid = Vapid01
    if args.gen or not os.path.exists(args.private_key):
        if not args.gen:
            print("No private key file found.")
            answer = None
            while answer not in ['y', 'n']:
                answer = prompt("Do you want me to create one for you? (Y/n)")
                if not answer:
                    answer = 'y'
                answer = answer.lower()[0]
                if answer == 'n':
                    print("Sorry, can't do much for you then.")
                    exit(1)
        vapid = Vapid(conf=args)
        vapid.generate_keys()
        print("Generating private_key.pem")
        vapid.save_key('private_key.pem')
        print("Generating public_key.pem")
        vapid.save_public_key('public_key.pem')
    vapid = Vapid.from_file(args.private_key)
    claim_file = args.sign
    result = dict()
    if args.applicationServerKey:
        raw_pub = vapid.public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )
        print("Application Server Key = {}\n\n".format(
            b64urlencode(raw_pub)))
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
            exit(1)
        try:
            claims = json.loads(open(claim_file).read())
            result.update(vapid.sign(claims))
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


if __name__ == '__main__':
    main()
