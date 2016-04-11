# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import time
import hashlib

import ecdsa
import logging
from jose import jws

__version__ = "0.2"


class VapidException(Exception):
    pass


class Vapid(object):
    """Minimal VAPID signature generation library. """
    _private_key = None
    _public_key = None
    _hasher = hashlib.sha256

    def __init__(self, private_key_file=None, private_key=None):
        """Initialize VAPID using an optional file containing a private key
        in PEM format.

        :param private_key_file: The name of the file containing the
        private key
        """
        if private_key_file:
            private_key = open(private_key_file).read()
        if private_key:
            try:
                if "BEGIN EC" in private_key:
                    self._private_key = ecdsa.SigningKey.from_pem(private_key)
                else:
                    self._private_key = \
                        ecdsa.SigningKey.from_der(
                            base64.urlsafe_b64decode(private_key))
            except Exception, exc:
                logging.error("Could not open private key file: %s", repr(exc))
                raise VapidException(exc)
            self._pubilcKey = self._private_key.get_verifying_key()

    @property
    def private_key(self):
        if not self._private_key:
            raise VapidException(
                "No private key defined. Please import or generate a key.")
        return self._private_key

    @private_key.setter
    def private_key(self, value):
        self._private_key = value

    @property
    def public_key(self):
        if not self._public_key:
            self._public_key = self.private_key.get_verifying_key()
        return self._public_key

    def generate_keys(self):
        """Generate a valid ECDSA Key Pair."""
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        self.public_key

    def save_key(self, key_file):
        """Save the private key to a PEM file."""
        file = open(key_file, "w")
        if not self._private_key:
            self.generate_keys()
        file.write(self._private_key.to_pem())
        file.close()

    def save_public_key(self, key_file):
        """Save the public key to a PEM file.

        :param key_file: The name of the file to save the public key
        """
        with open(key_file, "w") as file:
            file.write(self.public_key.to_pem())
            file.close()

    def validate(self, token):
        """Sign a Valdiation token from the dashboard"""
        sig = self.private_key.sign(token, hashfunc=self._hasher)
        token = base64.urlsafe_b64encode(sig)
        return token

    def verifyToken(self, sig, token):
        hsig = base64.urlsafe_b64decode(sig)
        return self.public_key.verify(hsig, token,
                                      hashfunc=self._hasher)

    def sign(self, claims, crypto_key=None):
        """Sign a set of claims.

        :param claims: JSON object containing the JWT claims to use.
        :param crypto_key: Optional existing crypto_key header content. The
            vapid public key will be appended to this data.
        :returns result: a hash containing the header fields to use in
            the subscription update.
        """
        if not claims.get('exp'):
            claims['exp'] = int(time.time()) + 86400
        if not claims.get('aud'):
            raise VapidException(
                "Missing 'aud' from claims. "
                "'aud' is your site's URL.")
        if not claims.get('sub'):
            raise VapidException(
                "Missing 'sub' from claims. "
                "'sub' is your admin email as a mailto: link.")
        sig = jws.sign(claims, self.private_key, algorithm="ES256")
        pkey = 'p256ecdsa='
        pkey += base64.urlsafe_b64encode(self.public_key.to_string())
        if crypto_key:
            crypto_key = crypto_key + ',' + pkey
        else:
            crypto_key = pkey

        return {"Authorization": "Bearer " + sig.strip('='),
                "Crypto-Key": crypto_key}
