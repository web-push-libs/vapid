# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import os
import json
import unittest
from nose.tools import eq_, ok_

from jose import jws
from vapid import Vapid, VapidException

T_PRIVATE = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPeN1iAipHbt8+/KZ2NIF8NeN24jqAmnMLFZEMocY8RboAoGCCqGSM49
AwEHoUQDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hbWAUpQFKDByKB81yldJ9GTklB
M5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ==
-----END EC PRIVATE KEY-----
"""

T_PUBLIC = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hb
WAUpQFKDByKB81yldJ9GTklBM5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ==
-----END PUBLIC KEY-----
"""


def setUp(self):
    open('/tmp/private', 'w').write(T_PRIVATE)
    open('/tmp/public', 'w').write(T_PUBLIC)


def tearDown(self):
    os.unlink('/tmp/private')
    os.unlink('/tmp/public')


class VapidTestCase(unittest.TestCase):
    def test_init(self):
        v = Vapid("/tmp/private")
        eq_(v.private_key.to_pem(), T_PRIVATE)
        eq_(v.public_key.to_pem(), T_PUBLIC)

    def test_private(self):
        v = Vapid()

        def getKey(v):
            v.private_key

        self.assertRaises(VapidException, getKey, v)

    def test_public(self):
        v = Vapid()

        def getKey(v):
            v.public_key

        self.assertRaises(VapidException, getKey, v)

    def test_gen_key(self):
        v = Vapid()
        v.generate_keys()
        ok_(v.public_key)
        ok_(v.private_key)

    def test_validate(self):
        v = Vapid("/tmp/private")
        msg = "foobar"
        vtoken = v.validate(msg)
        ok_(v.public_key.verify(base64.urlsafe_b64decode(vtoken), msg))

    def test_sign(self):
        v = Vapid("/tmp/private")
        claims = {"aud":"example.com", "sub":"admin@example.com"}
        result = v.sign(claims)
        eq_(result['Crypto-Key'],
            'p256ecdsa=EJwJZq_GN8jJbo1GGpyU70hmP2hbWAUpQFKDBy'
             'KB81yldJ9GTklBM5xqEwuPM7VuQcyiLDhvovthPIXx-gsQRQ==')
        items = jws.verify(result['Authorization'][7:],
                           v.public_key,
                           algorithms=["ES256"])
        eq_(json.loads(items), claims)

