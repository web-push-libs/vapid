import binascii
import base64
import hashlib
import os
import json
import unittest
from nose.tools import eq_, ok_
from mock import patch

from jose import jws
from py_vapid import Vapid01, Vapid02, VapidException

T_DER = """
MHcCAQEEIPeN1iAipHbt8+/KZ2NIF8NeN24jqAmnMLFZEMocY8RboAoGCCqGSM49
AwEHoUQDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hbWAUpQFKDByKB81yldJ9GTklB
M5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ==
"""
T_PRIVATE = ("-----BEGIN EC PRIVATE KEY-----{}"
             "-----END EC PRIVATE KEY-----\n").format(T_DER)

T_PUBLIC = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hb
WAUpQFKDByKB81yldJ9GTklBM5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ==
-----END PUBLIC KEY-----
"""

# this is a DER RAW key ('\x04' + 2 32 octet digits)
# Remember, this should have any padding stripped.
T_PUBLIC_RAW = (
    "BBCcCWavxjfIyW6NRhqclO9IZj9oW1gFKUBSgwcigfNc"
    "pXSfRk5JQTOcahMLjzO1bkHMoiw4b6L7YTyF8foLEEU"
    ).strip('=')


def setUp(self):
    ff = open('/tmp/private', 'w')
    ff.write(T_PRIVATE)
    ff.close()
    ff = open('/tmp/public', 'w')
    ff.write(T_PUBLIC)
    ff.close()


def tearDown(self):
    os.unlink('/tmp/private')
    os.unlink('/tmp/public')


class VapidTestCase(unittest.TestCase):
    def test_init(self):
        v1 = Vapid01(private_key_file="/tmp/private")
        eq_(v1.private_key.to_pem(), T_PRIVATE.encode('utf8'))
        eq_(v1.public_key.to_pem(), T_PUBLIC.encode('utf8'))
        v2 = Vapid01(private_key=T_PRIVATE)
        eq_(v2.private_key.to_pem(), T_PRIVATE.encode('utf8'))
        eq_(v2.public_key.to_pem(), T_PUBLIC.encode('utf8'))
        v3 = Vapid01(private_key=T_DER)
        eq_(v3.private_key.to_pem(), T_PRIVATE.encode('utf8'))
        eq_(v3.public_key.to_pem(), T_PUBLIC.encode('utf8'))
        no_exist = '/tmp/not_exist'
        Vapid01(private_key_file=no_exist)
        ok_(os.path.isfile(no_exist))
        os.unlink(no_exist)

    def repad(self, data):
        return data + "===="[:len(data) % 4]

    @patch("ecdsa.SigningKey.from_pem", side_effect=Exception)
    def test_init_bad_priv(self, mm):
        self.assertRaises(Exception,
                          Vapid01,
                          private_key_file="/tmp/private")

    def test_private(self):
        v = Vapid01()
        self.assertRaises(VapidException, lambda x=None: v.private_key)

    def test_public(self):
        v = Vapid01()

        self.assertRaises(VapidException, lambda x=None: v.public_key)

    def test_gen_key(self):
        v = Vapid01()
        v.generate_keys()
        ok_(v.public_key)
        ok_(v.private_key)

    def test_save_key(self):
        v = Vapid01()
        v.save_key("/tmp/p2")
        os.unlink("/tmp/p2")

    def test_same_public_key(self):
        v = Vapid01()
        v.generate_keys()
        v.save_public_key("/tmp/p2")
        os.unlink("/tmp/p2")

    def test_validate(self):
        v = Vapid01("/tmp/private")
        msg = "foobar".encode('utf8')
        vtoken = v.validate(msg)
        ok_(v.public_key.verify(base64.urlsafe_b64decode(vtoken),
                                msg,
                                hashfunc=hashlib.sha256))
        # test verify
        ok_(v.verify_token(msg, vtoken))

    def test_sign_01(self):
        v = Vapid01("/tmp/private")
        claims = {"aud": "example.com", "sub": "admin@example.com"}
        result = v.sign(claims, "id=previous")
        eq_(result['Crypto-Key'],
            'id=previous;p256ecdsa=' + T_PUBLIC_RAW)
        items = jws.verify(result['Authorization'].split(' ')[1],
                           v.public_key,
                           algorithms=["ES256"])
        eq_(json.loads(items.decode('utf8')), claims)
        result = v.sign(claims)
        eq_(result['Crypto-Key'],
            'p256ecdsa=' + T_PUBLIC_RAW)

    def test_sign_02(self):
        v = Vapid02("/tmp/private")
        claims = {"aud": "example.com",
                  "sub": "admin@example.com",
                  "foo": "extra value"}
        result = v.sign(claims, "id=previous")
        auth = result['Authorization']
        eq_(auth[:6], 'vapid ')
        ok_(' t=' in auth)
        ok_(',k=' in auth)
        parts = auth[6:].split(',')
        eq_(len(parts), 2)
        t_val = json.loads(base64.urlsafe_b64decode(
            self.repad(parts[0][2:].split('.')[1])
        ).decode('utf8'))
        k_val = binascii.a2b_base64(self.repad(parts[1][2:]))
        eq_(binascii.hexlify(k_val)[:2], b'04')
        eq_(len(k_val), 65)
        for k in claims:
            eq_(t_val[k], claims[k])

    def test_bad_sign(self):
        v = Vapid01("/tmp/private")
        self.assertRaises(VapidException,
                          v.sign,
                          {'aud': "p.example.com"})
