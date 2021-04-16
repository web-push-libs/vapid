import binascii
import base64
import copy
import os
import json
import unittest
from cryptography.hazmat.primitives import serialization
from mock import patch, Mock

from py_vapid import Vapid01, Vapid02, VapidException, _check_sub
from py_vapid.jwt import decode

TEST_KEY_PRIVATE_DER = """
MHcCAQEEIPeN1iAipHbt8+/KZ2NIF8NeN24jqAmnMLFZEMocY8RboAoGCCqGSM49
AwEHoUQDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hbWAUpQFKDByKB81yldJ9GTklB
M5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ==
"""

key = dict(
    d=111971876876285331364078054667935803036831194031221090723024134705696601261147,  # noqa
    x=7512698603580564493364310058109115206932767156853859985379597995200661812060,  # noqa
    y=74837673548863147047276043384733294240255217876718360423043754089982135570501  # noqa
)

# This is the same private key, in PEM form.
TEST_KEY_PRIVATE_PEM = (
    "-----BEGIN PRIVATE KEY-----{}"
    "-----END PRIVATE KEY-----\n").format(TEST_KEY_PRIVATE_DER)

# This is the same private key, as a point in uncompressed form. This should
# be Base64url-encoded without padding.
TEST_KEY_PRIVATE_RAW = """
943WICKkdu3z78pnY0gXw143biOoCacwsVkQyhxjxFs
""".strip().encode('utf8')

# This is a public key in PEM form.
TEST_KEY_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJwJZq/GN8jJbo1GGpyU70hmP2hb
WAUpQFKDByKB81yldJ9GTklBM5xqEwuPM7VuQcyiLDhvovthPIXx+gsQRQ==
-----END PUBLIC KEY-----
"""

# this is a public key in uncompressed form ('\x04' + 2 * 32 octets)
# Remember, this should have any padding stripped.
TEST_KEY_PUBLIC_RAW = (
    "BBCcCWavxjfIyW6NRhqclO9IZj9oW1gFKUBSgwcigfNc"
    "pXSfRk5JQTOcahMLjzO1bkHMoiw4b6L7YTyF8foLEEU"
    ).strip('=').encode('utf8')


def setup_module(self):
    with open('/tmp/private', 'w') as ff:
        ff.write(TEST_KEY_PRIVATE_PEM)
    with open('/tmp/public', 'w') as ff:
        ff.write(TEST_KEY_PUBLIC_PEM)
    with open('/tmp/private.der', 'w') as ff:
        ff.write(TEST_KEY_PRIVATE_DER)


def teardown_module(self):
    os.unlink('/tmp/private')
    os.unlink('/tmp/public')


class VapidTestCase(unittest.TestCase):
    def check_keys(self, v):
        assert v.private_key.private_numbers().private_value == key.get('d')
        assert v.public_key.public_numbers().x == key.get('x')
        assert v.public_key.public_numbers().y == key.get('y')

    def test_init(self):
        v1 = Vapid01.from_file("/tmp/private")
        self.check_keys(v1)
        v2 = Vapid01.from_pem(TEST_KEY_PRIVATE_PEM.encode())
        self.check_keys(v2)
        v3 = Vapid01.from_der(TEST_KEY_PRIVATE_DER.encode())
        self.check_keys(v3)
        v4 = Vapid01.from_file("/tmp/private.der")
        self.check_keys(v4)
        no_exist = '/tmp/not_exist'
        Vapid01.from_file(no_exist)
        assert os.path.isfile(no_exist)
        os.unlink(no_exist)

    def repad(self, data):
        return data + "===="[len(data) % 4:]

    @patch("py_vapid.Vapid01.from_pem", side_effect=Exception)
    def test_init_bad_read(self, mm):
        self.assertRaises(Exception,
                          Vapid01.from_file,
                          private_key_file="/tmp/private")

    def test_gen_key(self):
        v = Vapid01()
        v.generate_keys()
        assert v.public_key
        assert v.private_key

    def test_private_key(self):
        v = Vapid01()
        self.assertRaises(VapidException,
                          lambda: v.private_key)

    def test_public_key(self):
        v = Vapid01()
        assert v._private_key is None
        assert v._public_key is None

    def test_save_key(self):
        v = Vapid01()
        v.generate_keys()
        v.save_key("/tmp/p2")
        os.unlink("/tmp/p2")

    def test_same_public_key(self):
        v = Vapid01()
        v.generate_keys()
        v.save_public_key("/tmp/p2")
        os.unlink("/tmp/p2")

    def test_from_raw(self):
        v = Vapid01.from_raw(TEST_KEY_PRIVATE_RAW)
        self.check_keys(v)

    def test_from_string(self):
        v1 = Vapid01.from_string(TEST_KEY_PRIVATE_DER)
        v2 = Vapid01.from_string(TEST_KEY_PRIVATE_RAW.decode())
        self.check_keys(v1)
        self.check_keys(v2)

    def test_sign_01(self):
        v = Vapid01.from_string(TEST_KEY_PRIVATE_DER)
        claims = {"aud": "https://example.com",
                  "sub": "mailto:admin@example.com"}
        result = v.sign(claims, "id=previous")
        assert result['Crypto-Key'] == (
            'id=previous;p256ecdsa=' + TEST_KEY_PUBLIC_RAW.decode('utf8'))
        pkey = binascii.b2a_base64(
            v.public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )
        ).decode('utf8').replace('+', '-').replace('/', '_').strip()
        items = decode(result['Authorization'].split(' ')[1], pkey)
        for k in claims:
            assert items[k] == claims[k]
        result = v.sign(claims)
        assert result['Crypto-Key'] == ('p256ecdsa=' +
            TEST_KEY_PUBLIC_RAW.decode('utf8'))
        # Verify using the same function as Integration
        # this should ensure that the r,s sign values are correctly formed
        assert Vapid01.verify(
            key=result['Crypto-Key'].split('=')[1],
            auth=result['Authorization']
        )

    def test_sign_02(self):
        v = Vapid02.from_file("/tmp/private")
        claims = {"aud": "https://example.com",
                  "sub": "mailto:admin@example.com",
                  "foo": "extra value"}
        claim_check = copy.deepcopy(claims)
        result = v.sign(claims, "id=previous")
        auth = result['Authorization']
        assert auth[:6] == 'vapid '
        assert ' t=' in auth
        assert ',k=' in auth
        parts = auth[6:].split(',')
        assert len(parts) == 2
        t_val = json.loads(base64.urlsafe_b64decode(
            self.repad(parts[0][2:].split('.')[1])
        ).decode('utf8'))
        k_val = binascii.a2b_base64(self.repad(parts[1][2:]))
        assert binascii.hexlify(k_val)[:2] == b'04'
        assert len(k_val) == 65
        assert claims == claim_check
        for k in claims:
            assert t_val[k] == claims[k]

    def test_sign_02_localhost(self):
        v = Vapid02.from_file("/tmp/private")
        claims = {"aud": "http://localhost:8000",
                  "sub": "mailto:admin@example.com",
                  "foo": "extra value"}
        result = v.sign(claims, "id=previous")
        auth = result['Authorization']
        assert auth[:6] == 'vapid '
        assert ' t=' in auth
        assert ',k=' in auth

    def test_integration(self):
        # These values were taken from a test page. DO NOT ALTER!
        key = ("BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foI"
               "iBHXRdJI2Qhumhf6_LFTeZaNndIo")
        auth = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJod"
                "HRwczovL3VwZGF0ZXMucHVzaC5zZXJ2aWNlcy5tb3ppbGxhLmNvbSIsImV"
                "4cCI6MTQ5NDY3MTQ3MCwic3ViIjoibWFpbHRvOnNpbXBsZS1wdXNoLWRlb"
                "W9AZ2F1bnRmYWNlLmNvLnVrIn0.LqPi86T-HJ71TXHAYFptZEHD7Wlfjcc"
                "4u5jYZ17WpqOlqDcW-5Wtx3x1OgYX19alhJ9oLumlS2VzEvNioZolQA")
        assert Vapid01.verify(key=key, auth="webpush {}".format(auth))
        assert Vapid02.verify(auth="vapid t={},k={}".format(auth, key))

    def test_bad_integration(self):
        # These values were taken from a test page. DO NOT ALTER!
        key = ("BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foI"
               "iBHXRdJI2Qhumhf6_LFTeZaNndIo")
        auth = ("WebPush eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJod"
                "HRwczovL3VwZGF0ZXMucHVzaC5zZXJ2aWNlcy5tb3ppbGxhLmNvbSIsImV"
                "4cCI6MTQ5NDY3MTQ3MCwic3ViIjoibWFpbHRvOnNpbXBsZS1wdXNoLWRlb"
                "W9AZ2F1bnRmYWNlLmNvLnVrIn0.LqPi86T-HJ71TXHAYFptZEHD7Wlfjcc"
                "4u5jYZ17WpqOlqDcW-5Wtx3x1OgYX19alhJ9oLumlS2VzEvNioZ_BAD")
        assert Vapid01.verify(key=key, auth=auth) == False

    def test_bad_sign(self):
        v = Vapid01.from_file("/tmp/private")
        self.assertRaises(VapidException,
                          v.sign,
                          {})
        self.assertRaises(VapidException,
                          v.sign,
                          {'sub': 'foo',
                           'aud': "p.example.com"})
        self.assertRaises(VapidException,
                          v.sign,
                          {'sub': 'mailto:foo@bar.com',
                           'aud': "p.example.com"})
        self.assertRaises(VapidException,
                          v.sign,
                          {'sub': 'mailto:foo@bar.com',
                           'aud': "https://p.example.com:8080/"})

    def test_ignore_sub(self):
        v = Vapid02.from_file("/tmp/private")
        v.conf['no-strict'] = True
        assert v.sign({"sub": "foo", "aud": "http://localhost:8000"})

    @patch('cryptography.hazmat.primitives.asymmetric'
           '.ec.EllipticCurvePublicNumbers')
    def test_invalid_sig(self, mm):
        from cryptography.exceptions import InvalidSignature
        ve = Mock()
        ve.verify.side_effect = InvalidSignature
        pk = Mock()
        pk.public_key.return_value = ve
        mm.from_encoded_point.return_value = pk
        self.assertRaises(InvalidSignature,
                          decode,
                          'foo.bar.blat',
                          'aaaa')
        self.assertRaises(InvalidSignature,
                          decode,
                          'foo.bar.a',
                          'aaaa')

    def test_sub(self):
        valid = [
            'mailto:me@localhost',
            'mailto:me@1.2.3.4',
            'mailto:me@1234::',
            'mailto:me@1234::5678',
            'mailto:admin@example.org',
            'mailto:admin-test-case@example-test-case.test.org',
            'https://localhost',
            'https://exmample-test-case.test.org',
            'https://8001::',
            'https://8001:1000:0001',
            'https://1.2.3.4'
        ]
        invalid = [
            'mailto:@foobar.com',
            'mailto:example.org',
            'mailto:0123:',
            'mailto:::1234',
            'https://somehost',
            'https://xyz:123',
        ]

        for val in valid:
            assert _check_sub(val) is True
        for val in invalid:
            assert _check_sub(val) is False
