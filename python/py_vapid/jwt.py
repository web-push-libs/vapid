import binascii
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

from py_vapid.utils import b64urldecode, b64urlencode, num_to_bytes


def extract_signature(auth):
    """
    Extracts the payload and signature from a JWT, converting the
    signature from the JOSE format (RFC 7518, section 3.4) to the
    RFC 3279 format that Cryptography requires.

    :param auth: A JWT Authorization Token.
    :type auth: str

    :return tuple containing the signature material and signature

    """
    payload, asig = auth.encode('utf8').rsplit(b'.', 1)
    sig = b64urldecode(asig)
    if len(sig) != 64:
        raise InvalidSignature()

    encoded = utils.encode_dss_signature(
        s=int(binascii.hexlify(sig[32:]), 16),
        r=int(binascii.hexlify(sig[:32]), 16)
    )
    return payload, encoded


def decode(token, key):
    """Decode a web token into an assertion dictionary

    :param token: VAPID auth token
    :type token: str
    :param key: bitarray containing the public key
    :type key: str

    :return dict of the VAPID claims

    :raise InvalidSignature

    """
    try:
        sig_material, signature = extract_signature(token)
        dkey = b64urldecode(key.encode('utf8'))
        pkey = ec.EllipticCurvePublicNumbers.from_encoded_point(
            ec.SECP256R1(),
            dkey,
        ).public_key(default_backend())
        pkey.verify(
            signature,
            sig_material,
            ec.ECDSA(hashes.SHA256())
        )
        return json.loads(
            b64urldecode(sig_material.split(b'.')[1]).decode('utf8')
        )
    except InvalidSignature:
        raise
    except(ValueError, TypeError, binascii.Error):
        raise InvalidSignature()


def sign(claims, key):
    """Sign the claims

    :param claims: list of JWS claims
    :type claims: dict
    :param key: Private key for signing
    :type key: ec.EllipticCurvePrivateKey
    :param algorithm: JWT "alg" descriptor
    :type algorithm: str

    """
    header = b64urlencode(b"""{"typ":"JWT","alg":"ES256"}""")
    claims = b64urlencode(json.dumps(claims,
                                     separators=(',', ':')).encode('utf8'))
    token = "{}.{}".format(header, claims)
    rsig = key.sign(token.encode('utf8'), ec.ECDSA(hashes.SHA256()))
    (r, s) = utils.decode_dss_signature(rsig)
    sig = b64urlencode(num_to_bytes(r) + num_to_bytes(s))
    return "{}.{}".format(token, sig)
