"""
This is a weird little file that converts a public PEM key into a X962 style key.

I can hear you cocking your head sideways at those terms, so let me clarify.
is a format that has the "-----BEGIN EC PUBLIC KEY----" spoo and a format that
only a DER hex parser would ever love. X962 is the format you're probably familiar
with if you ever edited a .ssh/authorized_keys file. Turns out, that in transit,
most VAPID keys are sent in X962 format, while the origin key files are in PEM
format.

Thus this weird little file.

to use:

`python3 convert.py YOUR_PUBLIC_KEY.pem`
It returns a stripped x962 string suitable for framing or handing out to children
on their birthday or other holidays. (Those are tears of joy, and tantrums of glee.)

"""
import base64
import sys

from typing import cast
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from cryptography.hazmat.primitives import serialization

try:
    content = open(sys.argv[1], "rb").read()
    pubkey = serialization.load_pem_public_key(content)
except IndexError:
    print ("Please specify a public key PEM file to convert.")
    exit()

pk_string = cast(ec.EllipticCurvePublicKey, pubkey).public_bytes(
    serialization.Encoding.X962,
    serialization.PublicFormat.UncompressedPoint
)

pk_string = base64.b64encode(pk_string).strip(b'=')

print(f"{pk_string.decode()}")