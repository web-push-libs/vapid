import base64
import binascii


def b64urldecode(data):
    """Decodes an unpadded Base64url-encoded string.

    :param data: data bytes to decode
    :type data: bytes

    :returns bytes

    """
    return base64.urlsafe_b64decode(data + b"===="[len(data) % 4:])


def b64urlencode(data):
    """Encode a byte string into a Base64url-encoded string without padding

    :param data: data bytes to encode
    :type data: bytes

    :returns str

    """
    return base64.urlsafe_b64encode(data).replace(b'=', b'').decode('utf8')


def num_to_bytes(n, pad_to):
    """Returns the byte representation of an integer, in big-endian order.
    :param n: The integer to encode.
    :type n: int
    :param pad_to: Expected length of result, zeropad if necessary.
    :type pad_to: int
    :returns bytes
    """
    h = '%x' % n
    r = binascii.unhexlify('0' * (len(h) % 2) + h)
    return b'\x00' * (pad_to - len(r)) + r
