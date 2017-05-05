import base64


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
