import hmac
import hashlib
from math import ceil

hash_len = 32


def hkdf(skm: bytes, length: int, salt=b"", CTXinfo=b"") -> bytes:
    """

    extract and expand key with hmac function

    Parameters:
        skm: bytes
        length: int
        salt: bytes
        CTXinfo: bytes

    Returns:
        dkm: bytes

    """

    if len(salt) == 0:
        salt = bytes([0]*hash_len)

    prk = hmac.new(salt, skm, hashlib.sha256).digest()

    k_i = b"0"
    dkm = b""
    t = ceil(length/hash_len)

    for i in range(t):
        k_i = hmac.new(prk, k_i + CTXinfo + bytes([1+i]), hashlib.sha256).digest()
        dkm += k_i

    return dkm[:length]
