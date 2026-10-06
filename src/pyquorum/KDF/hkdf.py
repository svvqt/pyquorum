import hashlib
import hmac

HASH_LEN = 32
MAX_LENGTH = 255 * HASH_LEN


def hkdf(skm: bytes, length: int, salt=b"", CTXinfo=b"") -> bytes:
    """
    Extract and expand keying material with HMAC-SHA256 (RFC 5869).

    Parameters
    ----------
    skm: bytes
        input keying material
    length: int
        length of the output keying material in bytes, 1 <= length <= 255*32
    salt: bytes, optional
        non-secret salt; None or b"" means the RFC 5869 default of HashLen
        zero bytes
    CTXinfo: bytes, optional
        context and application specific information; None means b""

    Returns
    -------
    dkm: bytes
        output keying material of the requested length

    Raises
    ------
    TypeError
        If skm, salt or CTXinfo is not bytes-like, or length is not an int
    ValueError
        If length is not in 1..255*32

    Notes
    -----
    Matches the RFC 5869 SHA-256 test vectors, see tests/KDF/test_hkdf.py
    """

    if not isinstance(skm, (bytes, bytearray, memoryview)):
        raise TypeError(f"skm must be bytes, not {type(skm).__name__}")
    if salt is None:
        salt = b""
    if CTXinfo is None:
        CTXinfo = b""
    if not isinstance(salt, (bytes, bytearray, memoryview)):
        raise TypeError(f"salt must be bytes, not {type(salt).__name__}")
    if not isinstance(CTXinfo, (bytes, bytearray, memoryview)):
        raise TypeError(f"CTXinfo must be bytes, not {type(CTXinfo).__name__}")
    if not isinstance(length, int):
        raise TypeError(f"length must be an int, not {type(length).__name__}")
    if length <= 0 or length > MAX_LENGTH:
        raise ValueError(f"length must be between 1 and {MAX_LENGTH}, not {length}")

    skm = bytes(skm)
    salt = bytes(salt)
    CTXinfo = bytes(CTXinfo)

    # Extract: PRK = HMAC-Hash(salt, IKM); a missing salt is HashLen zero bytes
    if len(salt) == 0:
        salt = bytes(HASH_LEN)
    prk = hmac.new(salt, skm, hashlib.sha256).digest()

    # Expand: T(0) is the empty string, T(n) = HMAC(PRK, T(n-1) | info | n)
    blocks = (length + HASH_LEN - 1) // HASH_LEN
    dkm = bytearray()
    block = b""
    for counter in range(1, blocks + 1):
        block = hmac.new(prk, block + CTXinfo + bytes([counter]), hashlib.sha256).digest()
        dkm += block

    return bytes(dkm[:length])
