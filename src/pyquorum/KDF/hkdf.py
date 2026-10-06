import hashlib
import hmac

from ..exceptions import InvalidLengthError

HASH_LEN = 32
MAX_LENGTH = 255 * HASH_LEN


def hkdf(ikm: bytes, length: int, salt=b"", info=b"") -> bytes:
    """
    Extract and expand keying material with HMAC-SHA256 (RFC 5869).

    Parameters
    ----------
    ikm: bytes
        input keying material
    length: int
        length of the output keying material in bytes, 1 <= length <= 255*32
    salt: bytes, optional
        non-secret salt; None or b"" means the RFC 5869 default of HashLen
        zero bytes
    info: bytes, optional
        context and application specific information; None means b""

    Returns
    -------
    okm: bytes
        output keying material of the requested length

    Raises
    ------
    TypeError
        If ikm, salt or info is not bytes-like, or length is not an int
    InvalidLengthError
        If length is not in 1..255*32; it is both a PyQuorumError and a
        ValueError

    Notes
    -----
    Matches the RFC 5869 SHA-256 test vectors, see tests/KDF/test_hkdf.py
    """

    if not isinstance(ikm, (bytes, bytearray, memoryview)):
        raise TypeError(f"ikm must be bytes, not {type(ikm).__name__}")
    if salt is None:
        salt = b""
    if info is None:
        info = b""
    if not isinstance(salt, (bytes, bytearray, memoryview)):
        raise TypeError(f"salt must be bytes, not {type(salt).__name__}")
    if not isinstance(info, (bytes, bytearray, memoryview)):
        raise TypeError(f"info must be bytes, not {type(info).__name__}")
    if not isinstance(length, int):
        raise TypeError(f"length must be an int, not {type(length).__name__}")
    if length <= 0 or length > MAX_LENGTH:
        raise InvalidLengthError(f"length must be between 1 and {MAX_LENGTH}, not {length}")

    ikm = bytes(ikm)
    salt = bytes(salt)
    info = bytes(info)

    # Extract: PRK = HMAC-Hash(salt, IKM); a missing salt is HashLen zero bytes
    if len(salt) == 0:
        salt = bytes(HASH_LEN)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand: T(0) is the empty string, T(n) = HMAC(PRK, T(n-1) | info | n)
    blocks = (length + HASH_LEN - 1) // HASH_LEN
    okm = bytearray()
    block = b""
    for counter in range(1, blocks + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block

    return bytes(okm[:length])
