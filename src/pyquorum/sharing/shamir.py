import crypto_core
from base import Scheme
from ..exceptions import InvalidKeyError, InvalidShareError

class ShamirScheme(Scheme):
    def split(self, key: bytes) -> list[str]:
        if not isinstance(key, bytes):
            raise InvalidKeyError(f"Key must be bytes, not {type(key)}")
        
        if len(key) != 32:
            raise InvalidKeyError(f"Key length must be 32, not {len(key)}")

        try:
            return crypto_core.split_secret(key)
        except ValueError as e:
            raise InvalidKeyError(str(e))

    def combine(self, shares: list[str]) -> bytes:
        for share in shares:
            if not isinstance(share, str):
                raise InvalidShareError(f"Share must be String, not {type(share)}")

        try:
            return crypto_core.combine_shares(shares)
        except ValueError as e:
            raise InvalidShareError(str(e))

if __name__ == "__main__":
    key = b"12312421412234567123456789123456"
    shares = shamir_split(key)
    print(shares)
    print(shamir_combine(shares))