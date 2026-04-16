import crypto_core
from .base import Scheme
from ..exceptions import InvalidKeyError, InvalidShareError

class ShamirScheme(Scheme):
    """
    Class for shamir secret sharing
    

    Parameters
    ----------
    k: int
        minimum number of shares required to reconstruct the secret
    n: int
        total number of shares to generate
    """
    def split(self, key: bytes) -> list[str]:
        """
        method for splitting secret key to number of shares

        Parameters
        ----------
        key: bytes
            secret key
        
        Returns
        -------
        shares: list[str]:
            secret key that splitted on shares 

        Raises
        ------
        InvalidKeyError
            If key not bytes or not 32 length
        """
        if not isinstance(key, bytes):
            raise InvalidKeyError(f"Key must be bytes, not {type(key)}")
        
        if len(key) != 32:
            raise InvalidKeyError(f"Key length must be 32, not {len(key)}")

        try:
            return crypto_core.split_secret(key, self.k, self.n)
        except ValueError as e:
            raise InvalidKeyError(str(e))

    def combine(self, shares: list[str]) -> bytes:
        """
        combine shares to secret key
        
        Parameters
        ----------
        shares: list[str]
            splitted pieces of secret key

        Returns
        -------
        secret key: bytes
            combined secret key

        Raises
        ------
        InvalidShareError
            If shares not string or less then k
        """
        for share in shares:
            if not isinstance(share, str):
                raise InvalidShareError(f"Share must be String, not {type(share)}")

        if len(shares) < self.k:
            raise InvalidShareError(f"Need at least {self.k} shares")

        try:
            return crypto_core.combine_shares(shares, self.k)
        except ValueError as e:
            raise InvalidShareError(str(e))

if __name__ == "__main__":
    key = b"12312421412234567123456789123456"
    shares = shamir_split(key)
    print(shares)
    print(shamir_combine(shares))