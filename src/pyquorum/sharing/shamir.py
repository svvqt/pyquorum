from pyquorum import pyquorum_core
from .base import Scheme
from .shares import Shares
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
    def split(self, key: bytes) -> Shares:
        """
        method for splitting secret key to number of shares

        Parameters
        ----------
        key: bytes
            secret key
        
        Returns
        -------
        shares: Shares:
            secret key that splitted on shares 

        Raises
        ------
        InvalidKeyError
            If key not bytes or not 32 length
        """
        super().split(key)
        try:
            return Shares(pyquorum_core.shamir_split(key, self.k, self.n))
        except ValueError as e:
            raise InvalidKeyError(str(e))

    def combine(self, shares: Shares) -> bytes:
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
        super().combine(shares)
        try:
            return pyquorum_core.shamir_combine(shares.to_raw(), self.k)
        except ValueError as e:
            raise InvalidShareError(str(e))
