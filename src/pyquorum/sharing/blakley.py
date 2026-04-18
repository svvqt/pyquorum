from .base import Scheme
from .shares import Shares
from ..exceptions import InvalidKeyError, InvalidShareError
from pyquorum import pyquorum_core

class BlakleyScheme(Scheme):
    """
    Class for Blakley secret sharing
    
    Parameters
    ----------
    k: int
        minimum number of shares required to reconstruct the secret
    n: int
        total number of shares to generate
    """
    def split(self, key:bytes) -> Shares:
        super().split(key)
        try:
            return Shares(pyquorum_core.blakley_split(key, self.k, self.n))
        except ValueError as e:
            raise InvalidKeyError(str(e))

    def combine(self, shares: Shares) -> bytes:
        super().combine(shares)
        try:
            return pyquorum_core.blakley_combine(shares.to_raw(), self.k)
        except ValueError as e:
            raise InvalidShareError(str(e))