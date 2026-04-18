from abc import ABC, abstractmethod
from .shares import Shares
from ..exceptions import ThresholdError, InvalidKeyError, InvalidShareError


class Scheme(ABC):
    def __init__(self, k: int, n: int):
        self.k = k
        self.n = n
        if self.k > self.n:
            raise ThresholdError(self.k, self.n)

    @abstractmethod
    def split(self, key: bytes) -> list[str]:
        """Разделение ключа"""
        if not isinstance(key, bytes):
            raise InvalidKeyError(f"Key must be bytes, not {type(key)}")
        
        if len(key) != 32:
            raise InvalidKeyError(f"Key length must be 32, not {len(key)}")


    @abstractmethod
    def combine(self, shares: Shares) -> bytes:
        """Соединение ключа"""

        if len(shares.to_raw()) < self.k:
            raise InvalidShareError(f"Need at least {self.k} shares")
