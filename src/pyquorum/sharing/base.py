from abc import ABC, abstractmethod
from ..exceptions import ThresholdError


class Scheme(ABC):
    def __init__(self, k: int, n: int):
        self.k = k
        self.n = n
        if self.k > self.n:
            raise ThresholdError(self.k, self.n)

    @abstractmethod
    def split(self, key: bytes) -> list[str]:
        """Разделение ключа"""
        pass

    @abstractmethod
    def combine(self, shares: list[str]) -> bytes:
        """Соединение ключа"""
        pass
