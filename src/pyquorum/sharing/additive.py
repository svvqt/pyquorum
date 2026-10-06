import secrets

from .base import Scheme
from .shares import Shares
from ..exceptions import InvalidShareError, ThresholdError


class AdditiveScheme(Scheme):
    """
    Class for additive secret sharing (n-of-n)

    The secret is xor-ed with n-1 uniformly random byte strings of the same
    length, and the last share is the result of that xor.  Every single share
    is therefore a one-time pad over the secret: any n-1 of them reveal
    nothing about it, and all n are required to restore it.  Shares are
    combined with xor in GF(2^256), so the split is exact and needs no modular
    arithmetic.

    Parameters
    ----------
    n: int
        total number of shares to generate; the threshold is always n

    Raises
    ------
    ThresholdError
        If n is less than 2
    """

    def __init__(self, n: int):
        if n < 2:
            raise ThresholdError(n, n, f"AdditiveScheme needs at least 2 shares, got {n}")
        super().__init__(n, n)

    def split(self, key: bytes) -> Shares:
        """
        method for splitting secret key to number of shares

        Parameters
        ----------
        key: bytes
            secret key

        Returns
        -------
        shares: Shares
            secret key that splitted on shares

        Raises
        ------
        InvalidKeyError
            If key not bytes or not 32 length
        """
        super().split(key)

        shares = [secrets.token_bytes(len(key)) for _ in range(self.n - 1)]
        shares.append(self._xor(key, *shares))
        return Shares([f"{index}:{share.hex()}" for index, share in enumerate(shares, start=1)])

    def combine(self, shares: Shares) -> bytes:
        """
        combine shares to secret key

        Parameters
        ----------
        shares: Shares
            splitted pieces of secret key; exactly n shares, produced by split

        Returns
        -------
        secret key: bytes
            combined secret key

        Raises
        ------
        InvalidShareError
            If shares are fewer or more than n, have indices other than 1..n,
            or are not 32-byte hex strings
        """
        super().combine(shares)

        raw = [share.split(":", 1) for share in shares.to_raw()]
        if len(raw) != self.n:
            raise InvalidShareError(f"AdditiveScheme needs exactly {self.n} shares, got {len(raw)}")

        try:
            indices = sorted(int(index) for index, _ in raw)
        except ValueError:
            raise InvalidShareError("Share index must be a decimal number")
        if indices != list(range(1, self.n + 1)):
            raise InvalidShareError(f"Share indices must be exactly 1..{self.n}, got {indices}")

        try:
            chunks = [bytes.fromhex(value) for _, value in raw]
        except ValueError as error:
            raise InvalidShareError(f"Share value is not a valid hex string: {error}")

        sizes = sorted({len(chunk) for chunk in chunks})
        if sizes != [32]:
            raise InvalidShareError(f"Every share must be 32 bytes, got sizes {sizes}")

        return self._xor(*chunks)

    @staticmethod
    def _xor(*chunks: bytes) -> bytes:
        """Xor of equally sized byte strings; the first chunk defines the size"""
        result = 0
        for chunk in chunks:
            result ^= int.from_bytes(chunk, "big")
        return result.to_bytes(len(chunks[0]), "big")
