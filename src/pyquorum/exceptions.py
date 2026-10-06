class PyQuorumError(Exception):
    pass


class InvalidKeyError(PyQuorumError):
    pass


class InvalidShareError(PyQuorumError):
    pass


class ThresholdError(PyQuorumError):
    def __init__(self, k, n, message=None):
        self.k = k
        self.n = n
        self.message = message

    def __str__(self):
        if self.message:
            return self.message
        return f"K must be less then N, now k={self.k}, n={self.n}"


class GenerateKeyError(PyQuorumError):
    pass
