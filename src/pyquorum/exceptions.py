class PyQuorumError(Exception):
    pass

class InvalidKeyError(PyQuorumError):
    pass
    

class InvalidShareError(PyQuorumError):
    pass

class ThresholdError(PyQuorumError):
    def __init__(self, k, n):
        self.k = k
        self.n = n
    def __str__(self):
        return f"K must be less then N, now k={self.k}, n={self.n}"
    
class GenerateKeyError(PyQuorumError):
    pass