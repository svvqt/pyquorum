import pyquorum
from ..exceptions import GenerateKeyError

def generate_key() -> bytes:
    """Generate a random secret key
    
    Returns
    --------
    bytes:
        32 byte generated key
    """
    try:
        return pyquorum.generate_key()
    except ValueError as e:
        raise GenerateKeyError(str(e))