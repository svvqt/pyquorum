from pyquorum import pyquorum_core
from ..exceptions import GenerateKeyError

def generate_key() -> bytes:
    """Generate a random secret key
    
    Returns
    --------
    bytes:
        32 byte generated key
    """
    try:
        return pyquorum_core.generate_key()
    except ValueError as e:
        raise GenerateKeyError(str(e))