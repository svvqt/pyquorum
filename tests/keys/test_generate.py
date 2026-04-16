from pyquorum import generate_key

def test_byte_return():
    key = generate_key()
    assert isinstance(key, bytes)

def test_length_key():
    key = generate_key()
    assert len(key) == 32

def test_unique_keys():
    keys = [generate_key() for _ in range(5)]
    assert len(set(keys)) == 5