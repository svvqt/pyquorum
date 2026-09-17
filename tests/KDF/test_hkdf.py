from pyquorum import hkdf, generate_key


def test_lenght_hkdf():
    key = generate_key()
    output = hkdf(key, 100)
    assert len(output) == 100


def test_valid_hkdf():
    key = b"input_key"
    salt = b"add_some_salt"
    output = hkdf(key, 100, salt)
    assert output.hex() == "2bcd8350cc31b6945b23b2a47add4d5ec4b1bd9fad0387590bf4e9f4d34ea456e63267c765e7cd5451df1f6f18f41eaba20de594fd8c6a008120276438d18fc4122ec152fff03204c966261b60408a569b6b0e3527ae4a34570c62b2d060fd15f3176a36"