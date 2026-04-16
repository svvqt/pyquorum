import pytest
from pyquorum import ShamirScheme, generate_key
from pyquorum.exceptions import InvalidKeyError, InvalidShareError, ThresholdError

@pytest.fixture
def scheme_test():
    return ShamirScheme(4, 7)

@pytest.fixture
def key_test():
    return generate_key()

def test_split_combine_full_shares(scheme_test, key_test):
    shares = scheme_test.split(key_test)
    source = scheme_test.combine(shares)
    assert source == key_test

def test_split_combine(scheme_test, key_test):
    shares = scheme_test.split(key_test)
    source = scheme_test.combine([shares[i] for i in range(scheme_test.k)])
    assert source == key_test

def test_invalid_key_type(scheme_test):
    with pytest.raises(InvalidKeyError):
        scheme_test.split("fqsar")

def test_invalid_key_length(scheme_test):
    with pytest.raises(InvalidKeyError):
        scheme_test.split(b"1234")

def test_invalid_share_type(scheme_test):
    with pytest.raises(InvalidShareError):
        scheme_test.combine([123, 456])

def test_empty_share(scheme_test):
    with pytest.raises(InvalidShareError):
        scheme_test.combine([])

def test_threshold_error():
    with pytest.raises(ThresholdError):
        ShamirScheme(3, 2)

def test_not_enough_share(scheme_test, key_test):
    shares = scheme_test.split(key_test)
    with pytest.raises(InvalidShareError):
        scheme_test.combine([shares[0]])