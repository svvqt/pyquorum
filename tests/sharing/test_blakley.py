import pytest
from pyquorum import BlakleyScheme, generate_key, Shares

@pytest.fixture
def scheme_test():
    return BlakleyScheme(4, 7)

@pytest.fixture
def key_test():
    return generate_key()


def test_split_combine_full_shares(scheme_test, key_test):
    shares = scheme_test.split(key_test)
    source = scheme_test.combine(shares)
    assert source == key_test

def test_split_combine(scheme_test, key_test):
    shares = scheme_test.split(key_test)
    source = scheme_test.combine(Shares([shares.to_raw()[i] for i in range(scheme_test.k)]))
    assert source == key_test