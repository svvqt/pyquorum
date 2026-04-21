import pytest
from pyquorum.exceptions import InvalidShareError
from pyquorum import Shares


@pytest.mark.parametrize("wrong_type_share", [
    ("Wrong type"), (3, 4, 5), ([3, 4, 5, 6, 7]), ([b"not str", b"still no str"])
    ])
def test_invalid_type_share(wrong_type_share):
    with pytest.raises(InvalidShareError):
        Shares(wrong_type_share)

def test_convert_base64():
    shares = Shares(["1:123421", "2:312124"])
    shares_base64 = shares.to_base64()
    assert shares.to_raw() == Shares.from_base64(shares_base64).to_raw()

def test_convert_json():
    shares = Shares(["1:123421", "2:312124"])
    shares_json = shares.to_json()
    assert shares.to_raw() == Shares.from_json(shares_json).to_raw()