"""Known-answer tests for HKDF against RFC 5869 (SHA-256 test cases 1-3).

The first implementation seeded the expand chain with b"0" instead of the
empty string T(0) required by RFC 5869, so the first block - and with it the
whole output - was wrong.  These vectors catch that.

Runs under pytest and directly:

    python tests/KDF/test_hkdf.py
"""

if __name__ == "__main__":  # direct run: make `pyquorum` importable from src/
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from pyquorum import generate_key, hkdf
from pyquorum.exceptions import InvalidLengthError, PyQuorumError

# (name, IKM, salt, info, L, OKM) from RFC 5869 appendix A.1-A.3, SHA-256
RFC5869_SHA256 = (
    (
        "A.1",
        "0b" * 22,
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865",
    ),
    (
        "A.2",
        "".join("%02x" % i for i in range(0x00, 0x50)),  # 80 octets 00..4f
        "".join("%02x" % i for i in range(0x60, 0xB0)),  # 80 octets 60..af
        "".join("%02x" % i for i in range(0xB0, 0x100)),  # 80 octets b0..ff
        82,
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87",
    ),
    (
        "A.3",
        "0b" * 22,
        "",
        "",
        42,
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8",
    ),
)


def _expect(error, call):
    """Assert that the call raises exactly the expected error type."""
    try:
        call()
    except error:
        return
    except BaseException as other:
        raise AssertionError(f"expected {error.__name__}, got {type(other).__name__}: {other}")
    raise AssertionError(f"expected {error.__name__}, nothing was raised")


def test_rfc5869_sha256_vectors():
    for name, ikm, salt, info, length, okm in RFC5869_SHA256:
        output = hkdf(bytes.fromhex(ikm), length, bytes.fromhex(salt), bytes.fromhex(info))
        assert output.hex() == okm, f"RFC 5869 test case {name} failed"


def test_length_bounds():
    key = generate_key()
    for length in (1, 31, 32, 33, 100, 255 * 32):
        assert len(hkdf(key, length)) == length
    for length in (0, -1, 255 * 32 + 1):
        _expect(InvalidLengthError, lambda value=length: hkdf(key, value))


def test_length_error_is_both_a_pyquorum_error_and_a_value_error():
    try:
        hkdf(generate_key(), 0)
    except InvalidLengthError as error:
        assert isinstance(error, PyQuorumError)
        assert isinstance(error, ValueError)
    else:
        raise AssertionError("InvalidLengthError was not raised")


def test_public_parameter_names():
    """The public names are the RFC 5869 ones: ikm / length / salt / info."""
    key = bytes.fromhex("0b" * 22)
    assert hkdf(ikm=key, length=42) == hkdf(key, 42)
    assert hkdf(key, 42, salt=b"salt", info=b"info") == hkdf(key, 42, b"salt", b"info")
    assert hkdf(ikm=key, length=42, salt=None, info=None) == hkdf(key, 42)


def test_types_are_checked():
    key = generate_key()
    _expect(TypeError, lambda: hkdf("not bytes", 32))
    _expect(TypeError, lambda: hkdf(key, "32"))
    _expect(TypeError, lambda: hkdf(key, 32, "not bytes"))
    _expect(TypeError, lambda: hkdf(key, 32, b"salt", "not bytes"))


def test_empty_salt_is_the_default_of_hashlen_zeros():
    key = bytes.fromhex("0b" * 22)
    default = hkdf(key, 42)
    assert default == hkdf(key, 42, b"")
    assert default == hkdf(key, 42, None)
    assert default == hkdf(key, 42, bytes(32))


def test_output_is_a_prefix_of_a_longer_output():
    key = generate_key()
    assert hkdf(key, 600, b"salt", b"info") == hkdf(key, 1000, b"salt", b"info")[:600]


def test_output_is_deterministic_and_context_bound():
    key = generate_key()
    assert hkdf(key, 32, b"salt", b"info") == hkdf(key, 32, b"salt", b"info")
    assert hkdf(key, 32, b"salt", b"info") != hkdf(key, 32, b"salt", b"other")
    assert hkdf(key, 32, b"salt", b"info") != hkdf(key, 32, b"other", b"info")
    assert hkdf(key, 32) != hkdf(generate_key(), 32)


if __name__ == "__main__":
    import traceback

    selected = [name for name in sorted(globals()) if name.startswith("test_")]
    if len(sys.argv) > 1:  # optional name filter
        selected = [name for name in selected if any(arg in name for arg in sys.argv[1:])]
    failed = 0
    for _name in selected:
        try:
            globals()[_name]()
            print("PASS  " + _name)
        except BaseException:
            failed += 1
            print("FAIL  " + _name)
            traceback.print_exc()
    print("")
    print("%d failed" % failed)
    raise SystemExit(1 if failed else 0)
