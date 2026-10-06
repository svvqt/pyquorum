"""Tests for the additive (n-of-n) secret sharing scheme.

The scheme used to combine shares by modular addition modulo 2^127+1 - a
composite number shorter than the 256-bit key - so the upper half of the
restored key was always zero and combine(split(key)) never returned the key.
Shares are now xor-ed in GF(2^256).

Runs under pytest and directly:

    python tests/sharing/test_additive.py
"""

if __name__ == "__main__":  # direct run: make `pyquorum` importable from src/
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from pyquorum import AdditiveScheme, Shares, generate_key
from pyquorum.exceptions import InvalidKeyError, InvalidShareError, ThresholdError


def _expect(error, call):
    """Assert that the call raises exactly the expected error type."""
    try:
        call()
    except error:
        return
    except BaseException as other:
        raise AssertionError(f"expected {error.__name__}, got {type(other).__name__}: {other}")
    raise AssertionError(f"expected {error.__name__}, nothing was raised")


def test_roundtrip_for_several_share_counts():
    for n in (2, 3, 5, 8):
        scheme = AdditiveScheme(n)
        key = generate_key()
        assert scheme.combine(scheme.split(key)) == key, f"n={n}"


def test_share_format():
    scheme = AdditiveScheme(4)
    shares = scheme.split(generate_key()).to_raw()
    assert [share.split(":", 1)[0] for share in shares] == ["1", "2", "3", "4"]
    assert all(len(share.split(":", 1)[1]) == 64 for share in shares)


def test_shares_are_random_and_differ_from_the_key():
    scheme = AdditiveScheme(5)
    key = generate_key()
    values = [share.split(":", 1)[1] for share in scheme.split(key).to_raw()]
    assert len(set(values)) == 5, "shares must not repeat"
    assert key.hex() not in values, "no share may equal the key"


def test_n_minus_one_shares_reveal_nothing():
    """Xor of any n-1 shares must never be the secret itself."""
    n = 4
    scheme = AdditiveScheme(n)
    key = generate_key()
    shares = scheme.split(key).to_raw()
    for dropped in range(n):
        combined = 0
        for index, share in enumerate(shares):
            if index != dropped:
                combined ^= int(share.split(":", 1)[1], 16)
        assert combined.to_bytes(32, "big") != key, f"dropped share {dropped + 1}"


def test_all_n_shares_are_required():
    scheme = AdditiveScheme(3)
    key = generate_key()
    shares = scheme.split(key).to_raw()
    _expect(InvalidShareError, lambda: scheme.combine(Shares(shares[:1])))
    _expect(InvalidShareError, lambda: scheme.combine(Shares(shares[:2])))
    _expect(InvalidShareError, lambda: scheme.combine(Shares(AdditiveScheme(4).split(key).to_raw())))
    assert scheme.combine(Shares(list(reversed(shares)))) == key


def test_repeated_share_is_rejected():
    """The same share twice would cancel itself out in the xor."""
    scheme = AdditiveScheme(2)
    key = generate_key()
    first, _ = scheme.split(key).to_raw()
    index, value = first.split(":", 1)
    _expect(InvalidShareError, lambda: scheme.combine(Shares([first, first])))
    _expect(InvalidShareError, lambda: scheme.combine(Shares([first, f"0{index}:{value}"])))


def test_non_canonical_index_spelling_is_normalised():
    """Indices are compared as numbers, so 01 is still share 1."""
    scheme = AdditiveScheme(2)
    key = generate_key()
    first, second = scheme.split(key).to_raw()
    index, value = first.split(":", 1)
    assert scheme.combine(Shares([f"0{index}:{value}", second])) == key


def test_foreign_or_missing_indices_are_rejected():
    scheme = AdditiveScheme(3)
    shares = scheme.split(generate_key()).to_raw()
    renumbered = [f"{int(share.split(':', 1)[0]) + 10}:{share.split(':', 1)[1]}" for share in shares]
    _expect(InvalidShareError, lambda: scheme.combine(Shares(renumbered)))


def test_broken_share_content_is_rejected():
    scheme = AdditiveScheme(2)
    shares = scheme.split(generate_key()).to_raw()
    _expect(InvalidShareError, lambda: scheme.combine(Shares(["1:zz", shares[1]])))
    _expect(InvalidShareError, lambda: scheme.combine(Shares(["1:ab", shares[1]])))
    _expect(InvalidShareError, lambda: scheme.combine(Shares(["1:", shares[1]])))


def test_corrupted_share_returns_a_wrong_key_without_error():
    """Known open issue: shares are not authenticated, so an attacker who can
    flip a bit in a share silently changes the restored key.
    """
    scheme = AdditiveScheme(2)
    key = generate_key()
    first, second = scheme.split(key).to_raw()
    index, value = first.split(":", 1)
    broken = "%s:%064x" % (index, int(value, 16) ^ 1)
    assert scheme.combine(Shares([broken, second])) != key


def test_invalid_key_is_rejected():
    scheme = AdditiveScheme(3)
    _expect(InvalidKeyError, lambda: scheme.split("fqsar"))
    _expect(InvalidKeyError, lambda: scheme.split(b"1234"))


def test_threshold_below_two_is_rejected():
    _expect(ThresholdError, lambda: AdditiveScheme(1))
    _expect(ThresholdError, lambda: AdditiveScheme(0))


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
