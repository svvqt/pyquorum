"""Regression test for share input validation (fixed in 0.3.0).

Before the fix untrusted share fields were parsed without any range or format
check.  Values >= 2^127-1 broke the mul_mod contract (correct only for
a, b < 2^127) and produced silently wrong keys, an index equal to p+1 and a
repeated index spelled differently ("1" and "01") both returned an all-zero
key, and k = 0 panicked the Rust core.

Runs under pytest and directly:

    python tests/security/test_input_validation.py
"""

if __name__ == "__main__":  # direct run: make `pyquorum` importable from src/
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from pyquorum import BlakleyScheme, ShamirScheme, Shares, generate_key
from pyquorum.exceptions import PyQuorumError

PRIME_MINUS_ONE = (1 << 127) - 1
MAX_SHARES = 1 << 20  # upper bound for n in the Rust core


def _sample(k=2, n=3):
    scheme = ShamirScheme(k, n)
    key = generate_key()
    return scheme, key, scheme.split(key).to_raw()


def _expect_rejected(call):
    """Assert the call is rejected with a PyQuorum error and return its text."""
    try:
        result = call()
    except PyQuorumError as exc:
        return str(exc)
    except BaseException as exc:  # includes pyo3 PanicException
        raise AssertionError("expected a PyQuorumError, got %s: %s" % (type(exc).__name__, exc))
    raise AssertionError("untrusted input was accepted, result: %r" % (result,))


def _replace(share, position, value):
    parts = share.split(":")
    parts[position] = value
    return ":".join(parts)


def test_field_at_or_above_prime_is_rejected():
    scheme, _, shares = _sample()
    value = int(shares[0].split(":")[1], 16) + PRIME_MINUS_ONE
    broken = _replace(shares[0], 1, "%032x" % value)
    _expect_rejected(lambda: scheme.combine(Shares([broken, shares[1]])))


def test_index_at_or_above_prime_is_rejected():
    scheme, _, shares = _sample()
    broken = _replace(shares[0], 0, str(PRIME_MINUS_ONE + 1))
    _expect_rejected(lambda: scheme.combine(Shares([broken, shares[1]])))


def test_duplicate_index_spelled_differently_is_rejected():
    scheme, _, shares = _sample()
    duplicate = _replace(shares[0], 0, "0" + shares[0].split(":")[0])
    _expect_rejected(lambda: scheme.combine(Shares([shares[0], duplicate])))


def test_malformed_hex_field_is_rejected():
    for field in ("", "abc", "a" * 33, "z" * 32):
        scheme, _, shares = _sample()
        broken = _replace(shares[0], 1, field)
        other = shares[1]
        _expect_rejected(lambda b=broken, s=scheme, o=other: s.combine(Shares([b, o])))


def test_uppercase_hex_is_accepted():
    scheme, key, shares = _sample()
    uppercase = _replace(shares[0], 1, shares[0].split(":")[1].upper())
    assert scheme.combine(Shares([uppercase, shares[1]])) == key


def test_threshold_below_two_is_rejected():
    key = generate_key()
    shamir = ShamirScheme(2, 3).split(key).to_raw()
    blakley = BlakleyScheme(2, 3).split(key).to_raw()
    cases = (
        (ShamirScheme(0, 0), []),
        (ShamirScheme(1, 1), shamir[:1]),
        (BlakleyScheme(0, 0), []),
        (BlakleyScheme(1, 1), blakley[:1]),
    )
    for scheme, shares in cases:
        _expect_rejected(lambda s=scheme, v=shares: s.combine(Shares(v)))


def test_share_count_above_the_limit_is_rejected():
    key = generate_key()
    _expect_rejected(lambda: ShamirScheme(2, MAX_SHARES + 1).split(key))
    _expect_rejected(lambda: BlakleyScheme(2, MAX_SHARES + 1).split(key))


def test_corrupted_share_still_returns_a_wrong_key_without_error():
    """Known open issue: shares are not authenticated (no VSS/MAC), so a
    corrupted share silently yields a wrong key.  Update this test if
    integrity checking is added.
    """
    scheme, key, shares = _sample()
    broken = _replace(shares[0], 1, "%032x" % (int(shares[0].split(":")[1], 16) ^ 1))
    assert scheme.combine(Shares([broken, shares[1]])) != key


if __name__ == "__main__":
    import traceback

    selected = [n for n in sorted(globals()) if n.startswith("test_")]
    if len(sys.argv) > 1:  # optional name filter, e.g. `... test_threshold`
        selected = [n for n in selected if any(arg in n for arg in sys.argv[1:])]
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
