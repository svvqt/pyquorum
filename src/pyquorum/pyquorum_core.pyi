"""Type stubs for pyquorum_core, the Rust extension module.

Shipped next to pyquorum_core.pyd / .so and kept in sync with the
#[pyfunction] definitions in src/rust/src/lib.rs.
"""

def generate_key() -> bytes:
    """Return a random 32-byte secret key from the operating system CSPRNG.

    Raises ValueError only if the platform RNG is unavailable.
    """
    ...

def shamir_split(secret: bytes, k: int, n: int) -> list[str]:
    """Split a 32-byte secret into n Shamir shares in GF(2^127-1).

    k shares are needed to restore the secret, any k-1 of them reveal nothing.
    Raises ValueError if the secret is not 32 bytes, if k < 2, if n < k or if
    n is above the internal MAX_SHARES limit.
    """
    ...

def shamir_combine(shares: list[str], k: int) -> bytes:
    """Combine at least k Shamir shares back into the 32-byte secret.

    Raises ValueError if there are fewer than k shares or if a share is
    malformed, out of range or has an index that repeats another share.
    """
    ...

def blakley_split(secret: bytes, k: int, n: int) -> list[str]:
    """Split a 32-byte secret into n Blakley shares (hyperplanes in GF(p)^k).

    k shares are needed to restore the secret, any k-1 of them reveal nothing.
    Raises ValueError if the secret is not 32 bytes, if k < 2, if n < k or if
    n is above the internal MAX_SHARES limit.
    """
    ...

def blakley_combine(shares: list[str], k: int) -> bytes:
    """Combine at least k Blakley shares back into the 32-byte secret.

    Raises ValueError if there are fewer than k shares, if a share is
    malformed or out of range, or if the hyperplanes are linearly dependent.
    """
    ...
