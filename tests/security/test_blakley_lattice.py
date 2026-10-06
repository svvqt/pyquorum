"""Regression test for the Blakley lattice break (fixed in 0.3.0).

Before the fix the random coordinates of the secret point and the hyperplane
coefficients were drawn as 64-bit values while the field is 2^127-1.  Every
coordinate of the secret point was therefore small, so k-1 shares formed a
modular linear system whose solution was a very short lattice vector; LLL
recovered the point - and with it the whole 256-bit key - for every k >= 3.

The attack below is a self-contained pure-Python implementation, with no
third-party dependencies.  Against the fixed core it must fail.

Runs under pytest and directly:

    python tests/security/test_blakley_lattice.py
"""

if __name__ == "__main__":  # direct run: make `pyquorum` importable from src/
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from fractions import Fraction

from pyquorum import BlakleyScheme, Shares, generate_key

PRIME = (1 << 127) - 1
SMALL = 1 << 64  # a coordinate below this bound is "short"
DELTA = Fraction(3, 4)
MAX_LLL_STEPS = 100_000


def _gram_schmidt(basis):
    size = len(basis)
    width = len(basis[0])
    ortho = []
    mu = [[Fraction(0)] * size for _ in range(size)]
    for i in range(size):
        vec = [Fraction(x) for x in basis[i]]
        for j in range(i):
            norm = sum(ortho[j][t] * ortho[j][t] for t in range(width))
            mu[i][j] = sum(Fraction(basis[i][t]) * ortho[j][t] for t in range(width)) / norm
            vec = [vec[t] - mu[i][j] * ortho[j][t] for t in range(width)]
        ortho.append(vec)
    return ortho, mu


def _lll(basis):
    """Exact-arithmetic LLL reduction (the lattices used here are tiny)."""
    basis = [list(row) for row in basis]
    size = len(basis)
    ortho, mu = _gram_schmidt(basis)
    k = 1
    for _ in range(MAX_LLL_STEPS):
        if k >= size:
            break
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                factor = int(round(mu[k][j]))
                if factor:
                    basis[k] = [basis[k][t] - factor * basis[j][t] for t in range(len(basis[k]))]
                    ortho, mu = _gram_schmidt(basis)
        left = sum(ortho[k][t] * ortho[k][t] for t in range(len(ortho[k])))
        right = sum(ortho[k - 1][t] * ortho[k - 1][t] for t in range(len(ortho[k - 1])))
        if left >= (DELTA - mu[k][k - 1] ** 2) * right:
            k += 1
        else:
            basis[k], basis[k - 1] = basis[k - 1], basis[k]
            ortho, mu = _gram_schmidt(basis)
            k = max(k - 1, 1)
    return basis


def _solve_square(matrix, rhs):
    """Solve a square system in GF(p); None when the matrix is singular."""
    size = len(matrix)
    rows = [list(row) + [rhs[i] % PRIME] for i, row in enumerate(matrix)]
    for col in range(size):
        pivot = None
        for r in range(col, size):
            if rows[r][col] % PRIME:
                pivot = r
                break
        if pivot is None:
            return None
        rows[col], rows[pivot] = rows[pivot], rows[col]
        inv = pow(rows[col][col] % PRIME, PRIME - 2, PRIME)
        rows[col] = [(v * inv) % PRIME for v in rows[col]]
        for r in range(size):
            if r != col and rows[r][col] % PRIME:
                factor = rows[r][col] % PRIME
                rows[r] = [(rows[r][t] - factor * rows[col][t]) % PRIME for t in range(size + 1)]
    return [rows[i][size] % PRIME for i in range(size)]


def _solution_lattice(coefficients, values, k):
    """All solutions of A*x = d (mod p): a particular point plus an integer basis."""
    for free in range(k):
        columns = [c for c in range(k) if c != free]
        matrix = [[row[c] for c in columns] for row in coefficients]
        particular = _solve_square(matrix, values)
        direction = _solve_square(matrix, [(-row[free]) % PRIME for row in coefficients])
        if particular is None or direction is None:
            continue
        point = [0] * k
        vector = [0] * k
        for pos, col in enumerate(columns):
            point[col] = particular[pos]
            vector[col] = direction[pos]
        vector[free] = 1
        basis = [vector]
        basis += [[PRIME if t == i else 0 for t in range(k)] for i in range(k) if i != free]
        return point, basis
    return None, None


def _attack_chunk(coefficients, values, k):
    """Try to recover the secret coordinate from k-1 shares.

    Returns the recovered coordinate, or None when no short solution exists
    (that is, when the attack failed).
    """
    particular, basis = _solution_lattice(coefficients, values, k)
    if particular is None:
        return None
    # Kannan embedding: a lattice vector (x, +-SMALL) with small x is a point
    # of the solution set whose coordinates are all below SMALL.
    rows = [row + [0] for row in basis] + [particular + [SMALL]]
    for row in _lll(rows):
        if abs(row[-1]) != SMALL:
            continue
        point = [v % PRIME for v in row[:-1]] if row[-1] > 0 else [(-v) % PRIME for v in row[:-1]]
        if not all(0 <= v < SMALL for v in point):
            continue
        if all((sum(coefficients[i][j] * point[j] for j in range(k)) - values[i]) % PRIME == 0
               for i in range(len(coefficients))):
            return point[0]
    return None


def _attack_input(shares, k):
    """Parse the k-1 shares an attacker would hold."""
    coefficients = []
    values = []
    for share in shares[:k - 1]:
        parts = share.split(":")
        coefficients.append([int(c, 16) for c in parts[0].split(",")])
        values.append([int(x, 16) for x in parts[1:]])
    return coefficients, values


def test_k_minus_one_shares_do_not_reveal_the_key():
    for k in (3, 4, 5):
        for _ in range(2):
            scheme = BlakleyScheme(k, k + 2)
            shares = scheme.split(generate_key()).to_raw()
            key = scheme.combine(Shares(shares))
            coefficients, values = _attack_input(shares, k)
            recovered = [
                _attack_chunk(coefficients, [values[i][block] for i in range(k - 1)], k)
                for block in range(4)
            ]
            assert recovered == [None] * 4, (
                "LLL recovered the secret point from k-1 shares (k=%d, key=%s): %r"
                % (k, key.hex(), recovered)
            )


def test_k_shares_still_reconstruct_the_key():
    for k in (2, 3, 4):
        scheme = BlakleyScheme(k, k + 2)
        key = generate_key()
        shares = scheme.split(key)
        assert scheme.combine(Shares(shares.to_raw()[:k])) == key
        assert scheme.combine(shares) == key


def test_coefficients_use_the_full_field_width():
    """Fast structural guard: coefficients must not be 64-bit again.

    The coordinates of the secret point are not visible from the outside; they
    are covered by test_k_minus_one_shares_do_not_reveal_the_key.
    """
    scheme = BlakleyScheme(3, 5)
    shares = scheme.split(generate_key()).to_raw()
    coefficients = [int(c, 16) for share in shares for c in share.split(":")[0].split(",")]
    assert any(c.bit_length() > 64 for c in coefficients), "all Blakley coefficients are 64-bit"


if __name__ == "__main__":
    import traceback

    selected = [n for n in sorted(globals()) if n.startswith("test_")]
    if len(sys.argv) > 1:  # optional name filter, e.g. `... test_k_minus_one`
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
