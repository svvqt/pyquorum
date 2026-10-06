## Known Security Issues

- **[MEDIUM]** Gaussian elimination in Blakley scheme is not constant-time
- **[LOW]** Shares are not authenticated: a corrupted or forged share silently yields a wrong key

These issues are tracked and will be fixed before 1.0.0 release.

## Fixed Security Issues

### v0.3.0

- **[CRITICAL]** Blakley scheme was fully broken for k >= 3. The random coordinates of the secret point and the hyperplane coefficients were drawn as 64-bit values (`rng.next_u64() % (PRIME - 1) + 1`) while the field is 2^127-1, so every coordinate of the secret point was small. With k-1 shares the secret was a solution of a modular linear system whose lattice vector was far shorter than the lattice minimum, and LLL recovered the point - and with it the whole 256-bit key - in milliseconds. Fixed by drawing both with the full field width (`rand_field_nonzero`). Regression test: `tests/security/test_blakley_lattice.py`
- **[HIGH]** Share fields were parsed without range or format validation. Values >= 2^127-1 broke the `mul_mod` contract (correct only for a, b < 2^127) and produced silently wrong keys; an index equal to p+1 returned an all-zero key; a repeated index spelled differently (`1` and `01`) zeroed the Lagrange denominator and returned an all-zero key; `k = 0` panicked the Rust core on `solution[0]`. Fixed with `parse_field` / `parse_index`, explicit duplicate detection, `mod_inv` returning an error instead of 0, `k >= 2` checks in both combine paths and `MAX_SHARES` as the upper bound for n. Regression test: `tests/security/test_input_validation.py`

### v0.2.1

- **[LOW]** Timing leak in modular multiplication (mul_mod)

## Note on the former [HIGH] entry "Secret key split into 4x64-bit chunks weakening 256-bit security"

That wording described the wrong thing. For Shamir the 4x64-bit split is not a weakening: with k-1 shares every 64-bit chunk stays uniform over a coset of size p, so the whole 256-bit key is preserved (the lattice attack from `tests/security/test_blakley_lattice.py` applied to Shamir recovers nothing). The real break was in Blakley, where the 4x64-bit split combined with 64-bit random coordinates gave the attack described above.
