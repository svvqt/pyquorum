# Changelog

## [0.3.0] - 2026-x-x

### Added

- HKDF - `def hkdf(skm, length, salt, CTXInfo)`
- Additive Scheme - `Class AdditiveScheme`

### Fixed

- Rust core: Blakley scheme was broken for k >= 3 (LLL recovered the key from k-1 shares), see SECURITY_ISSUES_TRACKER.md
- Rust core: share fields are validated (range, format, duplicate index) - no silently wrong or all-zero keys, no panic on k = 0
- HKDF now follows RFC 5869 (T(0) is the empty string, output length is validated) and passes its SHA-256 test vectors
- Additive Scheme: shares are xor-ed in GF(2^256) instead of added modulo 2^127+1, so combine(split(key)) returns the key

## [0.2.1] - 2026-04-29

### Fixed
- Timing leak in modular multiplication (mul_mod)

## [0.2.0] - 2026-04-24

### Added
- Blakley Scheme Sharing - `Class BlakleyScheme`
- Class Shares for serialize splitted pieces by Scheme Sharing - `Class Shares`

## [0.1.3] - 2026-04-17

### Updated
- Supports python 3.9+
- Updated rust core to pyo3 0.28.3

## [0.1.2] - 2026-04-16

### Added
- Shamir Scheme Sharing - `Class ShamirScheme`
- Function for generate secret key - `def generate_key()`