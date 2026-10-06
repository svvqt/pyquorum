# Changelog

## [0.3.0] - 2026-10-06

### Added

- HKDF - `def hkdf(ikm, length, salt, info)`
- Additive Scheme - `Class AdditiveScheme`

### Fixed

- Rust core: Blakley scheme was broken for k >= 3 (LLL recovered the key from k-1 shares), see SECURITY_ISSUES_TRACKER.md
- Rust core: share fields are validated (range, format, duplicate index) - no silently wrong or all-zero keys, no panic on k = 0

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