/*!
 * crypto-core — Rust/PyO3
 *
 * Shamir's Secret Sharing (2-of-3) в поле GF(p), p = 2^127 - 1
 * Zeroize: чувствительные структуры обнуляются при drop()
 *
 * Ключ (32 байта = 4 × u64) — каждый u64 << PRIME, что гарантирует
 * корректную работу арифметики поля без потери данных.
 */

use pyo3::exceptions::PyValueError;
use rand::rngs::OsRng;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Константы ─────────────────────────────────────────────────────────────

/// Простое число Мерсенна: 2^127 - 1
const PRIME: u128 = (1u128 << 127) - 1;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32; // 256 бит = 4 × u64

// ── Защищённый тип ────────────────────────────────────────────────────────

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
struct SecretKey([u8; KEY_LEN]);

// ── Арифметика GF(p) ──────────────────────────────────────────────────────

/// Быстрое возведение в степень по модулю
fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        exp >>= 1;
        base = mul_mod(base, base, modulus);
    }
    result
}

/// Умножение по модулю через Russian Peasant (без переполнения u128).
/// a, b < PRIME < 2^127, поэтому a + a < 2^128 — безопасно.
fn mul_mod(a: u128, b: u128, m: u128) -> u128 {
    let mut result = 0u128;
    let mut base = a % m;
    let mut exp = b;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result + base) % m;
        }
        // base * 2: base < m < 2^127, поэтому base*2 < 2^128 — не переполняется
        base = (base << 1) % m;
        exp >>= 1;
    }
    result
}

/// Модульный обратный через малую теорему Ферма
fn mod_inv(a: u128, p: u128) -> u128 {
    mod_pow(a, p - 2, p)
}

// ── Shamir's Secret Sharing ────────────────────────────────────────────────
//
// 32-байтный ключ разбивается на 4 × u64 (a, b, c, d).
// Каждый u64 < 2^64 << PRIME (2^127-1) — гарантированно в поле GF(p).
// Для каждого из 4 компонентов строится независимый полином степени 1.
// Share format: "index:a_hex:b_hex:c_hex:d_hex"

/// Разделяет секрет на n частей, восстановимых по любым k из них.
/// Полином степени (k-1): f(x) = s + c1*x + c2*x^2 + ... + c_{k-1}*x^{k-1}
fn shamir_split_internal(secret: &[u8; KEY_LEN], k: usize, n: usize) -> Result<Vec<String>, String> {
    if k < 2 {
        return Err("k must be >= 2".into());
    }
    if n < k {
        return Err("n must be >= k".into());
    }

    let a = u64::from_be_bytes(secret[0..8].try_into().unwrap()) as u128;
    let b = u64::from_be_bytes(secret[8..16].try_into().unwrap()) as u128;
    let c = u64::from_be_bytes(secret[16..24].try_into().unwrap()) as u128;
    let d = u64::from_be_bytes(secret[24..32].try_into().unwrap()) as u128;

    let mut rng = OsRng;

    let rand_coeff = |rng: &mut OsRng| -> u128 {
        let lo = rng.next_u64() as u128;
        let hi = (rng.next_u64() as u128) & 0x7FFF_FFFF_FFFF_FFFF;
        (hi << 64 | lo) % PRIME
    };

    let secrets = [a, b, c, d];
    let coeffs: Vec<Vec<u128>> = secrets
        .iter()
        .map(|_| (0..k - 1).map(|_| rand_coeff(&mut rng)).collect())
        .collect();

    let eval_poly = |s: u128, coeffs: &[u128], x: u128| -> u128 {
        let mut result = s;
        let mut x_pow = x;
        for &c in coeffs {
            result = (result + mul_mod(c, x_pow, PRIME)) % PRIME;
            x_pow = mul_mod(x_pow, x, PRIME);
        }
        result
    };

    let shares = (1..=n as u128)
        .map(|x| {
            let fa = eval_poly(secrets[0], &coeffs[0], x);
            let fb = eval_poly(secrets[1], &coeffs[1], x);
            let fc = eval_poly(secrets[2], &coeffs[2], x);
            let fd = eval_poly(secrets[3], &coeffs[3], x);
            format!("{x}:{fa:032x}:{fb:032x}:{fc:032x}:{fd:032x}")
        })
        .collect();

    Ok(shares)
}

/// Восстанавливает секрет из любых k частей через интерполяцию Лагранжа.
fn shamir_combine_internal(shares: &[String], k: usize) -> Result<SecretKey, String> {
    if shares.len() < k {
        return Err(format!("Need at least {} shares", k));
    }

    let parse = |s: &str| -> Result<(u128, [u128; 4]), String> {
        let p: Vec<&str> = s.split(':').collect();
        if p.len() != 5 {
            return Err(format!("Invalid share format (need 5 fields): {}", s));
        }
        let idx = p[0].parse::<u128>().map_err(|e| e.to_string())?;
        let vals = [
            u128::from_str_radix(p[1], 16).map_err(|e| e.to_string())?,
            u128::from_str_radix(p[2], 16).map_err(|e| e.to_string())?,
            u128::from_str_radix(p[3], 16).map_err(|e| e.to_string())?,
            u128::from_str_radix(p[4], 16).map_err(|e| e.to_string())?,
        ];
        Ok((idx, vals))
    };

    // Парсим ровно k частей
    let parsed: Result<Vec<_>, _> = shares[..k].iter().map(|s| parse(s)).collect();
    let parsed = parsed?;

    // Интерполяция Лагранжа для f(0) по k точкам
    // f(0) = sum_i( y_i * prod_{j != i}( (0 - x_j) / (x_i - x_j) ) )
    let lagrange_at_zero = |component: usize| -> u128 {
        let mut result = 0u128;
        for i in 0..k {
            let (xi, yi) = (parsed[i].0, parsed[i].1[component]);
            let mut num = 1u128;   // числитель произведения
            let mut den = 1u128;   // знаменатель произведения
            for j in 0..k {
                if i == j { continue; }
                let xj = parsed[j].0;
                // (0 - xj) mod PRIME
                num = mul_mod(num, PRIME - xj % PRIME, PRIME);
                // (xi - xj) mod PRIME
                let diff = if xi > xj { xi - xj } else { PRIME - (xj - xi) % PRIME };
                den = mul_mod(den, diff, PRIME);
            }
            let li = mul_mod(num, mod_inv(den, PRIME), PRIME);
            result = (result + mul_mod(yi, li, PRIME)) % PRIME;
        }
        result
    };

    let ra = lagrange_at_zero(0);
    let rb = lagrange_at_zero(1);
    let rc = lagrange_at_zero(2);
    let rd = lagrange_at_zero(3);

    let mut key = SecretKey([0u8; KEY_LEN]);
    key.0[0..8].copy_from_slice(&(ra as u64).to_be_bytes());
    key.0[8..16].copy_from_slice(&(rb as u64).to_be_bytes());
    key.0[16..24].copy_from_slice(&(rc as u64).to_be_bytes());
    key.0[24..32].copy_from_slice(&(rd as u64).to_be_bytes());
    Ok(key)
}


// ── PyO3 bindings ─────────────────────────────────────────────────────────

/// Генерирует случайный 256-битный ключ
#[pyfunction]
fn generate_key(py: Python<'_>) -> PyObject {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let result = PyBytes::new(py, &key).into();
    key.zeroize();
    result
}

/// Разбивает 32-байтный секрет на 3 части Шамира (порог 2).
/// Возвращает список строк "index:a:b:c:d"
#[pyfunction]
fn split_secret(secret: &[u8], k: usize, n: usize) -> PyResult<Vec<String>> {
    if secret.len() != KEY_LEN {
        return Err(PyValueError::new_err(format!(
            "Secret must be exactly {} bytes",
            KEY_LEN
        )));
    }
    let key: [u8; KEY_LEN] = secret.try_into().unwrap();
    shamir_split_internal(&key, k, n)
        .map_err(|e| PyValueError::new_err(format!("Shamir split failed: {}", e)))
}

/// Восстанавливает секрет из 2+ частей. Возвращает bytes (32 байта).
#[pyfunction]
fn combine_shares(py: Python<'_>, shares: Vec<String>, k: usize) -> PyResult<PyObject> {
    let key = shamir_combine_internal(&shares, k)
        .map_err(|e| PyValueError::new_err(format!("Shamir combine failed: {}", e)))?;
    let result = PyBytes::new(py, &key.0).into();
    Ok(result)
}

#[pymodule]
fn pyquorum_core(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(split_secret, m)?)?;
    m.add_function(wrap_pyfunction!(combine_shares, m)?)?;
    Ok(())
}