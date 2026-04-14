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

fn shamir_split_internal(secret: &[u8; KEY_LEN]) -> Vec<String> {
    let a = u64::from_be_bytes(secret[0..8].try_into().unwrap()) as u128;
    let b = u64::from_be_bytes(secret[8..16].try_into().unwrap()) as u128;
    let c = u64::from_be_bytes(secret[16..24].try_into().unwrap()) as u128;
    let d = u64::from_be_bytes(secret[24..32].try_into().unwrap()) as u128;

    let mut rng = OsRng;

    // Для каждого компонента генерируем случайный коэффициент k1 полинома f(x) = s + k1*x
    let rand_coeff = |rng: &mut OsRng| -> u128 {
        let lo = rng.next_u64() as u128;
        let hi = (rng.next_u64() as u128) & 0x7FFF_FFFF_FFFF_FFFF; // < 2^63, чтобы результат < PRIME
        (hi << 64 | lo) % PRIME
    };

    let ka = rand_coeff(&mut rng);
    let kb = rand_coeff(&mut rng);
    let kc = rand_coeff(&mut rng);
    let kd = rand_coeff(&mut rng);

    // f(x) = s + k*x  mod PRIME   для x = 1, 2, 3
    (1u128..=3)
        .map(|x| {
            let fa = (a + mul_mod(ka, x, PRIME)) % PRIME;
            let fb = (b + mul_mod(kb, x, PRIME)) % PRIME;
            let fc = (c + mul_mod(kc, x, PRIME)) % PRIME;
            let fd = (d + mul_mod(kd, x, PRIME)) % PRIME;
            format!("{x}:{fa:016x}:{fb:016x}:{fc:016x}:{fd:016x}")
        })
        .collect()
}

/// Восстанавливает секрет из любых 2 частей через интерполяцию Лагранжа.
/// shares: ["index:a:b:c:d", ...]
fn shamir_combine_internal(shares: &[String]) -> Result<SecretKey, String> {
    if shares.len() < 2 {
        return Err("Need at least 2 shares".into());
    }

    // Парсим первые 2 части
    let parse = |s: &str| -> Result<(u128, u128, u128, u128, u128), String> {
        let p: Vec<&str> = s.split(':').collect();
        if p.len() != 5 {
            return Err(format!("Invalid share format (need 5 fields): {}", s));
        }
        let idx = p[0].parse::<u128>().map_err(|e| e.to_string())?;
        let a = u128::from_str_radix(p[1], 16).map_err(|e| e.to_string())?;
        let b = u128::from_str_radix(p[2], 16).map_err(|e| e.to_string())?;
        let c = u128::from_str_radix(p[3], 16).map_err(|e| e.to_string())?;
        let d = u128::from_str_radix(p[4], 16).map_err(|e| e.to_string())?;
        Ok((idx, a, b, c, d))
    };

    let s0 = parse(&shares[0])?;
    let s1 = parse(&shares[1])?;

    let (x0, x1) = (s0.0, s1.0);

    // Лагранж для двух точек: f(0) = y0*(0-x1)/((x0-x1)) + y1*(0-x0)/((x1-x0))
    // = y0*(-x1)/(x0-x1) + y1*(-x0)/(x1-x0)
    let recover = |y0: u128, y1: u128| -> u128 {
        // l0(0) = (-x1) / (x0 - x1) mod PRIME
        let neg_x1 = PRIME - x1 % PRIME;
        let diff01 = if x0 > x1 { x0 - x1 } else { PRIME - (x1 - x0) };
        let l0 = mul_mod(neg_x1, mod_inv(diff01, PRIME), PRIME);

        // l1(0) = (-x0) / (x1 - x0) mod PRIME
        let neg_x0 = PRIME - x0 % PRIME;
        let diff10 = if x1 > x0 { x1 - x0 } else { PRIME - (x0 - x1) };
        let l1 = mul_mod(neg_x0, mod_inv(diff10, PRIME), PRIME);

        (mul_mod(y0, l0, PRIME) + mul_mod(y1, l1, PRIME)) % PRIME
    };

    let ra = recover(s0.1, s1.1);
    let rb = recover(s0.2, s1.2);
    let rc = recover(s0.3, s1.3);
    let rd = recover(s0.4, s1.4);

    // ra..rd — восстановленные u64 компоненты (хранились как u64, так и возвращаем)
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
fn split_secret(secret: &[u8]) -> PyResult<Vec<String>> {
    if secret.len() != KEY_LEN {
        return Err(PyValueError::new_err(format!(
            "Secret must be exactly {} bytes",
            KEY_LEN
        )));
    }
    let key: [u8; KEY_LEN] = secret.try_into().unwrap();
    Ok(shamir_split_internal(&key))
}

/// Восстанавливает секрет из 2+ частей. Возвращает bytes (32 байта).
#[pyfunction]
fn combine_shares(py: Python<'_>, shares: Vec<String>) -> PyResult<PyObject> {
    let key = shamir_combine_internal(&shares)
        .map_err(|e| PyValueError::new_err(format!("Shamir combine failed: {}", e)))?;
    let result = PyBytes::new(py, &key.0).into();
    Ok(result)
}

#[pymodule]
fn crypto_core(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(split_secret, m)?)?;
    m.add_function(wrap_pyfunction!(combine_shares, m)?)?;
    Ok(())
}