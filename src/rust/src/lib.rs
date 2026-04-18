use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Константы ─────────────────────────────────────────────────────────────

const PRIME: u128 = (1u128 << 127) - 1;
const KEY_LEN: usize = 32;

// ── Защищённый тип ────────────────────────────────────────────────────────

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
struct SecretKey([u8; KEY_LEN]);

// ── Арифметика GF(p) ──────────────────────────────────────

fn mul_mod(a: u128, b: u128, m: u128) -> u128 {
    let mut result = 0u128;
    let mut base = a % m;
    let mut exp = b;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result + base) % m;
        }
        base = (base << 1) % m;
        exp >>= 1;
    }
    result
}

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

fn mod_inv(a: u128, p: u128) -> u128 {
    mod_pow(a, p - 2, p)
}

// ── Shamir's Secret Sharing ──────────────────

fn shamir_split_internal(secret: &[u8; KEY_LEN], k: usize, n: usize) -> Result<Vec<String>, String> {
    if k < 2 || n < k {
        return Err("Invalid k/n parameters".into());
    }

    let secrets = [
        u64::from_be_bytes(secret[0..8].try_into().unwrap()) as u128,
        u64::from_be_bytes(secret[8..16].try_into().unwrap()) as u128,
        u64::from_be_bytes(secret[16..24].try_into().unwrap()) as u128,
        u64::from_be_bytes(secret[24..32].try_into().unwrap()) as u128,
    ];

    let mut rng = OsRng;
    let mut rand_coeff = || {
        let lo = rng.next_u64() as u128;
        let hi = (rng.next_u64() as u128) & 0x7FFF_FFFF_FFFF_FFFF;
        (hi << 64 | lo) % PRIME
    };

    let coeffs: Vec<Vec<u128>> = secrets
        .iter()
        .map(|_| (0..k - 1).map(|_| rand_coeff()).collect())
        .collect();

    let eval_poly = |s: u128, c_list: &[u128], x: u128| -> u128 {
        let mut result = s;
        let mut x_pow = x;
        for &c in c_list {
            result = (result + mul_mod(c, x_pow, PRIME)) % PRIME;
            x_pow = mul_mod(x_pow, x, PRIME);
        }
        result
    };

    let shares = (1..=n as u128)
        .map(|x| {
            let res: Vec<String> = secrets
                .iter()
                .zip(&coeffs)
                .map(|(&s, c)| format!("{:032x}", eval_poly(s, c, x)))
                .collect();
            format!("{}:{}", x, res.join(":"))
        })
        .collect();

    Ok(shares)
}

fn shamir_combine_internal(shares: &[String], k: usize) -> Result<SecretKey, String> {
    if shares.len() < k {
        return Err(format!("Need at least {} shares", k));
    }

    let mut parsed = Vec::with_capacity(k);
    for s in &shares[..k] {
        let p: Vec<&str> = s.split(':').collect();
        if p.len() != 5 { return Err("Invalid format".into()); }
        let idx = p[0].parse::<u128>().map_err(|e| e.to_string())?;
        let vals = [
            u128::from_str_radix(p[1], 16).map_err(|e| e.to_string())?,
            u128::from_str_radix(p[2], 16).map_err(|e| e.to_string())?,
            u128::from_str_radix(p[3], 16).map_err(|e| e.to_string())?,
            u128::from_str_radix(p[4], 16).map_err(|e| e.to_string())?,
        ];
        parsed.push((idx, vals));
    }

    let mut key_bytes = [0u8; KEY_LEN];
    for comp in 0..4 {
        let mut result = 0u128;
        for i in 0..k {
            let (xi, yi) = (parsed[i].0, parsed[i].1[comp]);
            let (mut num, mut den) = (1u128, 1u128);
            for j in 0..k {
                if i == j { continue; }
                let xj = parsed[j].0;
                num = mul_mod(num, PRIME - (xj % PRIME), PRIME);
                let diff = if xi > xj { xi - xj } else { PRIME - (xj - xi) % PRIME };
                den = mul_mod(den, diff, PRIME);
            }
            let li = mul_mod(num, mod_inv(den, PRIME), PRIME);
            result = (result + mul_mod(yi, li, PRIME)) % PRIME;
        }
        key_bytes[comp * 8..(comp + 1) * 8].copy_from_slice(&(result as u64).to_be_bytes());
    }

    Ok(SecretKey(key_bytes))
}

// ── Линейная алгебра в GF(p) ─────────────────────────────────────────────

/// Решает систему Ax = B методом Гаусса в поле GF(p)
fn solve_system(mut matrix: Vec<Vec<u128>>, mut b: Vec<u128>, p: u128) -> Result<Vec<u128>, String> {
    let n = matrix.len();

    for i in 0..n {
        // Поиск опорного элемента
        let mut pivot = i;
        while pivot < n && matrix[pivot][i] == 0 { pivot += 1; }
        if pivot == n { return Err("System is linearly dependent".into()); }
        
        matrix.swap(i, pivot);
        b.swap(i, pivot);

        let inv = mod_inv(matrix[i][i], p);
        for j in i..n { matrix[i][j] = mul_mod(matrix[i][j], inv, p); }
        b[i] = mul_mod(b[i], inv, p);

        for k in 0..n {
            if k != i {
                let factor = matrix[k][i];
                for j in i..n {
                    let sub = mul_mod(factor, matrix[i][j], p);
                    matrix[k][j] = (matrix[k][j] + p - sub) % p;
                }
                let sub_b = mul_mod(factor, b[i], p);
                b[k] = (b[k] + p - sub_b) % p;
            }
        }
    }
    Ok(b)
}

// ── Blakley's Scheme ──────────────────────────────────────────────────────

fn blakley_split_internal(secret: &[u8; KEY_LEN], k: usize, n: usize) -> Result<Vec<String>, String> {
    if k < 2 || n < k { return Err("Invalid k/n".into()); }

    // Секрет — это точка (x1, x2, ..., xk). 
    // Для простоты распределим 32 байта ключа по координатам.
    // Если k=2, разобьем на 2 по 128 бит. Если k=4, по 64 бит.
    // Здесь мы просто дополним ключ до k координат по 127 бит.
    let mut point = vec![0u128; k];
    for i in 0..4 {
        if i < k {
            point[i] = u64::from_be_bytes(secret[i*8..(i+1)*8].try_into().unwrap()) as u128;
        }
    }

    let mut rng = OsRng;
    let mut shares = Vec::new();

    for _ in 0..n {
        // Генерируем коэффициенты гиперплоскости: a1*x1 + a2*x2 + ... + ak*xk = d
        let mut coeffs = vec![0u128; k];
        let mut d = 0u128;
        
        for i in 0..k {
            coeffs[i] = (rng.next_u64() as u128 % (PRIME - 1)) + 1;
            d = (d + mul_mod(coeffs[i], point[i], PRIME)) % PRIME;
        }

        // Доля: "a1,a2,...,ak:d"
        let coeffs_str: Vec<String> = coeffs.iter().map(|c| format!("{:032x}", c)).collect();
        shares.push(format!("{}:{:032x}", coeffs_str.join(","), d));
    }

    Ok(shares)
}

fn blakley_combine_internal(shares: &[String], k: usize) -> Result<SecretKey, String> {
    if shares.len() < k { return Err("Not enough shares".into()); }

    let mut a_matrix = Vec::new();
    let mut b_vector = Vec::new();

    for s in &shares[..k] {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 { return Err("Invalid format".into()); }
        
        let coeffs: Vec<u128> = parts[0].split(',')
            .map(|c| u128::from_str_radix(c, 16).unwrap())
            .collect();
        let d = u128::from_str_radix(parts[1], 16).unwrap();

        a_matrix.push(coeffs);
        b_vector.push(d);
    }

    let result_point = solve_system(a_matrix, b_vector, PRIME)?;
    
    let mut key = [0u8; KEY_LEN];
    for i in 0..4 {
        if i < result_point.len() {
            key[i*8..(i+1)*8].copy_from_slice(&(result_point[i] as u64).to_be_bytes());
        }
    }
    
    Ok(SecretKey(key))
}

// ── PyO3 bindings ─

#[pyfunction]
fn generate_key(py: Python<'_>) -> PyResult<Bound<'_, PyBytes>> {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    
    let result = PyBytes::new(py, &key);
    
    key.zeroize();
    Ok(result)
}

#[pyfunction]
fn shamir_split(secret: &[u8], k: usize, n: usize) -> PyResult<Vec<String>> {
    let key: [u8; KEY_LEN] = secret
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("Secret must be {} bytes", KEY_LEN)))?;
    
    shamir_split_internal(&key, k, n)
        .map_err(|e| PyValueError::new_err(e))
}

#[pyfunction]
fn shamir_combine<'py>(py: Python<'py>, shares: Vec<String>, k: usize) -> PyResult<Bound<'py, PyBytes>> {
    let key = shamir_combine_internal(&shares, k)
        .map_err(|e| PyValueError::new_err(e))?;
    
    Ok(PyBytes::new(py, &key.0))
}

#[pyfunction]
fn blakley_split(secret: &[u8], k: usize, n: usize) -> PyResult<Vec<String>> {
    let key: [u8; KEY_LEN] = secret.try_into()
        .map_err(|_| PyValueError::new_err("Secret must be 32 bytes"))?;
    blakley_split_internal(&key, k, n).map_err(PyValueError::new_err)
}

#[pyfunction]
fn blakley_combine<'py>(py: Python<'py>, shares: Vec<String>, k: usize) -> PyResult<Bound<'py, PyBytes>> {
    let key = blakley_combine_internal(&shares, k).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &key.0))
}

#[pymodule]
fn pyquorum_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_split, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_combine, m)?)?;
    m.add_function(wrap_pyfunction!(blakley_split,m)?)?;
    m.add_function(wrap_pyfunction!(blakley_combine,m)?)?;
    Ok(())
}