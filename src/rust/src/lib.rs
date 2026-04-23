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

    let mut rng = OsRng;
    
    // 1. Разбиваем секрет на 4 блока по 8 байт
    let chunks = [
        u64::from_be_bytes(secret[0..8].try_into().unwrap()) as u128,
        u64::from_be_bytes(secret[8..16].try_into().unwrap()) as u128,
        u64::from_be_bytes(secret[16..24].try_into().unwrap()) as u128,
        u64::from_be_bytes(secret[24..32].try_into().unwrap()) as u128,
    ];

    // 2. Для каждого блока создаем фиксированную "секретную точку" в k-мерном пространстве
    // Точка P = (chunk, r1, r2, ..., r_{k-1})
    let mut secret_points = Vec::new();
    for &chunk in &chunks {
        let mut point = vec![chunk];
        for _ in 1..k {
            point.push((rng.next_u64() as u128 % (PRIME - 1)) + 1);
        }
        secret_points.push(point);
    }

    let mut shares = Vec::new();

    // 3. Генерируем n долей (гиперплоскостей)
    for _ in 0..n {
        // Коэффициенты a1, a2, ..., ak общие для всех 4-х блоков в рамках одной доли
        let mut a_coeffs = vec![0u128; k];
        for i in 0..k {
            a_coeffs[i] = (rng.next_u64() as u128 % (PRIME - 1)) + 1;
        }

        // Вычисляем d_j = A * P_j для каждого из 4-х блоков
        let mut d_results = Vec::new();
        for point in &secret_points {
            let mut d = 0u128;
            for i in 0..k {
                d = (d + mul_mod(a_coeffs[i], point[i], PRIME)) % PRIME;
            }
            d_results.push(format!("{:032x}", d));
        }

        let a_str: Vec<String> = a_coeffs.iter().map(|c| format!("{:032x}", c)).collect();
        // Результат: "a1,a2,a3:d1:d2:d3:d4"
        shares.push(format!("{}:{}", a_str.join(","), d_results.join(":")));
    }

    Ok(shares)
}

fn blakley_combine_internal(shares: &[String], k: usize) -> Result<SecretKey, String> {
    if shares.len() < k { 
        return Err(format!("Not enough shares: got {}, need {}", shares.len(), k)); 
    }

    let mut a_matrix = Vec::new();
    let mut b_vectors = vec![Vec::new(); 4];

    for (idx, s) in shares.iter().take(k).enumerate() {
        let parts: Vec<&str> = s.split(':').collect();
        // Проверка: Коэффициенты (1 часть) + 4 значения d = 5 частей
        if parts.len() != 5 { 
            return Err(format!("Share {} has invalid format: expected 5 parts, got {}", idx, parts.len())); 
        }
        
        let coeffs: Vec<u128> = parts[0].split(',')
            .map(|c| u128::from_str_radix(c, 16).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        
        if coeffs.len() != k {
            return Err(format!("Share {} has invalid number of coefficients: expected {}, got {}", idx, k, coeffs.len()));
        }

        a_matrix.push(coeffs);
        for i in 0..4 {
            let d = u128::from_str_radix(parts[i+1], 16).map_err(|e| e.to_string())?;
            b_vectors[i].push(d);
        }
    }

    let mut final_key = [0u8; KEY_LEN];
    for i in 0..4 {
        let solution = solve_system(a_matrix.clone(), b_vectors[i].clone(), PRIME)?;
        // Координата x0 — это наш секретный чанк
        final_key[i*8..(i+1)*8].copy_from_slice(&(solution[0] as u64).to_be_bytes());
    }
    
    Ok(SecretKey(final_key))
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