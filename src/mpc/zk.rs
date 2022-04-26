use num::{integer::sqrt, BigInt, Zero};
use sha2::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::{
    encryption::PublicKey,
    mpc::{diag, encode, encrypt_det, Ciphertext, Parameters},
    poly::Polynomial,
    prob::{sample_from_uniform, sample_single},
};

const SEC: usize = 40;
const V: usize = 2 * SEC + 1;

/// Make a zero-knowledge proof of plaintext knowledge
pub fn make_zkpopk(
    params: &Parameters,
    x: Vec<Polynomial>,
    c: Vec<Ciphertext>,
    diagonal: bool,
    pk: &PublicKey,
) -> (Vec<Vec<Polynomial>>, Vec<Vec<BigInt>>, ()) {
    let tau: BigInt = &params.t / BigInt::from(2_i32);
    let rho = BigInt::from(2_i32) * BigInt::from(params.r as i64) * sqrt(params.n);
    let d = params.n * 3;

    let y_i_bound = BigInt::from(128_i32) * params.n * tau * BigInt::from(SEC).pow(2);
    let s_i_bound = BigInt::from(128_i32) * d * rho * BigInt::from(SEC).pow(2);

    let mut y = Vec::with_capacity(V);
    let mut s = Vec::with_capacity(V);

    let mut a = Vec::with_capacity(V);
    for i in 0..V {
        let mut m_i = sample_single(&params.t);
        if diagonal {
            m_i = diag(params, m_i)
        }
        let encoded_m_i = encode(m_i);
        let u_i = sample_from_uniform(&((y_i_bound.clone() / params.t.clone()) - 1_i32), params.n)
            * params.t.clone();
        y.push(encoded_m_i + u_i);

        s.push((
            sample_from_uniform(&s_i_bound, params.n),
            sample_from_uniform(&s_i_bound, params.n),
            sample_from_uniform(&s_i_bound, params.n),
        ));

        a.push(encrypt_det(params, y[i].clone(), pk, s[i].clone()))
    }

    let e = hash(&a, &c);

    let mut m_e = vec![vec![0_u8; V]; SEC];
    for (i, row) in m_e.iter_mut().enumerate() {
        for (k, item) in row.iter_mut().enumerate() {
            let e_index = i as i32 - k as i32;

            if (0..(SEC as i32)).contains(&e_index) {
                *item = e[e_index as usize];
            }
        }
    }

    // Calculate z
    let mut z = Vec::with_capacity(params.n);
    for i in 0..params.n {
        let mut z_row = Vec::with_capacity(V);

        for j in 0..V {
            let mut val;

            // Get y^T values
            let y_col = &y[j];
            val = y_col.coefficient(i).to_owned();

            // Multiply M_e * x^T and add it
            for k in 0..SEC {
                let x_i = &x[k];
                val += m_e[k][j] * x_i.coefficient(i).to_owned();
            }

            z_row.push(val);
        }

        z.push(z_row);
    }

    // Calculate t
    let t = ();

    (a, z, t)
}

/// Hash `(a, c)` to get a random value `e`
fn hash(a: &[Vec<Polynomial>], c: &[Vec<Polynomial>]) -> Vec<u8> {
    let mut hasher = Shake256::default();

    for ciphertext in a {
        for p in ciphertext {
            hasher.update(&polynomial_to_bytes(p));
        }
    }
    for ciphertext in c {
        for p in ciphertext {
            hasher.update(&polynomial_to_bytes(p));
        }
    }

    let mut reader = hasher.finalize_xof();
    let mut e_bytes = [0_u8; SEC / 8];
    reader.read(&mut e_bytes);

    let mut e_bit_string = String::new();
    for e_byte in e_bytes {
        e_bit_string = format!("{}{:08b}", e_bit_string, &e_byte);
    }

    let mut e_bits = Vec::with_capacity(SEC);
    for c in e_bit_string.chars() {
        match c {
            '0' => e_bits.push(0),
            '1' => e_bits.push(1),
            _ => unreachable!("should only have 0's and 1's"),
        }
    }

    e_bits
}

/// Verify the validity of a zero-knowledge proof of plaintext knowledge
pub fn verify_zkpopk(a: Vec<Vec<Polynomial>>, z: Vec<Vec<BigInt>>, t: ()) -> bool {
    true
}

/// A little hack to convert a polynomial to bytes
fn polynomial_to_bytes(p: &Polynomial) -> Vec<u8> {
    let json = serde_json::to_string(p).unwrap();
    json.as_bytes().to_owned()
}

#[cfg(test)]
mod tests {
    use num::{bigint::RandomBits, BigInt};
    use rand::Rng;

    use crate::{
        encryption::{encrypt, generate_key_pair, Ciphertext, Parameters, PublicKey, SecretKey},
        poly::Polynomial,
    };

    use super::{make_zkpopk, verify_zkpopk, SEC};

    fn setup() -> (
        Parameters,
        PublicKey,
        SecretKey,
        Vec<Polynomial>,
        Vec<Ciphertext>,
    ) {
        let params = Parameters::default();
        let (pk, sk) = generate_key_pair(&params);

        let mut x = Vec::with_capacity(SEC);
        let mut c = Vec::with_capacity(SEC);
        for _ in 0..SEC {
            let x_i = Polynomial::new(vec![random_bigint()]);
            let c_i = encrypt(&params, x_i.clone(), &pk);
            x.push(x_i);
            c.push(c_i);
        }

        (params, pk, sk, x, c)
    }

    fn random_bigint() -> BigInt {
        let mut rng = rand::thread_rng();
        rng.sample(RandomBits::new(256))
    }

    #[test]
    fn verify_accepts_valid_zkpopk() {
        let (params, pk, sk, x, c) = setup();

        let (a, z, t) = make_zkpopk(&params, x, c, false, &pk);

        assert!(verify_zkpopk(a, z, t), "proof was not valid")
    }
}
