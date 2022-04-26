use num::{integer::sqrt, BigInt};
use sha2::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::{
    encryption::PublicKey,
    mpc::{diag, encode, encrypt_det, Ciphertext, Parameters},
    poly::Polynomial,
    prob::{sample_from_uniform, sample_single},
};

const SEC: usize = 40;

// Supposed to be split into part for prover and part for verifier
pub fn make_zkpopk(
    params: &Parameters,
    x: Polynomial,
    c: Ciphertext,
    diagonal: bool,
    pk: &PublicKey,
) -> (Vec<Vec<Polynomial>>, (), ()) {
    let v = 2 * SEC - 1;
    let tau: BigInt = &params.t / BigInt::from(2_i32);
    let rho = BigInt::from(2_i32) * BigInt::from(params.r as i64) * sqrt(params.n);
    let d = params.n * 3;

    let y_i_bound = BigInt::from(128_i32) * params.n * tau * BigInt::from(SEC).pow(2);
    let s_i_bound = BigInt::from(128_i32) * d * rho * BigInt::from(SEC).pow(2);

    let mut y = Vec::with_capacity(v);
    let mut s = Vec::with_capacity(v);

    let mut a = Vec::with_capacity(v);
    for i in 0..v {
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

    // The prover sends a to the verifier.

    let mut hasher = Shake256::default();
    for ciphertext in &a {
        for p in ciphertext {
            hasher.update(&polynomial_to_bytes(p));
        }
    }
    for p in c {
        hasher.update(&polynomial_to_bytes(&p));
    }
    let mut reader = hasher.finalize_xof();
    let mut e_bytes = [0_u8; SEC / 8];
    reader.read(&mut e_bytes);

    let mut e_bit_string = String::new();
    for e_byte in e_bytes {
        e_bit_string = format!("{}{:08b}", e_bit_string, &e_byte);
    }

    let mut e_bits: Vec<u8> = Vec::new();
    for c in e_bit_string.chars() {
        match c {
            '0' => e_bits.push(0),
            '1' => e_bits.push(1),
            _ => unreachable!("should only have 0's and 1's"),
        }
    }

    let mut m_e = vec![vec![0_u8; v]; SEC];
    for (i, row) in m_e.iter_mut().enumerate() {
        for (k, item) in row.iter_mut().enumerate() {
            let e_index = i as i32 - k as i32;

            if (0..(SEC as i32)).contains(&e_index) {
                let e_index = e_index as usize;
                *item = e_bits[e_index];
            }
        }
    }

    let mut z = y.clone();

    let t = ();

    (a, z, t)
}

pub fn verify_zkpopk(a: Vec<Vec<Polynomial>>, z: (), t: ()) -> bool {
    true
}

fn polynomial_to_bytes(p: &Polynomial) -> Vec<u8> {
    let json = serde_json::to_string(p).unwrap();
    json.as_bytes().to_owned()
}

#[cfg(test)]
mod tests {
    use num::{bigint::RandomBits, BigInt};
    use rand::Rng;

    use crate::{
        encryption::{encrypt, generate_key_pair, Parameters, PublicKey, SecretKey},
        poly::Polynomial,
    };

    use super::{make_zkpopk, verify_zkpopk};

    fn setup() -> (Parameters, PublicKey, SecretKey, Vec<Polynomial>) {
        let params = Parameters::default();
        let (pk, sk) = generate_key_pair(&params);

        let m = Polynomial::new(vec![random_bigint()]);
        let c = encrypt(&params, m, &pk);

        (params, pk, sk, c)
    }

    fn random_bigint() -> BigInt {
        let mut rng = rand::thread_rng();
        rng.sample(RandomBits::new(256))
    }

    #[test]
    fn verify_accepts_valid_zkpopk() {
        let (params, pk, sk, c) = setup();

        let (a, z, t) = make_zkpopk(&params, c, false, &pk);

        assert!(verify_zkpopk(a, z, t), "proof was not valid")
    }
}
