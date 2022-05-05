use rug::Integer;

use crate::{
    poly::Polynomial,
    polynomial,
    prob::{sample_from_gaussian, sample_from_uniform},
    quotient_ring::*,
};

use std::{cmp, str::FromStr};

pub type SecretKey = Polynomial;
pub type PublicKey = (Polynomial, Polynomial);
pub type Ciphertext = Vec<Polynomial>;

pub struct Parameters {
    pub quotient_ring: Rq,
    pub t: Integer,
    pub r: f64,
    pub r_prime: f64,
    pub n: usize,
}

impl Parameters {
    pub fn new<Int>(q: Int, r: f64, r_prime: f64, n: usize, t: Int) -> Parameters
    where
        Int: Into<Integer>,
    {
        let q = q.into();
        let t = t.into();

        let mut fx_vec = vec![Integer::new(); n + 1];
        fx_vec[0] = Integer::from(1);
        fx_vec[n] = Integer::from(1);
        let fx = Polynomial::from(fx_vec);
        let quotient_ring = Rq::new(q, fx);

        Parameters {
            quotient_ring,
            r,
            r_prime,
            n,
            t,
        }
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters::new(65537, 1.0, 2.0, 4, 7)
    }
}

// Loosely based on http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
// security level (quantum): 128 bits
// q: 27 bit prime, ex. 80708963
// n: 1024
// t: 2
// r: 2 = w * sqrt(log2(1024)) = 0.632 * 3.162
// r_prime: 80 >= 2^(0.632 * log2(1024)) = 2^(0.632 * 10)
pub fn secure_params() -> Parameters {
    let c = Integer::from_str("7491009436045135886698181243708504421607358929720206973094758479498049015628852031735169966277519969").unwrap();
    let t2 = Integer::from_str("127").unwrap();
    Parameters::new(c, 3.2, 100.0, 7, t2)
}

pub fn mpc_secure_params() -> Parameters {
    // q not accurate, still should reflect real performance
    Parameters::new(80708963, 2.0, 80.0, 12900, 127)
}

pub fn encrypt_det(
    params: &Parameters,
    m: Polynomial,
    pk: &PublicKey,
    r: (Polynomial, Polynomial, Polynomial),
) -> Ciphertext {
    let rq = &params.quotient_ring;

    let (a0, b0) = pk;
    let (v, e_prime, e_prime_prime) = r;

    let a0_mul_v = rq.mul(a0, &v);
    let t_mul_e_prime = rq.times(&e_prime, &params.t);
    let a = rq.add(&a0_mul_v, &t_mul_e_prime);

    let b0_mul_v = rq.mul(b0, &v);
    let t_mul_e_prime_prime = rq.times(&e_prime_prime, &params.t);
    let b = rq.add(&b0_mul_v, &t_mul_e_prime_prime);

    let c0 = rq.add(&b, &m);
    let c1 = rq.neg(&a);
    vec![c0, c1]
}

pub fn encrypt(params: &Parameters, m: Polynomial, pk: &PublicKey) -> Ciphertext {
    let v = sample_from_gaussian(params.r, params.n);
    let e_prime = sample_from_gaussian(params.r, params.n);
    let e_prime_prime = sample_from_gaussian(params.r_prime, params.n);

    encrypt_det(params, m, pk, (v, e_prime, e_prime_prime))
}

#[derive(Debug)]
pub enum DecryptionError {
    LInfNormTooBig(Integer),
}

pub fn decrypt(
    params: &Parameters,
    c: Ciphertext,
    sk: &Polynomial,
) -> Result<Polynomial, DecryptionError> {
    let rq = &params.quotient_ring;

    // Construct secret key vector
    let mut sk_vec: Vec<Polynomial> = vec![];
    let mut cur_vec_entry = polynomial![1_i32];
    sk_vec.push(cur_vec_entry.clone());

    for _ in 1..c.len() {
        cur_vec_entry = rq.mul(&cur_vec_entry, sk);
        sk_vec.push(cur_vec_entry.clone());
    }

    // Compute plaintext using ciphertext and sk vector
    let mut msg = polynomial![0];

    for i in 0..c.len() {
        let ci_mul_sk_veci = rq.mul(&c[i], &sk_vec[i]);
        msg = rq.add(&msg, &ci_mul_sk_veci);
    }

    let msg_minus_q = msg.normalized_coefficients(&rq.q);

    let q_half: Integer = (&rq.q / 2_i32).into();
    if msg_minus_q.l_inf_norm() >= q_half {
        return Err(DecryptionError::LInfNormTooBig(msg_minus_q.l_inf_norm()));
    }

    // Reduce polynomial modulo the coefficients
    Ok(msg_minus_q.modulo(&params.t))
}

pub fn generate_key_pair(params: &Parameters) -> (PublicKey, SecretKey) {
    let rq = &params.quotient_ring;

    let sk = sample_from_gaussian(params.r, params.n);
    let a0 = sample_from_uniform(&rq.q, params.n);
    let e0 = sample_from_gaussian(params.r, params.n);

    let elem1 = rq.mul(&a0, &sk);
    let elem2 = rq.times(&e0, &params.t);
    let pk = (a0, rq.add(&elem1, &elem2));

    (pk, sk)
}

pub fn add(params: &Parameters, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    let rq = &params.quotient_ring;

    let max = cmp::max(c1.len(), c2.len());
    let mut res = vec![polynomial![0]; max];

    for i in 0..c1.len() {
        res[i] = rq.add(&res[i], &c1[i]);
    }
    for i in 0..c2.len() {
        res[i] = rq.add(&res[i], &c2[i]);
    }

    res
}

pub fn mul(params: &Parameters, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    let rq = &params.quotient_ring;

    let mut res = vec![polynomial![0]; c1.len() + c2.len() - 1];

    for i in 0..c1.len() {
        for j in 0..c2.len() {
            let c1i_mul_c2i = rq.mul(&c1[i], &c2[j]);
            res[i + j] = rq.add(&res[i + j], &c1i_mul_c2i);
        }
    }

    res
}

// Drowns noise by adding an encryption of 0 with a large amount of noise
pub fn drown_noise(
    params: &Parameters,
    params_noisy: &Parameters,
    c: Ciphertext,
    pk: PublicKey,
) -> Ciphertext {
    let zero = polynomial![0];
    let noisy_zero = encrypt(params_noisy, zero, &pk);
    add(params, &c, &noisy_zero)
}

pub fn encode(coef: Integer) -> Polynomial {
    let coefficients = vec![coef];
    Polynomial::new(coefficients)
}

pub fn decode(pol: Polynomial) -> Integer {
    pol.coefficient(0).clone()
}
