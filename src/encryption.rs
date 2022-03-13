use crate::{
    poly::Polynomial,
    prob::{sample_from_gaussian, sample_from_uniform},
    quotient_ring::*,
};

use std::cmp;

pub type SecretKey = Polynomial;
pub type PublicKey = (Polynomial, Polynomial);
pub type Ciphertext = Vec<Polynomial>;

pub struct Parameters {
    pub quotient_ring: Rq,
    pub t: i128,
    pub r: f64,
    pub r_prime: f64,
    pub n: usize,
    pub q: i128,
}

impl Parameters {
    pub fn new(q: i128, r: f64, r_prime: f64, n: usize, t: i128) -> Parameters {
        let mut fx_vec = vec![0; n + 1];
        fx_vec[0] = 1;
        fx_vec[n] = 1;
        let fx = Polynomial(fx_vec);
        let quotient_ring = Rq::new(q, fx);
        return Parameters {
            quotient_ring,
            r,
            r_prime,
            n,
            q,
            t,
        };
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters::new(65537, 1.0, 2.0, 4, 7)
    }
}

pub fn encrypt(params: &Parameters, m: Polynomial, pk: &PublicKey) -> Ciphertext {
    debug_assert!(m.0.iter().all(|&c| c < params.t));

    let rq = &params.quotient_ring;

    let (a0, b0) = pk;

    let v = sample_from_gaussian(params.r, params.n);
    let e_prime = sample_from_gaussian(params.r, params.n);
    let e_prime_prime = sample_from_gaussian(params.r_prime, params.n);

    let a0_mul_v = rq.mul(&a0, &v);
    let t_mul_e_prime = rq.times(&e_prime, params.t);
    let a = rq.add(&a0_mul_v, &t_mul_e_prime);

    let b0_mul_v = rq.mul(&b0, &v);
    let t_mul_e_prime_prime = rq.times(&e_prime_prime, params.t);
    let b = rq.add(&b0_mul_v, &t_mul_e_prime_prime);

    let c0 = rq.add(&b, &m);
    let c1 = rq.neg(&a);
    vec![c0, c1]
}

#[derive(Debug)]
pub enum DecryptionError {
    LInfNormTooBig(i128),
}

pub fn decrypt(
    params: &Parameters,
    c: Ciphertext,
    sk: &Polynomial
) -> Result<Polynomial, DecryptionError> {
    let rq = &params.quotient_ring;

    // Construct secret key vector
    let mut sk_vec: Vec<Polynomial> = vec![];
    let mut cur_vec_entry: Polynomial = Polynomial(vec![1]);
    sk_vec.push(cur_vec_entry.clone());

    for _ in 1..c.len() {
        cur_vec_entry = rq.mul(&cur_vec_entry, &sk);
        sk_vec.push(cur_vec_entry.clone());
    }

    // Compute plaintext using ciphertext and sk vector
    let mut msg = Polynomial(vec![0]);

    for i in 0..c.len() {
        let ci_mul_sk_veci = rq.mul(&c[i], &sk_vec[i]);
        msg = rq.add(&msg, &ci_mul_sk_veci);
    }

    // Compute msg minus q if x > q/2
    let msg_minus_q = Polynomial(
        msg.0
            .iter()
            .map(|x| {
                if x > &(params.q / 2) {
                    x - params.q
                } else {
                    *x
                }
            })
            .collect(),
    )
    .trim_res();

    println!("{:?}", msg_minus_q.l_inf_norm());
    if msg_minus_q.l_inf_norm() >= params.q / 2 {
        return Err(DecryptionError::LInfNormTooBig(msg_minus_q.l_inf_norm()));
    }

    // Reduce polynomial modulo the coefficients
    Ok(msg_minus_q % params.t)
}

pub fn generate_key_pair(params: &Parameters) -> (PublicKey, SecretKey) {
    let rq = &params.quotient_ring;

    let sk = sample_from_gaussian(params.r, params.n);
    let a0 = sample_from_uniform(params.q, params.n);
    let e0 = sample_from_gaussian(params.r, params.n);

    let elem1 = rq.mul(&a0, &sk);
    let elem2 = rq.times(&e0, params.t);
    let pk = (a0, rq.add(&elem1, &elem2));

    (pk, sk)
}

pub fn add(params: &Parameters, c1: Ciphertext, c2: Ciphertext) -> Ciphertext {
    let rq = &params.quotient_ring;

    let max = cmp::max(c1.len(), c2.len());
    let mut res = vec![Polynomial(vec![0]); max];

    for i in 0..c1.len() {
        res[i] = rq.add(&res[i], &c1[i]);
    }
    for i in 0..c2.len() {
        res[i] = rq.add(&res[i], &c2[i]);
    }

    res
}

pub fn mul(params: &Parameters, c1: Ciphertext, c2: Ciphertext) -> Ciphertext {
    let rq = &params.quotient_ring;

    let mut res = vec![Polynomial(vec![0]); c1.len() + c2.len() - 1];

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
    pk: PublicKey) -> Ciphertext {
    let zero = Polynomial(vec![0]);
    let noisy_zero = encrypt(&params_noisy, zero, &pk);
    println!("Noisy zero: {:?}", noisy_zero);
    add(params, c, noisy_zero)
}
