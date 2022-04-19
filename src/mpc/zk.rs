use num::{integer::sqrt, BigInt};
use sha2::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::{
    mpc::{diag, encode, encrypt_det, Ciphertext, Parameters, PlayerState},
    poly::Polynomial,
    prob::{sample_from_uniform, sample_single},
    protocol::Facilitator,
};

const SEC: usize = 40;

// Supposed to be split into part for prover and part for verifier
pub fn zkpopk<F: Facilitator>(
    params: &Parameters,
    e_fi: Ciphertext,
    diagonal: bool,
    state: &PlayerState<F>,
) -> bool {
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
        let u_i = sample_from_uniform(&((y_i_bound.clone() / params.t.clone()) - 1), params.n)
            * params.t.clone();
        y.push(encoded_m_i + u_i);

        s.push((
            sample_from_uniform(&s_i_bound, params.n),
            sample_from_uniform(&s_i_bound, params.n),
            sample_from_uniform(&s_i_bound, params.n),
        ));

        a.push(encrypt_det(params, y[i].clone(), &state.pk, s[i].clone()))
    }

    // The prover sends a to the verifier.

    let mut hasher = Shake256::default();
    for ciphertext in a {
        for p in ciphertext {
            hasher.update(&polynomial_to_bytes(&p));
        }
    }
    for p in e_fi {
        hasher.update(&polynomial_to_bytes(&p));
    }
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; SEC / 8];
    reader.read(&mut output);

    todo!()
}

fn polynomial_to_bytes(p: &Polynomial) -> Vec<u8> {
    let json = serde_json::to_string(p).unwrap();
    json.as_bytes().to_owned()
}
