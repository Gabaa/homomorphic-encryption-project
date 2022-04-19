use sha3::Shake256;
use crate::mpc::PlayerState;
use crate::mpc::PublicKey;
use crate::mpc::encrypt_det;
use crate::mpc::encode;
use crate::mpc::encrypt;
use crate::mpc::Ciphertext;
use crate::protocol::Facilitator;
use crate::mpc::{diag, Parameters};
use crate::prob::sample_from_uniform;
use crate::prob::sample_single;
use num::integer::sqrt;
use num::BigInt;
use num::One;

// Supposed to be split into part for prover and part for verifier
pub fn zkpopk<F: Facilitator>(params: &Parameters, e_fi: Ciphertext, sec: usize, diagonal: bool, state: &PlayerState<F>) -> bool {
    let v = 2 * sec - 1;
    let tau: BigInt = &params.t / BigInt::from(2_i32);
    let rho = BigInt::from(2_i32) * BigInt::from(params.r as i64) * sqrt(params.n);
    let d = params.n * 3;

    let y_i_bound = BigInt::from(128_i32) * params.n * tau * BigInt::from(sec).pow(2);
    let s_i_bound = BigInt::from(128_i32) * d * rho * BigInt::from(sec).pow(2);

    let mut y = Vec::with_capacity(v);
    let mut s = Vec::with_capacity(v);

    let mut a = Vec::with_capacity(v);
    for i in 0..v {
        let mut m_i = sample_single(&params.t);
        if diagonal {
            m_i = diag(params, m_i)
        }
        let encoded_m_i = encode(m_i);
        let u_i = sample_from_uniform(&((y_i_bound.clone() / params.t.clone()) - 1), params.n) * params.t.clone();
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
    /* hasher.update(a[0]);
    hasher.update(e_fi[0]); */


    todo!()
}
