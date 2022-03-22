use num::BigInt;
use num::One;
use num::Zero;

use crate::{encryption::*, polynomial};
use crate::{poly::*, protocol::Facilicator};
use crate::{prob::sample_from_uniform, protocol::OnlineMessage};

mod commitment;
mod online;
mod prep;
mod zk;

pub type Angle = Vec<BigInt>;
pub type AngleShare = (BigInt, BigInt);
pub type MulTriple = (Angle, Angle, Angle);

#[derive(Clone, Debug)]
pub struct PlayerState<F: Facilicator> {
    sk_i1: Polynomial, // Additive shares of sk
    sk_i2: Polynomial, // Additive shares of sk^2
    pk: PublicKey,
    alpha_i: BigInt,     // global key share
    e_alpha: Ciphertext, // Encrypted global key
    opened: Vec<Angle>,
    facilitator: F,
}

impl<F: Facilicator> PlayerState<F> {
    pub fn new(facilitator: F) -> Self {
        Self {
            sk_i1: polynomial![0],
            sk_i2: polynomial![0],
            pk: (polynomial![0], polynomial![0]),
            alpha_i: BigInt::zero(),
            e_alpha: vec![],
            opened: vec![],
            facilitator,
        }
    }
}

/// Function for "dec" functionality in Fkey_gen_dec figure 3 of the MPC article.
pub fn ddec<F: Facilicator>(
    params: &Parameters,
    state: PlayerState<F>,
    mut c: Ciphertext,
) -> BigInt {
    let rq = &params.quotient_ring;

    // Need to ensure that there are 3 elements (there can never be < 2)
    if c.len() == 2 {
        c.push(polynomial![0])
    }

    let si1_ci1 = rq.mul(&state.sk_i1, &c[1]);
    let si2_ci2 = rq.mul(&state.sk_i2, &c[2]);
    let sum = rq.add(&si1_ci1, &si2_ci2);

    let v_i = if state.facilitator.player_number() == 0 {
        rq.add(&c[0], &sum)
    } else {
        sum
    };

    //Random element does not currently have a bounded l_inf norm
    let norm_bound: BigInt = BigInt::from(2_i32) ^ &BigInt::from(32_i32);
    let t_i = rq.add(
        &v_i,
        &rq.times(&sample_from_uniform(&norm_bound, params.n), &params.t), // norm_bound is placeholder, since q needs to be a lot higher for this to work properly
    );

    // Assume public decryption
    let msg = OnlineMessage::SharePoly(t_i);
    state.facilitator.broadcast(&msg);

    let t_shares: Vec<Polynomial> = state
        .facilitator
        .receive_many(state.facilitator.player_count())
        .iter()
        .map(|(_, msg)| {
            if let OnlineMessage::SharePoly(t_j) = msg {
                t_j
            } else {
                panic!("Expected a share of a polynomial")
            }
        })
        .collect();

    let t_prime = t_shares
        .iter()
        .fold(polynomial![0], |acc, elem| rq.add(&acc, elem));

    // Compute msg minus q if x > q/2
    let msg_minus_q = Polynomial::from(
        t_prime
            .coefficients()
            .map(|x| {
                if x > &(&rq.q / 2_i32) {
                    x - &rq.q
                } else {
                    x.to_owned()
                }
            })
            .collect::<Vec<BigInt>>(),
    )
    .trim_res();

    decode(msg_minus_q.modulo(&params.t))
}

pub fn open_shares(params: &Parameters, repr: Vec<BigInt>, amount_of_players: usize) -> BigInt {
    let mut r = BigInt::zero();
    let shares = repr
        .iter()
        .take(amount_of_players)
        .cloned()
        .collect::<Vec<BigInt>>();
    for i in 0..shares.len() {
        r = (r + shares[i].clone()).modpow(&BigInt::one(), &params.t);
    }
    r
}

pub fn add_encrypted_shares(
    params: &Parameters,
    enc_shares: Vec<Ciphertext>,
    amount_of_players: usize,
) -> Ciphertext {
    let mut res = vec![polynomial![0]];
    for i in 0..amount_of_players {
        res = add(params, &res, &enc_shares[i])
    }
    res
}

pub fn diag(params: &Parameters, a: BigInt) -> BigInt {
    //vec![a; params.n]
    a
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distributed_decryption_works() {
        let mut player_array = vec![Player::new(); 5];
        let params = secure_params();
        player_array = distribute_keys(&params, player_array);

        let pk = player_array[0].pk.clone();

        let msg = polynomial![0];
        let cipher = encrypt(&params, msg, &pk);
        let decrypted = ddec(&params, &player_array, cipher);

        assert_eq!(decrypted, decode(polynomial![0]));

        let msg2 = polynomial![5, 7, 3];
        let cipher2 = encrypt(&params, msg2, &pk);
        let decrypted2 = ddec(&params, &player_array, cipher2);

        assert_eq!(decrypted2, decode(polynomial![5, 7, 3]));
    }
}
*/
