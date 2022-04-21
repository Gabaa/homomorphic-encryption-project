use rug::{ops::RemRounding, Integer};

use crate::{encryption::*, polynomial, protocol::KeyMaterial};
use crate::{poly::*, protocol::Facilicator};
use crate::{prob::sample_from_uniform, protocol::OnlineMessage};

pub mod commitment;
pub mod online;
pub mod prep;
pub mod zk;

pub type Angle = Vec<Integer>;
pub type AngleShare = (Integer, Integer);
pub type MulTriple = (AngleShare, AngleShare, AngleShare);

#[derive(Clone, Debug)]
pub struct PlayerState<F: Facilicator> {
    sk_i1: Polynomial, // Additive shares of sk
    sk_i2: Polynomial, // Additive shares of sk^2
    pk: PublicKey,
    alpha_i: Integer,    // global key share
    e_alpha: Ciphertext, // Encrypted global key
    opened: Vec<(Integer, Integer)>,
    pub facilitator: F,
}

impl<F: Facilicator> PlayerState<F> {
    pub fn new(facilitator: F, key_material: KeyMaterial) -> Self {
        Self {
            sk_i1: key_material.sk_i1,
            sk_i2: key_material.sk_i2,
            pk: key_material.pk,
            alpha_i: Integer::ZERO,
            e_alpha: vec![],
            opened: vec![],
            facilitator,
        }
    }

    pub fn stop(self) {
        self.facilitator.stop()
    }
}

/// Function for "dec" functionality in Fkey_gen_dec figure 3 of the MPC article.
pub fn ddec<F: Facilicator>(
    params: &Parameters,
    state: &PlayerState<F>,
    mut c: Ciphertext,
) -> Integer {
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
    let norm_bound = Integer::from(2) ^ Integer::from(32);
    let t_i = rq.add(
        &v_i,
        &rq.times(&sample_from_uniform(&norm_bound, params.n), &params.t), // norm_bound is placeholder, since q needs to be a lot higher for this to work properly
    );

    // Assume public decryption
    let msg = OnlineMessage::SharePoly(t_i);
    state.facilitator.broadcast(&msg);

    let mut t_shares = Vec::with_capacity(state.facilitator.player_count());
    let messages = state
        .facilitator
        .receive_many(state.facilitator.player_count());
    for (_, msg) in messages {
        if let OnlineMessage::SharePoly(t_j) = msg {
            t_shares.push(t_j);
        }
    }

    let t_prime = t_shares
        .iter()
        .fold(polynomial![0], |acc, elem| rq.add(&acc, elem));

    let msg_minus_q = t_prime.normalized_coefficients(&rq.q);

    decode(msg_minus_q.modulo(&params.t))
}

pub fn open_shares(params: &Parameters, shares: Vec<Integer>) -> Integer {
    let mut r = Integer::ZERO;
    for share in &shares {
        r = (r + share).rem_euc(&params.t);
    }
    r
}

pub fn add_encrypted_shares(params: &Parameters, enc_shares: Vec<Ciphertext>) -> Ciphertext {
    let mut res = vec![polynomial![0]];
    for enc_share in &enc_shares {
        res = add(params, &res, enc_share)
    }
    res
}

pub fn diag(_params: &Parameters, a: Integer) -> Integer {
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
