//! Preprocessing phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 5)

use crate::mpc::zk::zkpopk;
use crate::mpc::Angle;
use crate::{
    encryption::*,
    mpc::{ddec, diag, Player},
    poly::Polynomial,
    polynomial,
    prob::*,
};
use crate::{mpc::add_encrypted_shares, protocol::Facilicator};
use num::One;

use num::{BigInt, Zero};

pub enum Enc {
    NewCiphertext,
    NoNewCiphertext,
}

/// Represents the preprocessing protocol (fig. 7)
pub struct ProtocolPrep {}

impl ProtocolPrep {
    /// Implements the Initialize step
    pub fn initialize(params: &Parameters, facilitator: Facilicator) -> Vec<Player> {
        let amount_of_players = players.len();
        let mut new_players = vec![]; // distribute_keys(params, players.clone());

        let mut e_alpha_is = vec![vec![]; amount_of_players];

        // Each player does the contents of the loop
        for i in 0..amount_of_players {
            new_players[i].alpha_i = sample_single(&params.t);
            new_players[i].beta_i = sample_single(&params.t);

            e_alpha_is[i] = encrypt(
                params,
                encode(diag(params, new_players[i].alpha_i.clone())),
                &players[i].pk,
            );
        }

        let e_alpha = add_encrypted_shares(&params, e_alpha_is.clone(), amount_of_players);

        for i in 0..amount_of_players {
            new_players[i].e_alpha = e_alpha.clone();
        }

        // TODO: ZK proof faked for now
        let sec = 40; //sec hardcoded for now common values are 40, 80
        for i in 0..amount_of_players {
            for _ in 0..sec {
                if !zkpopk(new_players[i].e_alpha.clone()) {
                    panic!("ZK proof failed!")
                }
            }
        }

        new_players
    }

    /// Implements the Pair step
    pub fn pair(params: &Parameters, players: &Vec<Player>) -> (Vec<BigInt>, Angle) {
        let amount_of_players = players.len();

        let mut r_is = vec![BigInt::zero(); amount_of_players];
        for i in 0..amount_of_players {
            r_is[i] = sample_single(&params.t)
        }

        let mut e_r_is = vec![vec![]; amount_of_players];
        for i in 0..amount_of_players {
            e_r_is[i] = encrypt(params, encode(r_is[i].clone()), &players[0].pk)
        }

        let e_r = add_encrypted_shares(params, e_r_is.clone(), amount_of_players);

        // TODO: ZK proof faked for now
        for i in 0..amount_of_players {
            if !zkpopk(e_r_is[i].clone()) {
                panic!("ZK proof failed!")
            }
        }

        let r_angle = p_angle(params, r_is.clone(), e_r, players);
        (r_is, r_angle)
    }

    /// Implements the Triple step
    pub fn triple(params: &Parameters, players: &Vec<Player>) -> (Angle, Angle, Angle) {
        let amount_of_players = players.len();

        let mut a_is = vec![BigInt::zero(); amount_of_players];
        let mut b_is = vec![BigInt::zero(); amount_of_players];
        for i in 0..amount_of_players {
            a_is[i] = sample_single(&params.t);
            b_is[i] = sample_single(&params.t)
        }

        let mut e_a_is = vec![vec![]; amount_of_players];
        let mut e_b_is = vec![vec![]; amount_of_players];

        for i in 0..amount_of_players {
            e_a_is[i] = encrypt(params, encode(a_is[i].clone()), &players[0].pk);
            e_b_is[i] = encrypt(params, encode(b_is[i].clone()), &players[0].pk)
        }

        // TODO: ZK proof faked for now
        for i in 0..amount_of_players {
            if !zkpopk(e_a_is[i].clone()) {
                panic!("ZK proof failed!")
            }
            if !zkpopk(e_b_is[i].clone()) {
                panic!("ZK proof failed!")
            }
        }

        let e_a = add_encrypted_shares(params, e_a_is, amount_of_players);
        let e_b = add_encrypted_shares(params, e_b_is, amount_of_players);

        let a_angle = p_angle(params, a_is, e_a.clone(), players);
        let b_angle = p_angle(params, b_is, e_b.clone(), players);
        let e_c = mul(params, &e_a, &e_b);

        let (e_c_prime_opt, reshared) = reshare(params, &e_c, players, Enc::NewCiphertext);
        let e_c_prime: Ciphertext = e_c_prime_opt.unwrap();

        let c_angle = p_angle(params, reshared, e_c_prime, players);

        (a_angle, b_angle, c_angle)
    }
}

/// Implements Protocol Reshare (fig. 4)
pub fn reshare(
    params: &Parameters,
    e_m: &Ciphertext,
    players: &Vec<Player>,
    enc: Enc,
) -> (Option<Ciphertext>, Vec<BigInt>) {
    let amount_of_players = players.len();

    // Each player samples vec from M (this is just from Rt for now)
    let mut f_is = vec![BigInt::zero(); amount_of_players];
    for i in 0..amount_of_players {
        f_is[i] = sample_single(&params.t)
    }

    // e_f_is[i] supposed to be computed by P_i and broadcast
    let mut e_f_is = vec![vec![]; amount_of_players];
    for i in 0..amount_of_players {
        e_f_is[i] = encrypt(params, encode(f_is[i].clone()), &players[i].pk)
    }

    // ZK proof faked for now
    for i in 0..amount_of_players {
        if !zkpopk(e_f_is[i].clone()) {
            panic!("ZK proof failed!")
        }
    }

    // This is done by each player
    let e_f = add_encrypted_shares(params, e_f_is.clone(), amount_of_players);
    let e_m_plus_f = add(params, e_m, &e_f);

    // Done by each player
    let m_plus_f = ddec(params, players, e_m_plus_f);

    // m_i computed by P_i
    let mut m_is = vec![BigInt::zero(); amount_of_players];
    m_is[0] = (m_plus_f.clone() - f_is[0].clone()).modpow(&BigInt::one(), &params.t);
    for i in 1..amount_of_players {
        m_is[i] = (-f_is[i].clone()).modpow(&BigInt::one(), &params.t)
    }

    if matches!(enc, Enc::NewCiphertext) {
        let mut e_m_prime = encrypt_det(
            params,
            encode(m_plus_f),
            &players[0].pk,
            (polynomial![1], polynomial![1], polynomial![1]),
        ); //Hvilket randomness???
        for i in 0..amount_of_players {
            e_m_prime = add(
                params,
                &e_m_prime,
                &(e_f_is[i].iter().map(|e| -(e.clone())).collect()),
            );
        }
        return (Some(e_m_prime), m_is);
    }

    // Player P_i is supposed to get m_is[i]
    (None, m_is)
}

/// Implements Protocol PAngle (fig. 6)
pub fn p_angle(
    params: &Parameters,
    v_is: Vec<BigInt>,
    e_v: Ciphertext,
    players: &Vec<Player>,
) -> Angle {
    // Each player does the following:
    let e_v_mul_alpha = mul(&params, &e_v, &players[0].e_alpha);
    let (_, gamma_is) = reshare(params, &e_v_mul_alpha, players, Enc::NoNewCiphertext); // each player Pi gets a share γi of α·v
    let v_angle = [v_is.as_slice(), gamma_is.as_slice()].concat();
    v_angle
}

#[cfg(test)]
mod tests {
    use crate::{encryption::secure_params, mpc::prep::*, mpc::*};

    #[test]
    fn test_mult_triple() {
        let amount_of_players = 3;
        let players = vec![Player::new(); amount_of_players];
        let params = secure_params();

        let initialized_players = ProtocolPrep::initialize(&params, &players);
        let (a_angle, b_angle, c_angle) = ProtocolPrep::triple(&params, &initialized_players);

        let mut a = BigInt::zero();
        let mut b = BigInt::zero();
        let mut c = BigInt::zero();
        for i in 0..amount_of_players {
            a = a + a_angle[i].clone();
            b = b + b_angle[i].clone();
            c = c + c_angle[i].clone()
        }

        assert_eq!(
            (a * b).modpow(&BigInt::one(), &params.t),
            c.modpow(&BigInt::one(), &params.t)
        )
    }

    #[test]
    fn test_reshare() {
        let amount_of_players = 3;
        let players = vec![Player::new(); amount_of_players];
        let params = secure_params();

        let initialized_players = ProtocolPrep::initialize(&params, &players);

        let mut r_is = vec![BigInt::zero(); amount_of_players];
        for i in 0..amount_of_players {
            r_is[i] = sample_single(&params.t)
        }
        let mut e_r_is = vec![vec![]; amount_of_players];
        for i in 0..amount_of_players {
            e_r_is[i] = encrypt(&params, encode(r_is[i].clone()), &initialized_players[0].pk)
        }
        let e_r = add_encrypted_shares(&params, e_r_is.clone(), amount_of_players);
        let (_, reshared) = reshare(&params, &e_r, &initialized_players, Enc::NoNewCiphertext);

        let r = open_shares(&params, r_is, amount_of_players);
        let reshared_opened = open_shares(&params, reshared, amount_of_players);

        assert_eq!(r, reshared_opened)
    }

    #[test]
    fn test_angle_mac() {
        let amount_of_players = 3;
        let players = vec![Player::new(); amount_of_players];
        let params = secure_params();
        let initialized_players = ProtocolPrep::initialize(&params, &players);
        let (_, angle) = ProtocolPrep::pair(&params, &initialized_players);
        let mut sigma = BigInt::zero();
        for i in 0..amount_of_players {
            sigma =
                (sigma + angle[amount_of_players + i].clone()).modpow(&BigInt::one(), &params.t);
        }
        let a = open_shares(&params, angle, amount_of_players);
        let mut alpha_is = vec![BigInt::zero(); amount_of_players];
        for i in 0..amount_of_players {
            alpha_is[i] = initialized_players[i].alpha_i.clone();
        }
        let alpha = open_shares(&params, alpha_is, amount_of_players);
        let res = (alpha * a).modpow(&BigInt::one(), &params.t);
        assert_eq!(res, sigma)
    }
}
