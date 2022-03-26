//! Preprocessing phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 5)

use crate::{encryption::*, mpc::{Player, ddec, distribute_keys, diag}, prob::*, polynomial, poly::Polynomial};

use num::{BigInt, Zero};

pub enum Enc {
    NewCiphertext,
    NoNewCiphertext,
}

/// Represents the preprocessing protocol (fig. 7)
pub struct ProtocolPrep {}

impl ProtocolPrep {
    /// Implements the Initialize step
    pub fn initialize(params: &Parameters, players: &Vec<Player>) -> (Vec<Player>, Vec<Polynomial>) {
        let amount_of_players = players.len();
        let new_players = distribute_keys(params, players.clone());

        let mut alpha_is = vec![BigInt::zero(); amount_of_players];

        let mut e_alpha_is = vec![vec![]; amount_of_players];
        let mut e_beta_is = vec![vec![]; amount_of_players];

        // Each player does the cocntents of the loop
        for i in 0..amount_of_players {
            alpha_is[i] = sample_single(&params.t);
            let beta_i = sample_single(&params.t);

            e_alpha_is[i] = encrypt(params, diag(params, alpha_is[i].clone()), &players[i].pk);
            e_beta_is[i] = encrypt(params, diag(params, beta_i), &players[i].pk)
        }

        let mut e_alpha = vec![polynomial![0]];
        for i in 0..amount_of_players {
            e_alpha = add(params, &e_alpha, &e_alpha_is[i])
        }

        let diag_alpha_is = alpha_is.iter().map(|a| diag(params, a.clone())).collect();
        let diag_alpha_share = p_bracket(params, diag_alpha_is, e_alpha, &new_players);

        (new_players, diag_alpha_share)

    }

    /// Implements the Pair step
    pub fn pair(params: &Parameters, players: &Vec<Player>) -> (Vec<Polynomial>, Vec<Polynomial>) {
        let amount_of_players = players.len();
        
        let r_is = vec![sample_from_uniform(&params.t, params.n); amount_of_players];

        let mut e_r = vec![polynomial![0]];
        for i in 0..amount_of_players {
            e_r = add(params, &e_r, &encrypt(params, r_is[i].clone(), &players[0].pk))
        }
        let r_bracket = p_bracket(params, r_is.clone(), e_r.clone(), players);
        let r_angle = p_angle(params, r_is, e_r, players);
        (r_bracket, r_angle)
    }

    /// Implements the Triple step
    pub fn triple(params: &Parameters, players: &Vec<Player>) -> (Vec<Polynomial>, Vec<Polynomial>, Vec<Polynomial>) {
        let amount_of_players = players.len();
        
        let a_is = vec![sample_from_uniform(&params.t, params.n); amount_of_players];
        let b_is = vec![sample_from_uniform(&params.t, params.n); amount_of_players];

        let mut e_a = vec![polynomial![0]];
        let mut e_b = vec![polynomial![0]];
        for i in 0..amount_of_players {
            e_a = add(params, &e_a, &encrypt(params, a_is[i].clone(), &players[0].pk));
            e_b = add(params, &e_b, &encrypt(params, b_is[i].clone(), &players[0].pk))
        }

        let a_angle = p_angle(params, a_is, e_a.clone(), players);
        let b_angle = p_angle(params, b_is, e_b.clone(), players);
        let e_c = mul(params, &e_a, &e_b);

        let (e_c_prime_opt, reshared) = reshare(params, &e_c, players, Enc::NewCiphertext);
        let e_c_prime: Ciphertext;
        match e_c_prime_opt {
            Some(enc) => e_c_prime = enc,
            None => todo!()
        }

        let c_angle = p_angle(params, reshared, e_c_prime, players);

        (a_angle, b_angle, c_angle)
    }
}

/// Implements Protocol Reshare (fig. 4)
pub fn reshare(params: &Parameters, e_m: &Ciphertext, players: &Vec<Player>, enc: Enc) -> (Option<Ciphertext>, Vec<Polynomial>) {
    let rq = &params.quotient_ring;
    let amount_of_players = players.len();

    // Each player samples vec from M (this is just from Rt for now)
    let f_is = vec![sample_from_uniform(&rq.q, params.n); amount_of_players];

    // e_f_is[i] supposed to be computed by P_i and broadcast
    let mut e_f_is = vec![vec![polynomial![0]]; amount_of_players];
    for i in 0..amount_of_players {
        e_f_is[i] = encrypt(params, f_is[i].clone(), &players[i].pk)
    }

    // This is done by each player
    let mut e_f = vec![polynomial![0]];
    for i in 0..amount_of_players {
        e_f = add(params, &e_f, &e_f_is[i])
    }
    let e_m_plus_f = add(params, e_m, &e_f);

    // TODO: No ZK proof (only passive sec. for now)

    // Done by each player
    let m_plus_f = ddec(params, players, e_m_plus_f);

    // m_i computed by P_i
    let mut m_is = vec![polynomial![0]; amount_of_players];
    m_is[0] = m_plus_f.clone() + -f_is[0].clone();
    for i in 1..amount_of_players {
        m_is[i] = -f_is[i].clone()
    }

    if matches!(enc, Enc::NewCiphertext) {
        let e_m_plus_f = encrypt_det(params, m_plus_f, &players[0].pk, (polynomial![0], polynomial![0], polynomial![0]));
        let mut e_m_prime = e_m_plus_f;
        for i in 0..amount_of_players {
            //e_m_prime = params.quotient_ring.sub(&e_m_prime, &e_f_is[i]); MISSING CORRECT BEHAVIOUR
        }
        return (None, m_is)
    }

    // Player P_i is supposed to get m_is[i]
    (None, m_is)

}

/// Implements Protocol PBracket (fig. 5)
pub fn p_bracket(params: &Parameters, v_is: Vec<Polynomial>, e_v: Ciphertext, players: &Vec<Player>) -> Vec<Polynomial> {
    let amount_of_players = players.len();

    let mut e_gamma_is = vec![vec![polynomial![0]]; amount_of_players];
    let mut v_bracket = v_is;

    for i in 0..amount_of_players {
        // All players do this
        e_gamma_is[i] = mul(params, &players[i].e_beta_is[i], &e_v);

        let (_, reshared) = reshare(params, &e_gamma_is[i], players, Enc::NoNewCiphertext);

        // Each player gets a share
        v_bracket = [
            v_bracket.as_slice(),
            players[i].e_beta_is[i].as_slice(),
            reshared.as_slice()
        ].concat();
    }
    v_bracket
}

/// Implements Protocol PAngle (fig. 6)
pub fn p_angle(params: &Parameters, v_is: Vec<Polynomial>, e_v: Ciphertext, players: &Vec<Player>) -> Vec<Polynomial> {
    // Each player does the following:
    let e_v_mul_alpha = mul(&params, &e_v, &players[0].e_alpha); 
    let (_, gamma_is) = reshare(params, &e_v_mul_alpha, players, Enc::NoNewCiphertext); // each player Pi gets a share γi of α·v
    let v_angle = [[polynomial![0]].as_slice(), v_is.as_slice(), gamma_is.as_slice()].concat();
    v_angle
}
