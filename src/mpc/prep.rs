//! Preprocessing phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 5)

use crate::{encryption::*, mpc::{Player, ddec}, prob::sample_from_uniform, polynomial, poly::Polynomial};

pub enum Enc {
    NewCiphertext,
    NoNewCiphertext,
}

/// Represents the preprocessing protocol (fig. 7)
pub struct ProtocolPrep {}

impl ProtocolPrep {
    /// Implements the Initialize step
    pub fn initialize(params: &Parameters, players: &Vec<Player>) {
        
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
        let shared = reshare(params, &e_c, players, Enc::NewCiphertext);
        let c_angle = p_angle(params, shared, e_c, players); // e_c should be e_c' (output of reshare    )

        (a_angle, b_angle, c_angle)
    }
}

/// Implements Protocol Reshare (fig. 4)
pub fn reshare(params: &Parameters, e_m: &Ciphertext, players: &Vec<Player>, enc: Enc) -> Vec<Polynomial> {
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
    m_is[0] = m_plus_f + -f_is[0].clone();
    for i in 1..amount_of_players {
        m_is[i] = -f_is[i].clone()
    }

    if matches!(enc, NewCiphertext) {
        // TODO: Supposed to do an encryption with default randomness (requires refactoring)
        // Then the encryption should be returned instead of m_i's
        todo!()
    }

    // Player P_i is supposed to get m_is[i]
    m_is

}

/// Implements Protocol PBracket (fig. 5)
pub fn p_bracket(params: &Parameters, v_is: Vec<Polynomial>, e_v: Ciphertext, players: &Vec<Player>) -> Vec<Polynomial> {
    let amount_of_players = players.len();

    let mut e_gamma_is = vec![vec![polynomial![0]]; amount_of_players];
    let mut v_bracket = v_is;

    for i in 0..amount_of_players {
        // All players do this
        e_gamma_is[i] = mul(params, &players[i].e_beta_is[i], &e_v);

        // Each player gets a share
        v_bracket = [
            v_bracket.as_slice(),
            players[i].e_beta_is[i].as_slice(),
            reshare(params, &e_gamma_is[i], players, Enc::NoNewCiphertext).as_slice()
        ].concat();
    }
    v_bracket
}

/// Implements Protocol PAngle (fig. 6)
pub fn p_angle(params: &Parameters, v_is: Vec<Polynomial>, e_v: Ciphertext, players: &Vec<Player>) -> Vec<Polynomial> {
    // Each player does the following:
    let e_v_mul_alpha = mul(&params, &e_v, &players[0].e_alpha); 
    let gamma_is = reshare(params, &e_v_mul_alpha, players, Enc::NoNewCiphertext); // each player Pi gets a share γi of α·v
    let v_angle = [[polynomial![0]].as_slice(), v_is.as_slice(), gamma_is.as_slice()].concat();
    v_angle
}
