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
        todo!()
    }

    /// Implements the Pair step
    pub fn pair() {
        todo!()
    }

    /// Implements the Triple step
    pub fn triple() {
        todo!()
    }
}

/// Implements Protocol Reshare (fig. 4)
pub fn reshare(params: &Parameters, e_m: Ciphertext, players: &Vec<Player>, enc: Enc) -> Vec<Polynomial> {
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
        e_f = add(params, e_f, e_f_is[i].clone())
    }
    let e_m_plus_f = add(params, e_m, e_f);

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

    m_is

}

/// Implements Protocol PBracket (fig. 5)
pub fn p_bracket() {
    todo!()
}

/// Implements Protocol PAngle (fig. 6)
pub fn p_angle() {
    todo!()
}
