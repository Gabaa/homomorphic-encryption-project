//! Preprocessing phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 5)

use crate::mpc::zk::zkpopk;
use crate::mpc::AngleShare;
use crate::mpc::PlayerState;
use crate::protocol::OnlineMessage;
use crate::{
    encryption::*,
    mpc::{ddec, diag},
    poly::Polynomial,
    polynomial,
    prob::*,
};
use crate::{mpc::add_encrypted_shares, protocol::Facilicator};

use rug::{ops::RemRounding, Integer};

pub enum Enc {
    NewCiphertext,
    NoNewCiphertext,
}

/// Represents the preprocessing protocol (fig. 7)
pub mod protocol {
    use super::*;

    /// Implements the Initialize step
    pub fn initialize<F: Facilicator>(params: &Parameters, state: &mut PlayerState<F>) {
        state.alpha_i = sample_single(&params.t);
        let e_alpha_i = encrypt(
            params,
            encode(diag(params, state.alpha_i.clone())),
            &state.pk,
        );

        let msg = OnlineMessage::ShareCiphertext(e_alpha_i.clone());
        state.facilitator.broadcast(&msg);

        let messages = state.facilitator.receive_from_all();
        let e_alpha_is = messages
            .into_iter()
            .map(|msg| match msg {
                OnlineMessage::ShareCiphertext(e_i) => e_i,
                _ => panic!("expected ShareCiphertext message, got {:?}", msg),
            })
            .collect();

        state.e_alpha = add_encrypted_shares(params, e_alpha_is);

        // TODO: ZK proof faked for now
        let sec = 40; //sec hardcoded for now common values are 40, 80
        for _ in 0..sec {
            if !zkpopk(e_alpha_i.clone()) {
                panic!("ZK proof failed!")
            }
        }
    }

    /// Implements the Pair step
    pub fn pair<F: Facilicator>(
        params: &Parameters,
        state: &PlayerState<F>,
    ) -> (Integer, AngleShare) {
        let r_i = sample_single(&params.t);
        let e_r_i = encrypt(params, encode(r_i.clone()), &state.pk);

        let msg = OnlineMessage::ShareCiphertext(e_r_i.clone());
        state.facilitator.broadcast(&msg);

        let messages = state.facilitator.receive_from_all();
        let e_r_is: Vec<Vec<Polynomial>> = messages
            .into_iter()
            .map(|msg| match msg {
                OnlineMessage::ShareCiphertext(e_i) => e_i,
                _ => panic!("expected ShareCiphertext message, got {:?}", msg),
            })
            .collect();

        let e_r = add_encrypted_shares(params, e_r_is);

        // TODO: ZK proof faked for now
        if !zkpopk(e_r_i) {
            panic!("ZK proof failed!")
        }

        let r_angle = p_angle(params, r_i.clone(), e_r, state);
        (r_i, r_angle)
    }

    /// Implements the Triple step
    pub fn triple<F: Facilicator>(
        params: &Parameters,
        state: &PlayerState<F>,
    ) -> (AngleShare, AngleShare, AngleShare) {
        let a_i = sample_single(&params.t);
        let b_i = sample_single(&params.t);
        let e_a_i = encrypt(params, encode(a_i.clone()), &state.pk);
        let e_b_i = encrypt(params, encode(b_i.clone()), &state.pk);

        let msg = OnlineMessage::ShareCiphertext(e_a_i.clone());
        state.facilitator.broadcast(&msg);

        let messages = state.facilitator.receive_from_all();
        let e_a_is = messages
            .into_iter()
            .map(|msg| match msg {
                OnlineMessage::ShareCiphertext(e_i) => e_i,
                _ => panic!("expected ShareCiphertext message, got {:?}", msg),
            })
            .collect();

        let msg = OnlineMessage::ShareCiphertext(e_b_i.clone());
        state.facilitator.broadcast(&msg);

        let messages = state.facilitator.receive_from_all();
        let e_b_is = messages
            .into_iter()
            .map(|msg| match msg {
                OnlineMessage::ShareCiphertext(e_i) => e_i,
                _ => panic!("expected ShareCiphertext message, got {:?}", msg),
            })
            .collect();

        let e_a = add_encrypted_shares(params, e_a_is);
        let e_b = add_encrypted_shares(params, e_b_is);

        // TODO: ZK proof faked for now
        if !zkpopk(e_a_i) {
            panic!("ZK proof failed!")
        }
        if !zkpopk(e_b_i) {
            panic!("ZK proof failed!")
        }

        let a_angle = p_angle(params, a_i, e_a.clone(), state);
        let b_angle = p_angle(params, b_i, e_b.clone(), state);
        let e_c = mul(params, &e_a, &e_b);

        let (e_c_prime_opt, reshared) = reshare(params, &e_c, state, Enc::NewCiphertext);
        let e_c_prime: Ciphertext = e_c_prime_opt.unwrap();

        let c_angle = p_angle(params, reshared, e_c_prime, state);

        (a_angle, b_angle, c_angle)
    }
}

/// Implements Protocol Reshare (fig. 4)
fn reshare<F: Facilicator>(
    params: &Parameters,
    e_m: &Ciphertext,
    state: &PlayerState<F>,
    enc: Enc,
) -> (Option<Ciphertext>, Integer) {
    let f_i = sample_single(&params.t);
    let e_f_i = encrypt(params, encode(f_i.clone()), &state.pk);

    let msg = OnlineMessage::ShareCiphertext(e_f_i.clone());
    state.facilitator.broadcast(&msg);

    let messages = state.facilitator.receive_from_all();
    let e_f_is: Vec<Vec<Polynomial>> = messages
        .into_iter()
        .map(|msg| match msg {
            OnlineMessage::ShareCiphertext(e_i) => e_i,
            _ => panic!("expected ShareCiphertext message, got {:?}", msg),
        })
        .collect();

    // ZK proof faked for now
    if !zkpopk(e_f_i) {
        panic!("ZK proof failed!")
    }

    // This is done by each player
    let e_f = add_encrypted_shares(params, e_f_is.clone());
    let e_m_plus_f = add(params, e_m, &e_f);

    // Done by each player
    let m_plus_f = ddec(params, state, e_m_plus_f);

    let m_i = if state.facilitator.player_number() == 0 {
        (m_plus_f.clone() - f_i).rem_euc(&params.t)
    } else {
        (-f_i).rem_euc(&params.t)
    };

    if matches!(enc, Enc::NewCiphertext) {
        let mut e_m_prime = encrypt_det(
            params,
            encode(m_plus_f),
            &state.pk,
            (polynomial![1], polynomial![1], polynomial![1]),
        ); //Hvilket randomness???
        for e_f_i in e_f_is {
            e_m_prime = add(
                params,
                &e_m_prime,
                &(e_f_i.iter().map(|e| -(e.clone())).collect()),
            );
        }
        return (Some(e_m_prime), m_i);
    }

    // Player P_i is supposed to get m_is[i]
    (None, m_i)
}

/// Implements Protocol PAngle (fig. 6)
fn p_angle<F: Facilicator>(
    params: &Parameters,
    v_i: Integer,
    e_v: Ciphertext,
    player_state: &PlayerState<F>,
) -> AngleShare {
    // Each player does the following:
    let e_v_mul_alpha = mul(params, &e_v, &player_state.e_alpha);
    let (_, gamma_i) = reshare(params, &e_v_mul_alpha, player_state, Enc::NoNewCiphertext); // each player Pi gets a share γi of α·v
    let v_angle: AngleShare = (v_i, gamma_i);
    v_angle
}

/* #[cfg(test)]
mod tests {
    use crate::{encryption::secure_params, mpc::prep::*, mpc::*};

    #[test]
    fn test_mult_triple() {
        let amount_of_players = 3;
        let players = vec![Player::new(); amount_of_players];
        let params = secure_params();

        let initialized_players = ProtocolPrep::initialize(&params, &players);
        let (a_angle, b_angle, c_angle) = ProtocolPrep::triple(&params, &initialized_players);

        let mut a = Integer::ZERO;
        let mut b = Integer::ZERO;
        let mut c = Integer::ZERO;
        for i in 0..amount_of_players {
            a = a + a_angle[i].clone();
            b = b + b_angle[i].clone();
            c = c + c_angle[i].clone()
        }

        assert_eq!(
            (a * b).modpow(&Integer::from(1), &params.t),
            c.modpow(&Integer::from(1), &params.t)
        )
    }

    #[test]
    fn test_reshare() {
        let amount_of_players = 3;
        let players = vec![Player::new(); amount_of_players];
        let params = secure_params();

        let initialized_players = ProtocolPrep::initialize(&params, &players);

        let mut r_is = vec![Integer::ZERO; amount_of_players];
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
        let mut sigma = Integer::ZERO;
        for i in 0..amount_of_players {
            sigma =
                (sigma + angle[amount_of_players + i].clone()).modpow(&Integer::from(1), &params.t);
        }
        let a = open_shares(&params, angle, amount_of_players);
        let mut alpha_is = vec![Integer::ZERO; amount_of_players];
        for i in 0..amount_of_players {
            alpha_is[i] = initialized_players[i].alpha_i.clone();
        }
        let alpha = open_shares(&params, alpha_is, amount_of_players);
        let res = (alpha * a).modpow(&Integer::from(1), &params.t);
        assert_eq!(res, sigma)
    }
}
 */
