//! Preprocessing phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 5)

use super::{
    add_encrypted_shares,
    zk::{make_zkpopk, verify_zkpopk},
    AngleShare, PlayerState, SEC,
};

use crate::{
    encryption::*,
    mpc::{ddec, diag},
    poly::Polynomial,
    polynomial,
    prob::*,
    protocol::{Facilitator, OnlineMessage},
};

use rug::{ops::RemRounding, Integer};

pub enum Enc {
    NewCiphertext,
    NoNewCiphertext,
}

/// Represents the preprocessing protocol (fig. 7)
pub mod protocol {
    use super::*;

    /// Implements the Initialize step
    pub fn initialize<F: Facilitator>(params: &Parameters, state: &mut PlayerState<F>) {
        state.alpha_i = sample_single(&params.p);
        let alpha_i_polynomial = encode(diag(params, state.alpha_i.clone()));
        let (e_alpha_i, r_i) = encrypt_with_rand(params, alpha_i_polynomial.clone(), &state.pk);

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

        run_zkpopk_for_single(params, state, alpha_i_polynomial, r_i, e_alpha_i);
    }

    /// Implements the Pair step
    pub fn pair<F: Facilitator>(
        params: &Parameters,
        state: &PlayerState<F>,
    ) -> (Integer, AngleShare) {
        let r_i = sample_single(&params.p);
        let r_i_polynomial = encode(r_i.clone());
        let (e_r_i, r_r_i) = encrypt_with_rand(params, r_i_polynomial.clone(), &state.pk);

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

        run_zkpopk_for_single(params, state, r_i_polynomial, r_r_i, e_r_i);

        let r_angle = p_angle(params, r_i.clone(), e_r, state);
        (r_i, r_angle)
    }

    /// Implements the Triple step
    pub fn triple<F: Facilitator>(
        params: &Parameters,
        state: &PlayerState<F>,
    ) -> (AngleShare, AngleShare, AngleShare) {
        let a_i = sample_single(&params.p);
        let b_i = sample_single(&params.p);
        let a_i_polynomial = encode(a_i.clone());
        let (e_a_i, r_a_i) = encrypt_with_rand(params, a_i_polynomial.clone(), &state.pk);
        let b_i_polynomial = encode(b_i.clone());
        let (e_b_i, r_b_i) = encrypt_with_rand(params, b_i_polynomial.clone(), &state.pk);

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

        run_zkpopk_for_single(params, state, a_i_polynomial, r_a_i, e_a_i);
        run_zkpopk_for_single(params, state, b_i_polynomial, r_b_i, e_b_i);

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
fn reshare<F: Facilitator>(
    params: &Parameters,
    e_m: &Ciphertext,
    state: &PlayerState<F>,
    enc: Enc,
) -> (Option<Ciphertext>, Integer) {
    let f_i = sample_single(&params.p);
    let f_i_polynomial = encode(f_i.clone());
    let (e_f_i, r_f_i) = encrypt_with_rand(params, f_i_polynomial.clone(), &state.pk);

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

    run_zkpopk_for_single(params, state, f_i_polynomial, r_f_i, e_f_i);

    let e_f = add_encrypted_shares(params, e_f_is.clone());
    let e_m_plus_f = add(params, e_m, &e_f);

    let m_plus_f = ddec(params, state, e_m_plus_f);

    let m_i = if state.facilitator.player_number() == 0 {
        (m_plus_f.clone() - f_i).rem_euc(&params.p)
    } else {
        (-f_i).rem_euc(&params.p)
    };

    if matches!(enc, Enc::NewCiphertext) {
        let mut e_m_prime = encrypt_det(
            params,
            encode(m_plus_f),
            &state.pk,
            (polynomial![1], polynomial![1], polynomial![1]),
        );
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
fn p_angle<F: Facilitator>(
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

fn run_zkpopk_for_single<F: Facilitator>(
    params: &Parameters,
    state: &PlayerState<F>,
    x_i: Polynomial,
    r_i: (Polynomial, Polynomial, Polynomial),
    c_i: Ciphertext,
) {
    // Create own ZKPoPK
    // We are running the protocol on (x_i, ..., x_i) (sec times)
    let x = vec![x_i; SEC];
    let r = vec![r_i; SEC];
    let c = vec![c_i; SEC];

    let (a, z, t) = make_zkpopk(params, x, r, c.clone(), true, &state.pk);

    // Broadcast ZKPoPK to all players
    let message = OnlineMessage::ShareZKPoPK { a, z, t, c };
    state.facilitator.broadcast(&message);

    // Verify all received ZKPoPK
    let messages = state.facilitator.receive_from_all();
    for (i, msg) in messages.into_iter().enumerate() {
        match msg {
            OnlineMessage::ShareZKPoPK { a, z, t, c } => {
                if !verify_zkpopk(params, a, z, t, c, &state.pk) {
                    panic!("ZKPoPK for player {} failed", i)
                }
            }
            _ => panic!("expected ShareZKPoPK, got {:?}", msg),
        }
    }
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
            (a * b).modpow(&Integer::from(1), &params.p),
            c.modpow(&Integer::from(1), &params.p)
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
            r_is[i] = sample_single(&params.p)
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
                (sigma + angle[amount_of_players + i].clone()).modpow(&Integer::from(1), &params.p);
        }
        let a = open_shares(&params, angle, amount_of_players);
        let mut alpha_is = vec![Integer::ZERO; amount_of_players];
        for i in 0..amount_of_players {
            alpha_is[i] = initialized_players[i].alpha_i.clone();
        }
        let alpha = open_shares(&params, alpha_is, amount_of_players);
        let res = (alpha * a).modpow(&Integer::from(1), &params.p);
        assert_eq!(res, sigma)
    }
}
 */
