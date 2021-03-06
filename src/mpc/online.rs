//! Online phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 2)

use crate::{
    encryption::Parameters,
    mpc::{
        commitment::{commit, open},
        open_shares, MulTriple,
    },
    protocol::{Facilitator, OnlineMessage},
};

use rand::Rng;
use rug::{integer::Order, ops::RemRounding, rand::RandState, Integer};

use super::{AngleShare, PlayerState};

/// Implementation of the online protocol (fig. 1).
///
/// #### Precondition
/// The protocol assumes that the players have been initialized with the preprocessing protocol.
pub mod protocol {
    use crate::protocol::{Facilitator, OnlineMessage};

    use super::*;

    pub fn give_input<F: Facilitator>(
        params: &Parameters,
        x_i: Integer,
        r_pair: (Integer, AngleShare),
        state: &PlayerState<F>,
    ) -> AngleShare {
        let player_number = state.facilitator.player_number();

        // Send intent to share x_i
        let msg = OnlineMessage::BeginInput;
        state.facilitator.broadcast(&msg);
        match state.facilitator.receive(player_number) {
            OnlineMessage::BeginInput => {}
            m => panic!("expected BeginInput message from myself, received {:?}", m),
        }

        // Send our share to ourselves
        let (r_share, r_angle) = r_pair;
        let msg = OnlineMessage::ShareInteger(r_share);
        state.facilitator.send(player_number, &msg);

        // [[r]] is opened to P_i
        let messages = state.facilitator.receive_from_all();
        let r_shares = messages
            .into_iter()
            .map(|msg| match msg {
                OnlineMessage::ShareInteger(r_share) => r_share,
                _ => panic!("expected ShareInteger message, got {:?}", msg),
            })
            .collect();

        let r = open_shares(params, r_shares);

        // P_i broadcasts this
        // TODO: Burde dette være mod t?
        let eps = x_i - r;
        let msg = OnlineMessage::ShareInteger(eps.clone());
        state.facilitator.broadcast(&msg);
        let _ = state.facilitator.receive(player_number);

        if state.facilitator.player_number() == 0 {
            return (
                r_angle.0 + eps.clone(),
                r_angle.1 + eps * state.alpha_i.clone(),
            );
        }
        (r_angle.0, r_angle.1 + eps * state.alpha_i.clone())
    }

    pub fn receive_input<F: Facilitator>(
        r_pair: (Integer, AngleShare),
        sharing_player: usize,
        state: &PlayerState<F>,
    ) -> AngleShare {
        // Wait for sharing player to send BeginInput
        let msg = state.facilitator.receive(sharing_player);
        if !matches!(msg, OnlineMessage::BeginInput) {
            panic!("expected BeginInput, got {:?}", msg)
        }

        // Share r with P_i
        let (r_share, r_angle) = r_pair;
        let msg = OnlineMessage::ShareInteger(r_share);
        state.facilitator.send(sharing_player, &msg);

        // Receive eps
        let msg = state.facilitator.receive(sharing_player);
        let eps = match msg {
            OnlineMessage::ShareInteger(eps) => eps,
            _ => panic!("expected ShareInteger, received {:?}", msg),
        };

        if state.facilitator.player_number() == 0 {
            return (
                r_angle.0 + eps.clone(),
                r_angle.1 + eps * state.alpha_i.clone(),
            );
        }
        (r_angle.0, r_angle.1 + eps * state.alpha_i.clone())
    }

    pub fn add(x: &AngleShare, y: &AngleShare) -> AngleShare {
        ((&x.0 + &y.0).into(), (&x.1 + &y.1).into())
    }

    pub fn multiply<F: Facilitator>(
        params: &Parameters,
        x: AngleShare,
        y: AngleShare,
        abc_triple: MulTriple,
        fgh_triple: MulTriple,
        t_share: Integer,
        state: &mut PlayerState<F>,
    ) -> AngleShare {
        let (a_angle, b_angle, c_angle) = abc_triple.clone();

        // Check if ab = c in first triple by using the second triple
        match triple_check(params, abc_triple, fgh_triple, t_share, state) {
            Ok(()) => {}
            Err(e) => panic!("Triple check did not succeed: {:?}", e),
        }

        // Compute epsilon
        let epsilon_share = (x.0 - a_angle.clone().0, x.1 - a_angle.clone().1);
        let epsilon = partial_opening(params, epsilon_share.0, state);
        state.opened.push((epsilon.clone(), epsilon_share.1));

        // Compute delta
        let delta_share = (y.0 - b_angle.clone().0, y.1 - b_angle.clone().1);
        let delta = partial_opening(params, delta_share.0, state);
        state.opened.push((delta.clone(), delta_share.1));

        // Compute shares of result
        let mut z_share = (
            c_angle.0 + epsilon.clone() * b_angle.0 + delta.clone() * a_angle.0,
            c_angle.1 + epsilon.clone() * b_angle.1 + delta.clone() * a_angle.1,
        );

        // Adding epsilon * delta
        if state.facilitator.player_number() == 0 {
            z_share.0 += epsilon.clone() * delta.clone();
        }
        z_share.1 += epsilon * delta * state.alpha_i.clone();

        z_share
    }

    pub fn output<F: Facilitator>(
        params: &Parameters,
        y_angle: AngleShare,
        state: &PlayerState<F>,
    ) -> Integer {
        if !maccheck(params, state.opened.clone(), state) {
            panic!("MACCheck did not succeed!")
        }

        let (y_share, _) = y_angle;
        state
            .facilitator
            .broadcast(&OnlineMessage::ShareInteger(y_share));

        // Receive all broadcasted y shares
        let messages = state.facilitator.receive_from_all();
        let y_shares = messages
            .into_iter()
            .map(|msg| match msg {
                OnlineMessage::ShareInteger(y_share) => y_share,
                _ => panic!("expected ShareInteger message, got {:?}", msg),
            })
            .collect();

        let y = open_shares(params, y_shares);

        if !maccheck(params, vec![(y.clone(), y_angle.1)], state) {
            panic!("MACCheck did not succeed!")
        }

        // Broadcast my y_angle share
        y
    }
}

fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.iter().zip(y.iter()).map(|(&x, &y)| x ^ y).collect()
}

fn partial_opening<F: Facilitator>(
    params: &Parameters,
    to_share: Integer,
    state: &PlayerState<F>,
) -> Integer {
    let msg = OnlineMessage::ShareInteger(to_share);
    // Need to send to a designated player, here we choose player 1, which has index 0
    state.facilitator.send(0, &msg);
    if state.facilitator.player_number() == 0 {
        let messages = state.facilitator.receive_from_all();
        let shares = messages
            .into_iter()
            .map(|msg| match msg {
                OnlineMessage::ShareInteger(share) => share,
                _ => panic!("expected ShareInteger message, got {:?}", msg),
            })
            .collect();

        let result = open_shares(params, shares);
        let result_msg = OnlineMessage::ShareInteger(result);
        state.facilitator.broadcast(&result_msg)
    }

    let msg = state.facilitator.receive(0);
    match msg {
        OnlineMessage::ShareInteger(received) => received,
        _ => panic!("expected ShareInteger message, got {:?}", msg),
    }
}

fn maccheck<F: Facilitator>(
    params: &Parameters,
    to_check: Vec<(Integer, Integer)>,
    state: &PlayerState<F>,
) -> bool {
    let amount_of_players = state.facilitator.player_count();
    let t = to_check.len();

    // Sample seed, randomness, and commit to seed
    let s_i = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    let r = rand::thread_rng().gen::<[u8; 32]>().to_vec(); // Hvor mange bytes?
    commit(s_i.clone(), r.clone(), state);

    // Store commitments
    let messages = state.facilitator.receive_from_all();
    let commitments: Vec<Vec<u8>> = messages
        .into_iter()
        .map(|msg| match msg {
            OnlineMessage::ShareCommitment(commitment) => commitment,
            _ => panic!("expected ShareCommitment message, got {:?}", msg),
        })
        .collect();

    // This should actually have been a part of the commitment.rs module
    let mut o = vec![];
    o.extend(s_i);
    o.extend(r);
    state
        .facilitator
        .broadcast(&OnlineMessage::ShareCommitOpen(o));

    // This should actually have been a part of the commitment.rs module
    let messages = state.facilitator.receive_from_all();
    let seeds: Vec<Vec<u8>> = messages
        .into_iter()
        .enumerate()
        .map(|(i, msg)| match msg {
            OnlineMessage::ShareCommitOpen(o_i) => {
                let opened = open(commitments[i].clone(), o_i).unwrap();
                opened.iter().take(32).cloned().collect()
            }
            _ => panic!("expected ShareCommitOpen message, got {:?}", msg),
        })
        .collect();

    // XOR seeds to get s
    let mut s: Vec<u8> = seeds[0].clone();
    for seed in seeds.iter().skip(1) {
        s = xor(&s, seed);
    }

    // Players sample random vector r using seed s (a vector of length n with elements generated uniformly modulo q)
    let rng_seed: [u8; 32] = s
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("Expected seed length {}, got {}!", 32, s.len()));

    let rng_seed = Integer::from_digits(&rng_seed, Order::MsfBe);

    // TODO: This is not cryptographically secure, should make a custom RandGen
    let mut rand_state = RandState::new();
    rand_state.seed(&rng_seed);

    let mut r = Vec::with_capacity(t);
    for _ in 0..t {
        let r_i = params.p.clone().random_below(&mut rand_state);
        r.push(r_i);
    }

    // Each player computes a
    let mut a = Integer::ZERO;
    for j in 0..t {
        let a_j = to_check[j].clone().0;
        a = (a + r[j].clone() * a_j).rem_euc(&params.p);
    }

    // Player i computes gamma_i and sigma_i
    let mut gamma_i = Integer::ZERO;
    for j in 0..t {
        gamma_i = (gamma_i + r[j].clone() * to_check[j].clone().1).rem_euc(&params.p);
    }
    let sigma_i = (gamma_i - state.alpha_i.clone() * a).rem_euc(&params.p);

    // Convert sigma_i to bytes, sample randomness, and commit to sigma_i
    let sigma_i_bytes = sigma_i.to_digits(Order::MsfBe);
    let r = rand::thread_rng().gen::<[u8; 32]>().to_vec(); // Hvor mange bytes?
    commit(sigma_i_bytes.clone(), r.clone(), state);

    // Store commitments
    let messages = state.facilitator.receive_from_all();
    let sigma_commitments: Vec<Vec<u8>> = messages
        .into_iter()
        .map(|msg| match msg {
            OnlineMessage::ShareCommitment(commitment) => commitment,
            _ => panic!("expected ShareCommitment message, got {:?}", msg),
        })
        .collect();

    // This should actually have been a part of the commitment.rs module
    let mut o = vec![];
    o.extend(sigma_i_bytes);
    o.extend(r);
    state
        .facilitator
        .broadcast(&OnlineMessage::ShareCommitOpen(o));

    // This should actually have been a part of the commitment.rs module
    let messages = state.facilitator.receive_from_all();
    let sigma_is: Vec<Integer> = messages
        .into_iter()
        .enumerate()
        .map(|(i, msg)| match msg {
            OnlineMessage::ShareCommitOpen(o_i) => {
                let opened = open(sigma_commitments[i].clone(), o_i).unwrap();
                let digits: Vec<u8> = opened.iter().take(opened.len() - 32).cloned().collect();
                Integer::from_digits(&digits, Order::MsfBe)
            }
            _ => panic!("expected ShareCommitOpen message, got {:?}", msg),
        })
        .collect();

    // Sum sigma_i's and check that this equals 0
    let mut sigma_sum = Integer::ZERO;
    for sigma_i in sigma_is.iter().take(amount_of_players) {
        sigma_sum = (sigma_sum + sigma_i).rem_euc(&params.p);
    }

    sigma_sum == Integer::ZERO
}

#[allow(dead_code)]
#[derive(Debug)]
enum TripleCheckErr {
    ResultNotZero { result: Integer },
}

fn triple_check<F: Facilitator>(
    params: &Parameters,
    abc_triple: MulTriple,
    fgh_triple: MulTriple,
    t_share: Integer,
    state: &mut PlayerState<F>,
) -> Result<(), TripleCheckErr> {
    let (a_angle, b_angle, c_angle) = abc_triple;
    let (f_angle, g_angle, h_angle) = fgh_triple;

    // Open t_bracket
    let msg = OnlineMessage::ShareInteger(t_share);
    state.facilitator.broadcast(&msg);

    let messages = state.facilitator.receive_from_all();
    let t_shares = messages
        .into_iter()
        .map(|msg| match msg {
            OnlineMessage::ShareInteger(t_share) => t_share,
            _ => panic!("expected ShareInteger message, got {:?}", msg),
        })
        .collect();
    let t = open_shares(params, t_shares);

    // Compute rho
    let rho_share = (
        t.clone() * a_angle.0 - f_angle.clone().0,
        t.clone() * a_angle.1 - f_angle.clone().1,
    );
    let rho = partial_opening(params, rho_share.0, state);
    state.opened.push((rho.clone(), rho_share.1));

    // Compute sigma
    let sigma_share = (b_angle.0 - g_angle.clone().0, b_angle.1 - g_angle.clone().1);
    let sigma = partial_opening(params, sigma_share.0, state);
    state.opened.push((sigma.clone(), sigma_share.1));

    // Evaluate formula and check if zero as expected. If zero, then ab = c.
    let mut zero_share = (
        t.clone() * c_angle.0 - h_angle.0 - sigma.clone() * f_angle.0 - rho.clone() * g_angle.0,
        t * c_angle.1 - h_angle.1 - sigma.clone() * f_angle.1 - rho.clone() * g_angle.1,
    );

    // Subtracting sigma * rho
    if state.facilitator.player_number() == 0 {
        zero_share.0 -= sigma.clone() * rho.clone();
    }
    zero_share.1 -= sigma * rho * state.alpha_i.clone();

    let zero = partial_opening(params, zero_share.0, state);
    state.opened.push((zero.clone(), zero_share.1));

    //Check for 0
    match zero == Integer::ZERO {
        true => Ok(()),
        false => Err(TripleCheckErr::ResultNotZero { result: zero }),
    }
}