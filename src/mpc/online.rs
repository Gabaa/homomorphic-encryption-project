//! Online phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 2)

use num::One;
use num::Zero;
use crate::protocol::OnlineMessage;
use crate::mpc::commitment::commit;
use crate::mpc::commitment::open;
use crate::mpc::open_shares;
use crate::mpc::MulTriple;
use crate::{encryption::Parameters, protocol::Facilicator};
use num::BigInt;
use rand::distributions::Uniform;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

use super::{AngleShare, PlayerState};

/// Implementation of the online protocol (fig. 1).
///
/// #### Precondition
/// The protocol assumes that the players have been initialized with the preprocessing protocol.
pub mod protocol {
    use crate::protocol::OnlineMessage;

    use super::*;

    pub fn give_input<F: Facilicator>(
        params: &Parameters,
        x_i: BigInt,
        r_pair: (BigInt, AngleShare),
        state: &PlayerState<F>,
    ) -> AngleShare {
        let amount_of_players = state.facilitator.player_count();
        let player_number = state.facilitator.player_number();

        // Send intent to share x_i
        let msg = OnlineMessage::BeginInput;
        state.facilitator.broadcast(&msg);
        let _ = state.facilitator.receive();

        // Send our share to ourselves
        let (r_share, r_angle) = r_pair;
        let msg = OnlineMessage::ShareBigInt(r_share);
        state.facilitator.send(player_number, &msg);

        // [[r]] is opened to P_i
        let msgs = state.facilitator.receive_many(amount_of_players);
        let mut r_shares = Vec::with_capacity(amount_of_players);
        for msg in msgs {
            if let (_, OnlineMessage::ShareBigInt(r_share)) = msg {
                r_shares.push(r_share)
            }
        }
        let r = open_shares(params, r_shares, amount_of_players);

        // P_i broadcasts this
        // TODO: Burde dette være mod t?
        let eps = x_i - r;
        let msg = OnlineMessage::ShareBigInt(eps.clone());
        state.facilitator.broadcast(&msg);
        let _ = state.facilitator.receive();

        if state.facilitator.player_number() == 0 {
            return (
                r_angle.0 + eps.clone(),
                r_angle.1 + eps * state.alpha_i.clone(),
            );
        }
        (r_angle.0, r_angle.1 + eps * state.alpha_i.clone())
    }

    pub fn receive_input<F: Facilicator>(
        r_pair: (BigInt, AngleShare),
        state: &PlayerState<F>,
    ) -> AngleShare {
        // Wait for sharing player to send BeginInput
        let (p_i, msg) = state.facilitator.receive();
        if !matches!(msg, OnlineMessage::BeginInput) {
            panic!()
        }

        // Share r with P_i
        let (r_share, r_angle) = r_pair;
        let msg = OnlineMessage::ShareBigInt(r_share);
        state.facilitator.send(p_i, &msg);

        // Receive eps
        let (_, msg) = state.facilitator.receive();
        let eps = match msg {
            OnlineMessage::ShareBigInt(eps) => eps,
            _ => panic!(),
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
        (&x.0 + &y.0, &x.1 + &y.1)
    }

    pub fn multiply<F: Facilicator>(
        params: &Parameters,
        x: AngleShare,
        y: AngleShare,
        abc_triple: MulTriple,
        fgh_triple: MulTriple,
        t_share: BigInt,
        mut state: PlayerState<F>,
    ) -> (AngleShare, PlayerState<F>) {
        let amount_of_players = state.facilitator.player_count();
        let (a_angle, b_angle, c_angle) = abc_triple.clone();

        // Check if ab = c in first triple by using the second triple

        let (is_valid, new_state) = triple_check(&params, abc_triple, fgh_triple, t_share, state);
        if !is_valid {
            panic!("Triple check did not succeed!")
        }
        state = new_state;

        // Compute epsilon
        let epsilon_share = (x.0 - a_angle.clone().0, x.1 - a_angle.clone().1);
        let epsilon = partial_opening(&params, epsilon_share.0, &state);
        state.opened.push((epsilon.clone(), epsilon_share.1));

        // Compute delta
        let delta_share = (y.0 - b_angle.clone().0, y.1 - b_angle.clone().1);
        let delta = partial_opening(&params, delta_share.0, &state);
        state.opened.push((delta.clone(), delta_share.1));

        // Compute shares of result
        let mut z_share = (c_angle.0 + epsilon.clone() * b_angle.0 + delta.clone() * a_angle.0,
            c_angle.1 + epsilon.clone() * b_angle.1 + delta.clone() * a_angle.1);

        // Adding epsilon * delta
        if state.facilitator.player_number() == 0 {
            z_share = (
                z_share.0 + epsilon.clone() * delta.clone(),
                z_share.1 + epsilon.clone() * delta.clone() * state.alpha_i.clone()
            );
        }
        z_share = (
            z_share.0,
            z_share.1 + epsilon.clone() * delta.clone() * state.alpha_i.clone()
        );

        (z_share, state)
    }

    pub fn output<F: Facilicator>(
        params: &Parameters,
        y_angle: AngleShare,
        state: &PlayerState<F>,
    ) -> BigInt {
        let amount_of_players = state.facilitator.player_count();

        if !maccheck(params, state.opened.clone(), state) {
            panic!("MACCheck did not succeed!")
        }

        if !maccheck(params, vec![y_angle.clone()], state) {
            panic!("MACCheck did not succeed!")
        }

        // Broadcast my y_angle share
        let (y_share, _) = y_angle;
        state
            .facilitator
            .broadcast(&OnlineMessage::ShareBigInt(y_share));

        // Receive all broadcasted y shares
        let msgs = state.facilitator.receive_many(amount_of_players);
        let mut y_shares = Vec::with_capacity(amount_of_players);
        for msg in msgs {
            if let (_, OnlineMessage::ShareBigInt(y_share)) = msg {
                y_shares.push(y_share);
            }
        }

        open_shares(params, y_shares, amount_of_players)
    }
}

fn xor(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
    x.iter().zip(y.iter()).map(|(&x, &y)| x ^ y).collect()
}

fn partial_opening<F: Facilicator>(params: &Parameters, to_share: BigInt, state: &PlayerState<F>) -> BigInt {
    let amount_of_players = state.facilitator.player_count();
        let msg = OnlineMessage::ShareBigInt(to_share);
        // Need to send to a designated player, here we choose player 1, which has index 0
        state.facilitator.send(0, &msg);
        if state.facilitator.player_number() == 0 {
            let mut epsilon_shares = Vec::with_capacity(amount_of_players);
            let messages = state.facilitator.receive_many(amount_of_players);
            for (_, msg) in messages {
                if let OnlineMessage::ShareBigInt(eps_i) = msg {
                    epsilon_shares.push(eps_i);
                }
            }
            let eps = open_shares(&params, epsilon_shares, amount_of_players);
            let eps_msg = OnlineMessage::ShareBigInt(eps);
            state.facilitator.broadcast(&eps_msg)
        }

        let (from, msg) = state.facilitator.receive();
        if from != 0 {
            panic!("Supposed to receive message from player 1, but received from someone else")
        }
        if let OnlineMessage::ShareBigInt(received) = msg {
            return received
        }
        
        BigInt::zero() // TODO: Mere clean løsning
}

fn maccheck<F: Facilicator>(
    params: &Parameters,
    to_check: Vec<(BigInt, BigInt)>,
    state: &PlayerState<F>,
) -> bool {
    let amount_of_players = state.facilitator.player_count();
    let t = to_check.len();

    // Sample seed, randomness, and commit to seed
    let s_i = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    let r = rand::thread_rng().gen::<[u8; 32]>().to_vec(); // Hvor mange bytes?
    commit(s_i.clone(), r.clone(), state);

    // Store commitments
    let mut commitments: Vec<Vec<u8>> = vec![vec![]; amount_of_players];
    for _ in 0..amount_of_players {
        let (p_i, msg) = state.facilitator.receive();
        if let OnlineMessage::ShareCommitment(commitment_i) = msg {
            commitments[p_i] = commitment_i;
        }
    }

    // This should actually have been a part of the commitment.rs module
    let mut o = vec![];
    o.extend(s_i);
    o.extend(r);
    state.facilitator.broadcast(&OnlineMessage::ShareCommitOpen(o));

    // This should actually have been a part of the commitment.rs module
    let mut seeds: Vec<Vec<u8>> = vec![vec![]; amount_of_players];
    for _ in 0..amount_of_players {
        let (p_i, msg) = state.facilitator.receive();
        if let OnlineMessage::ShareCommitOpen(o_i) = msg {
            let opened = open(commitments[p_i].clone(), o_i).unwrap();
            seeds[p_i] = opened.iter().take(32).cloned().collect();
            
        }
    }

    // XOR seeds to get s
    let mut s: Vec<u8> = seeds[0].clone();
    for i in 1..amount_of_players {
        s = xor(s, seeds[i].clone());
    }

    // Players sample random vector r using seed s (a vector of length n with elements generated uniformly modulo q)
    let rng_seed: [u8; 32] = s.as_slice().try_into().expect("Wrong length seed received!");
    let range = Uniform::new(BigInt::zero(), &params.t);
    let rng = StdRng::from_seed(rng_seed);
    let r: Vec<BigInt> = rng.sample_iter(&range).take(t).collect();

    // Each player computes a
    let mut a: BigInt = BigInt::zero();
    for j in 0..t {
        let a_j = to_check[j].clone().0;
        a = (a + r[j].clone() * a_j).modpow(&BigInt::one(), &params.t);
    }

    // Player i computes gamma_i and sigma_i
    let mut gamma_i = BigInt::zero();
    for j in 0..t {
        gamma_i = (gamma_i + r[j].clone() * to_check[j].clone().1).modpow(&BigInt::one(), &params.t);
    }
    let sigma_i = (gamma_i - state.alpha_i.clone() * a.clone()).modpow(&BigInt::one(), &params.t);

    // Convert sigma_i to bytes, sample randomness, and commit to sigma_i
    let (_, sigma_i_bytes) = sigma_i.to_bytes_be();
    let r = rand::thread_rng().gen::<[u8; 32]>().to_vec(); // Hvor mange bytes?
    commit(sigma_i_bytes.clone(), r.clone(), state);

    // Store commitments
    let mut sigma_commitments: Vec<Vec<u8>> = vec![vec![]; amount_of_players];
    for _i in 0..amount_of_players {
        let (p_i, msg) = state.facilitator.receive();
        if let OnlineMessage::ShareCommitment(commitment_i) = msg {
            sigma_commitments[p_i] = commitment_i;
        }
    }

    // This should actually have been a part of the commitment.rs module
    let mut o = vec![];
    o.extend(sigma_i_bytes);
    o.extend(r);
    state.facilitator.broadcast(&OnlineMessage::ShareCommitOpen(o));

    // This should actually have been a part of the commitment.rs module
    let mut sigma_is: Vec<BigInt> = vec![BigInt::zero(); amount_of_players];
    for i in 0..amount_of_players {
        let (p_i, msg) = state.facilitator.receive();
        if let OnlineMessage::ShareCommitOpen(o_i) = msg {
            let opened = open(sigma_commitments[p_i].clone(), o_i).unwrap();
            sigma_is[p_i] = BigInt::from_bytes_be(
                num::bigint::Sign::NoSign,
                &opened.iter().take(opened.len() - 32).cloned().collect::<Vec<u8>>().as_slice(),
            )
        }
    }

    // Sum sigma_i's and check that this equals 0
    let mut sigma_sum = BigInt::zero();
    for i in 0..amount_of_players {
        sigma_sum = (sigma_sum + sigma_is[i].clone()).modpow(&BigInt::one(), &params.t);
    }

    sigma_sum == BigInt::zero()
}

pub fn triple_check<F: Facilicator>(
    params: &Parameters,
    abc_triple: MulTriple,
    fgh_triple: MulTriple,
    t_share: BigInt,
    mut state: PlayerState<F>,
) -> (bool, PlayerState<F>) {
    let (a_angle, b_angle, c_angle) = abc_triple;
    let (f_angle, g_angle, h_angle) = fgh_triple;
    let amount_of_players = state.facilitator.player_count();

    // Open t_bracket
    let msg = OnlineMessage::ShareBigInt(t_share);
    state.facilitator.broadcast(&msg);

    let msgs = state.facilitator.receive_many(amount_of_players);
    let mut t_shares = Vec::with_capacity(amount_of_players);
    for msg in msgs {
        if let (_, OnlineMessage::ShareBigInt(t_share)) = msg {
            t_shares.push(t_share)
        }
    }
    let t = open_shares(&params, t_shares, amount_of_players);

    // Compute rho
    let rho_share = (t.clone() * a_angle.0 - f_angle.clone().0, t.clone() * a_angle.1 - f_angle.clone().1);
    let rho = partial_opening(&params, rho_share.0, &state);
    state.opened.push((rho.clone(), rho_share.1));

    // Compute sigma
    let sigma_share = (b_angle.0 - g_angle.clone().0, b_angle.1 - g_angle.clone().1);
    let sigma = partial_opening(&params, sigma_share.0, &state);
    state.opened.push((sigma.clone(), sigma_share.1));

    // Evaluate formula and check if zero as expected. If zero, then ab = c.
    let t_times_c = (t.clone() * c_angle.0, t * c_angle.1);
    let sigma_times_f = (sigma.clone() * f_angle.0, sigma.clone() * f_angle.1);
    let rho_times_g = (rho.clone() * g_angle.0, rho.clone() * g_angle.1);

    let mut zero_share = (
        t_times_c.0 - h_angle.0 - sigma_times_f.0 - rho_times_g.0,
        t_times_c.1 - h_angle.1 - sigma_times_f.1 - rho_times_g.1
    );

    // Subtracting sigma * rho
    if state.facilitator.player_number() == 0 {
        zero_share = (
            zero_share.0 - sigma.clone() * rho.clone(),
            zero_share.1 - sigma.clone() * rho.clone() * state.alpha_i.clone()
        );
    }
    zero_share = (
        zero_share.0,
        zero_share.1 - sigma.clone() * rho.clone() * state.alpha_i.clone()
    );

    let zero = partial_opening(&params, zero_share.0, &state);
    state.opened.push((zero.clone(), zero_share.1));

    //Check for 0
    (zero == BigInt::zero(), state)
}

/* #[cfg(test)]
mod tests {
    use crate::{encryption::secure_params, mpc::prep::*, mpc::*};

    use super::*;

    #[test]
    fn test_input() {
        let players = vec![Player::new(); 3];

        let params = secure_params();

        let initialized_players = ProtocolPrep::initialize(&params, &players);
        let r1_pair = ProtocolPrep::pair(&params, &initialized_players);

        assert_eq!(r1_pair.1.len(), players.len() * 2);

        let x = ProtocolOnline::input(&params, BigInt::from(2_i32), r1_pair, &initialized_players);
        let x_output = ProtocolOnline::output(&params, x, initialized_players);

        assert_eq!(BigInt::from(2_i32), x_output)
    }

    #[test]
    fn test_add() {
        let players = vec![Player::new(); 3];

        let params = secure_params();

        let initialized_players = ProtocolPrep::initialize(&params, &players);
        let r1_pair = ProtocolPrep::pair(&params, &initialized_players);
        let r2_pair = ProtocolPrep::pair(&params, &initialized_players);

        let x = ProtocolOnline::input(&params, BigInt::from(2_i32), r1_pair, &initialized_players);
        let y = ProtocolOnline::input(&params, BigInt::from(7_i32), r2_pair, &initialized_players);

        let res = ProtocolOnline::add(&params, x, y);
        let output = ProtocolOnline::output(&params, res, initialized_players);

        assert_eq!(BigInt::from(9_i32), output)
    }

    #[test]
    fn test_multiply() {
        let players = vec![Player::new(); 3];

        let params = secure_params();

        let initialized_players = ProtocolPrep::initialize(&params, &players);
        let triple_1 = ProtocolPrep::triple(&params, &initialized_players);
        let triple_2 = ProtocolPrep::triple(&params, &initialized_players);
        let r1_pair = ProtocolPrep::pair(&params, &initialized_players);
        let r2_pair = ProtocolPrep::pair(&params, &initialized_players);
        let (t_bracket, _) = ProtocolPrep::pair(&params, &initialized_players);

        let x = ProtocolOnline::input(&params, BigInt::from(2_i32), r1_pair, &initialized_players);
        let y = ProtocolOnline::input(&params, BigInt::from(7_i32), r2_pair, &initialized_players);

        let (res, new_players) = ProtocolOnline::multiply(
            &params,
            x,
            y,
            triple_1,
            triple_2,
            t_bracket,
            &initialized_players,
        );
        let output = ProtocolOnline::output(&params, res, new_players);

        assert_eq!(BigInt::from(14_i32), output)
    }
}
 */
