//! Online phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 2)

use crate::mpc::commitment::commit;
use crate::mpc::commitment::open;
use crate::mpc::open_shares;
use crate::mpc::{Angle, MulTriple};
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

    /* pub fn multiply<F: Facilicator>(
        params: &Parameters,
        x: AngleShare,
        y: AngleShare,
        abc_triple: MulTriple,
        fgh_triple: MulTriple,
        t_shares: BigInt,
        state: PlayerState<F>,
    ) -> (AngleShare, PlayerState<F>) {
        let amount_of_players = players.len();
        let (a_angle, b_angle, c_angle) = abc_triple.clone();
        let (f_angle, g_angle, h_angle) = fgh_triple.clone();

        let mut new_players = players.clone();
        new_players[0].opened.push(x.clone());
        new_players[0].opened.push(y.clone());
        new_players[0].opened.push(a_angle.clone());
        new_players[0].opened.push(b_angle.clone());
        new_players[0].opened.push(c_angle.clone());
        new_players[0].opened.push(f_angle.clone());
        new_players[0].opened.push(g_angle.clone());
        new_players[0].opened.push(h_angle.clone());

        // Check if ab = c in first triple by using the second triple

        if !triple_check(&params, abc_triple, fgh_triple, t_shares, &players) {
            panic!("Triple check did not succeed!")
        }

        // Compute epsilon
        let mut epsilon_shares = vec![BigInt::zero(); amount_of_players];
        for i in 0..amount_of_players {
            epsilon_shares[i] = x[i].clone() - a_angle[i].clone();
        }
        let epsilon = open_shares(&params, epsilon_shares, amount_of_players);

        // Compute delta
        let mut delta_shares = vec![BigInt::zero(); amount_of_players];
        for i in 0..amount_of_players {
            delta_shares[i] = y[i].clone() - b_angle[i].clone();
        }
        let delta = open_shares(&params, delta_shares, amount_of_players);

        // Compute shares of result
        let mut z_shares = vec![BigInt::zero(); x.len()];
        for i in 0..x.len() {
            z_shares[i] = c_angle[i].clone()
                + epsilon.clone() * b_angle[i].clone()
                + delta.clone() * a_angle[i].clone();
        }
        z_shares[0] = z_shares[0].clone() + epsilon.clone() * delta.clone();
        for i in 0..amount_of_players {
            z_shares[amount_of_players + i] = z_shares[amount_of_players + i].clone()
                + (epsilon.clone() * delta.clone()) * players[i].alpha_i.clone();
        }

        (z_shares, new_players)
    } */

    pub fn output<F: Facilicator>(
        params: &Parameters,
        y_angle: AngleShare,
        state: &PlayerState<F>,
    ) -> BigInt {
        let amount_of_players = state.facilitator.player_count();

        /* if !maccheck(params, players[0].opened.clone(), &players) {
            panic!("MACCheck did not succeed!")
        }

        if !maccheck(params, vec![y_angle.clone()], &players) {
            panic!("MACCheck did not succeed!")
        } */

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

/* pub fn maccheck<F: Facilicator>(
    params: &Parameters,
    to_check: Vec<Angle>,
    state: PlayerState<F>,
) -> bool {
    let amount_of_players = players.len();
    let t = to_check.len();

    let mut commitments: Vec<Vec<u8>> = vec![];
    // Storing o's here does not really make sense, but its fine for now, since we need to broadcast it normally
    let mut o_is: Vec<Vec<u8>> = vec![];
    for i in 0..amount_of_players {
        // Sample seed s_i and broadcast commitment generated using COMMIT func
        let mut s_i = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        let r = rand::thread_rng().gen::<[u8; 32]>().to_vec(); // Hvor mange bytes?
        commitments.push(commit(s_i.clone(), r.clone()));

        s_i.extend(r);
        o_is.push(s_i);
    }

    let mut seeds: Vec<Vec<u8>> = vec![vec![]; amount_of_players];
    for i in 0..amount_of_players {
        // Ask COMMIT func to open commitment
        let opened = open(commitments[i].clone(), o_is[i].clone()).unwrap();
        seeds[i] = opened.iter().take(32).cloned().collect()
    }

    // XOR seeds to get s
    let mut s: Vec<u8> = seeds[0].clone();
    for i in 1..amount_of_players {
        s = xor(s, seeds[i].clone());
    }

    // Players sample random vector r using seed s (a vector of length n with elements generated uniformly modulo q)
    let rng_seed: [u8; 32] = s.as_slice().try_into().expect("Wrong length!");
    let range = Uniform::new(BigInt::zero(), &params.t);
    let rng = StdRng::from_seed(rng_seed);
    let r: Vec<BigInt> = rng.sample_iter(&range).take(t).collect();

    // Each player computes a
    let mut a: BigInt = BigInt::zero();
    for j in 0..t {
        let a_j = open_shares(params, to_check[j].clone(), amount_of_players);
        a = (a + r[j].clone() * a_j.clone()).modpow(&BigInt::one(), &params.t);
    }

    // Player i computes gamma_i and sigma_i
    let mut sigma_is_nonshared = vec![BigInt::zero(); amount_of_players];
    for i in 0..amount_of_players {
        let mut gamma_i = BigInt::zero();
        for j in 0..t {
            gamma_i = (gamma_i + r[j].clone() * to_check[j][amount_of_players + i].clone())
                .modpow(&BigInt::one(), &params.t);
        }
        sigma_is_nonshared[i] =
            (gamma_i - players[i].alpha_i.clone() * a.clone()).modpow(&BigInt::one(), &params.t);
    }

    // Commit to sigma_i and broadcast
    let mut sigma_commitments: Vec<Vec<u8>> = vec![];
    // Storing o's here does not really make sense, but its fine for now, since we need to broadcast it normally
    let mut sigma_o_is: Vec<Vec<u8>> = vec![];
    for i in 0..amount_of_players {
        // Sample seed s_i and broadcast commitment generated using COMMIT func
        let (_, sigma_i_bytes) = sigma_is_nonshared[i].to_bytes_be();
        let mut to_commit = sigma_i_bytes;
        let r = rand::thread_rng().gen::<[u8; 32]>().to_vec(); // Hvor mange bytes?
        sigma_commitments.push(commit(to_commit.clone(), r.clone()));

        to_commit.extend(r);
        sigma_o_is.push(to_commit);
    }

    // Players open commitments to get sigma_i's
    let mut sigma_is = vec![BigInt::zero(); amount_of_players];
    for i in 0..amount_of_players {
        // Ask COMMIT func to open commitment
        let opened = open(sigma_commitments[i].clone(), sigma_o_is[i].clone()).unwrap();
        sigma_is[i] = BigInt::from_bytes_be(
            num::bigint::Sign::NoSign,
            &opened
                .iter()
                .take(32)
                .cloned()
                .collect::<Vec<u8>>()
                .as_slice(),
        )
    }

    // Sum sigma_i's and check that this equals 0
    let mut sigma_sum = BigInt::zero();
    for i in 0..amount_of_players {
        sigma_sum = (sigma_sum + sigma_is[i].clone()).modpow(&BigInt::one(), &params.t);
    }

    sigma_sum == BigInt::zero()
}

pub fn xor(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
    x.iter().zip(y.iter()).map(|(&x, &y)| x ^ y).collect()
}

pub fn triple_check<F: Facilicator>(
    params: &Parameters,
    abc_triple: MulTriple,
    fgh_triple: MulTriple,
    t_shares: Vec<BigInt>,
    state: PlayerState<F>,
) -> bool {
    let (a_angle, b_angle, c_angle) = abc_triple;
    let (f_angle, g_angle, h_angle) = fgh_triple;
    let amount_of_players = players.len();
    // Open t_bracket
    let t = open_shares(&params, t_shares, amount_of_players);

    // Compute rho
    let mut rho_shares = vec![BigInt::zero(); amount_of_players];
    for i in 0..amount_of_players {
        rho_shares[i] = t.clone() * a_angle[i].clone() - f_angle[i].clone();
    }
    let rho = open_shares(&params, rho_shares, amount_of_players);

    // Compute sigma
    let mut sigma_shares = vec![BigInt::zero(); amount_of_players];
    for i in 0..amount_of_players {
        sigma_shares[i] = b_angle[i].clone() - g_angle[i].clone();
    }
    let sigma = open_shares(&params, sigma_shares, amount_of_players);

    // Evaluate formula and check if zero as expected. If zero, then ab = c.
    let mut zero_shares = vec![BigInt::zero(); amount_of_players];
    for i in 0..amount_of_players {
        let t_times_c = t.clone() * c_angle[i].clone();
        let h = h_angle[i].clone();
        let sigma_times_f = sigma.clone() * f_angle[i].clone();
        let rho_times_g = rho.clone() * g_angle[i].clone();

        zero_shares[i] = t_times_c - h - sigma_times_f - rho_times_g;
    }

    zero_shares[0] = zero_shares[0].clone() - sigma.clone() * rho.clone();
    let zero = open_shares(&params, zero_shares, amount_of_players);

    //Check for 0
    zero == BigInt::zero()
} */

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
