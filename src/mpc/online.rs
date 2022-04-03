//! Online phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 2)

use crate::mpc::{MulTriple, Angle, Bracket};
use num::Zero;
use num::One;
use crate::BigInt;
use crate::quotient_ring::Rq;
use crate::mpc::open_shares;
use crate::{polynomial, poly::Polynomial, mpc::Player, encryption::Parameters};

pub struct ProtocolOnline {}

impl ProtocolOnline {
    pub fn input(params: &Parameters, x_i: Polynomial, r_pair: (Bracket, Angle), players: &Vec<Player>) -> Angle {
        let amount_of_players = players.len();
        let (r_bracket, r_angle) = r_pair;
        
        // Open r_bracket to P_i
        let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let r = open_shares(&params, shares);

        // P_i broadcasts this
        let eps = x_i - r;
        
        // All parties compute
        let mut x_i_angle_shares = r_angle.clone();
        x_i_angle_shares[0] = r_angle[0].clone() - eps.clone();
        x_i_angle_shares[1] = r_angle[1].clone() + eps;

        x_i_angle_shares
    }

    pub fn add(params: &Parameters, x: Angle, y: Angle) -> Angle {
        // Players just add shares locally
        let mut res = vec![polynomial![0]; x.len()];
        for i in 0..x.len() {
            res[i] = x[i].clone() + y[i].clone();
        }
        res
    }

    // SKAL DE ANDRE VÆRDIER OGSÅ REGNES PÅ NÅR VI REGNER PÅ ANGLE REPR.?
    pub fn multiply(params: &Parameters,
        x: Angle,
        y: Angle,
        abc_triple: MulTriple,
        fgh_triple: MulTriple,
        t_bracket: Bracket,
        players: &Vec<Player>)
    -> Angle {

        let rt = Rq::new(params.t.clone(), params.quotient_ring.modulo.clone());
        let amount_of_players = players.len();
        let (a_angle, b_angle, c_angle) = abc_triple;
        let (f_angle, g_angle, h_angle) = fgh_triple;

        
        // Check if ab = c in first triple by using the second triple

        // Open t_bracket
        let t_shares = t_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let t = open_shares(&params, t_shares);

        // Compute rho
        let mut rho_shares = vec![polynomial![]; amount_of_players];
        for i in 0..amount_of_players {
            rho_shares[i] = t.clone() * a_angle[i + 1].clone() - f_angle[i + 1].clone();
        }
        let rho = open_shares(&params, rho_shares);
        
        // Compute sigma
        let mut sigma_shares = vec![polynomial![]; amount_of_players];
        for i in 0..amount_of_players {
            sigma_shares[i] = b_angle[i + 1].clone() - g_angle[i + 1].clone();
        }
        let sigma = open_shares(&params, sigma_shares);

        // Evaluate formula and check if zero as expected. If zero, then ab = c.
        let mut zero_shares = vec![polynomial![0]; x.len()];
        for i in 0..x.len() {
            let t_times_c = t.clone() * c_angle[i].clone();
            let h = h_angle[i].clone();
            let sigma_times_f = sigma.clone() * f_angle[i].clone();
            let rho_times_g = rho.clone() * g_angle[i].clone();

            zero_shares[i] = t_times_c - h - sigma_times_f - rho_times_g;
        }
        zero_shares[0] = zero_shares[0].clone() + sigma.clone() * rho.clone();
        zero_shares[1] = zero_shares[1].clone() - sigma.clone() * rho.clone();
        zero_shares = zero_shares.iter().skip(1).take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let zero = rt.reduce(&open_shares(&params, zero_shares));

        println!("zero: {:?}", zero);

        //Check for 0
        if zero != polynomial![0; i32] {
            panic!("Polynomial non-zero! ab != c")
        }

        // Compute epsilon
        let mut epsilon_shares = vec![polynomial![]; amount_of_players];
        for i in 0..amount_of_players {
            epsilon_shares[i] = x[i + 1].clone() - a_angle[i + 1].clone();
        }
        let epsilon = open_shares(&params, epsilon_shares);

        // Compute delta
        let mut delta_shares = vec![polynomial![]; amount_of_players];
        for i in 0..amount_of_players {
            delta_shares[i] = y[i + 1].clone() - b_angle[i + 1].clone();
        }
        let delta = open_shares(&params, delta_shares);

        // Compute shares of result
        let mut z_shares = vec![polynomial![]; x.len()];
        for i in 0..x.len() {
            z_shares[i] = c_angle[i].clone() + epsilon.clone() * b_angle[i].clone() + delta.clone() * a_angle[i].clone();
        }
        z_shares[0] = z_shares[0].clone() - epsilon.clone() * delta.clone();
        z_shares[1] = z_shares[1].clone() + epsilon.clone() * delta.clone();

        z_shares
    }

    pub fn output(params: &Parameters,
        y_angle: Vec<Polynomial>,
        e_bracket: Vec<Polynomial>,
        shared_sk: Vec<Polynomial>,
        players: Vec<Player>)
    -> Polynomial {

        let rt = Rq::new(params.t.clone(), params.quotient_ring.modulo.clone());

        // Should get own opened instead of just getting 1'st players
        let amount_opened = players[0].opened.len();
        let amount_of_players = players.len();

        // CODE FOR ACTIVE SEC MISSING HERE

        // Open e_bracket to get e
        let e_shares = e_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let e = open_shares(&params, e_shares);

        // All players compute a
        let mut a = polynomial![0];
        let mut e_is = vec![polynomial![0]; amount_opened];
        if amount_opened > 0 {
            e_is[0] = e.clone();
            for j in 0..amount_opened {
                // Compute a_j's
                let a_j_shares = players[0].opened[j].iter().skip(1).take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
                let a_j = open_shares(&params, a_j_shares);

                // Gen e_i's
                e_is[j] = e_is[j-1].clone() * e.clone();

                // Compute a
                a = a + e_is[j].clone() * a_j
            }
        }

        // Commit to gamma_i + yi + MAC

        let alpha_shares = shared_sk.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let alpha = open_shares(&params, alpha_shares);

        // Open commitments and compute y_i's

        /* for i in 0..amount_of_players {
            players[i].opened.push(y_angle)
        } */
        // CALCULATE y
        let y_shares = y_angle.iter().skip(1).take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let y = open_shares(&params, y_shares);
        rt.reduce(&y)
    }
}

#[cfg(test)]
mod tests {
    use crate::{mpc::*, mpc::prep::*, encryption::secure_params};

    use super::*;

    #[test]
    fn test_input() {
        let players = vec![Player::new(); 3];

        let params = secure_params();

        let (initialized_players, global_key) = ProtocolPrep::initialize(&params, &players);
        let r1_pair = ProtocolPrep::pair(&params, &initialized_players);

        assert_eq!(r1_pair.1.len(), 1 + players.len() * 2);

        let x = ProtocolOnline::input(&params, polynomial![2], r1_pair, &initialized_players);
        let (e_bracket, _) = ProtocolPrep::pair(&params, &initialized_players);
        let x_output = ProtocolOnline::output(&params, x, e_bracket, global_key, initialized_players);
        
        assert_eq!(polynomial![2], x_output)

    }

    #[test]
    fn test_add() {
        let players = vec![Player::new(); 3];

        let params = secure_params();

        let (initialized_players, global_key) = ProtocolPrep::initialize(&params, &players);
        let r1_pair = ProtocolPrep::pair(&params, &initialized_players);
        let r2_pair = ProtocolPrep::pair(&params, &initialized_players);

        let x = ProtocolOnline::input(&params, polynomial![2], r1_pair, &initialized_players);
        let y = ProtocolOnline::input(&params, polynomial![7], r2_pair, &initialized_players);
        
        let (e_bracket, _) = ProtocolPrep::pair(&params, &initialized_players);

        let res = ProtocolOnline::add(&params, x, y);
        let output = ProtocolOnline::output(&params, res, e_bracket, global_key, initialized_players);

        assert_eq!(polynomial![9], output)
    }

    #[test]
    fn test_multiply() {
        let players = vec![Player::new(); 3];

        let params = secure_params();

        let (initialized_players, global_key) = ProtocolPrep::initialize(&params, &players);
        let triple_1 = ProtocolPrep::triple(&params, &initialized_players);
        let triple_2 = ProtocolPrep::triple(&params, &initialized_players);
        let r1_pair = ProtocolPrep::pair(&params, &initialized_players);
        let r2_pair = ProtocolPrep::pair(&params, &initialized_players);
        let (t_bracket, _) = ProtocolPrep::pair(&params, &initialized_players);

        let x = ProtocolOnline::input(&params, polynomial![2], r1_pair, &initialized_players);
        let y = ProtocolOnline::input(&params, polynomial![7], r2_pair, &initialized_players);

        let (e_bracket, _) = ProtocolPrep::pair(&params, &initialized_players);

        let res = ProtocolOnline::multiply(&params, x, y, triple_1, triple_2, t_bracket, &initialized_players);
        let output = ProtocolOnline::output(&params, res, e_bracket, global_key, initialized_players);

        assert_eq!(polynomial![14], output)

    }
}
