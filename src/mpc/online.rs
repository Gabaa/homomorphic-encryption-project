//! Online phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 2)

use num::Zero;
use num::One;
use crate::BigInt;
use crate::quotient_ring::Rq;
use crate::mpc::open_shares;
use crate::{polynomial, poly::Polynomial, mpc::Player, encryption::Parameters};

pub type MulTriple = (Vec<Polynomial>, Vec<Polynomial>, Vec<Polynomial>);

pub struct ProtocolOnline {}

impl ProtocolOnline {
    pub fn input(params: &Parameters, x_i: Polynomial, r_pair: (Vec<Polynomial>, Vec<Polynomial>), players: &Vec<Player>) -> Vec<Polynomial> {
        let rq = &params.quotient_ring;
        let amount_of_players = players.len();
        let (r_bracket, r_angle) = r_pair;
        
        // Open r_bracket to P_i
        let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let r = open_shares(&params, shares);

        // P_i broadcasts this
        let eps = (x_i - r);
        
        // All parties compute
        let mut x_i_angle_shares = r_angle.clone();
        x_i_angle_shares[0] = r_angle[0].clone() - eps.clone();
        x_i_angle_shares[1] = r_angle[1].clone() + eps;

        x_i_angle_shares
    }

    pub fn add(params: &Parameters, x: Vec<Polynomial>, y: Vec<Polynomial>) -> Vec<Polynomial> {
        // Players just add shares locally
        let mut res = vec![polynomial![0]; x.len()];
        for i in 0..x.len() {
            res[i] = x[i].clone() + y[i].clone();
        }
        res
    }

    // SKAL DE ANDRE VÆRDIER OGSÅ REGNES PÅ NÅR VI REGNER PÅ ANGLE REPR.?
    pub fn multiply(params: &Parameters,
        x: Vec<Polynomial>,
        y: Vec<Polynomial>,
        abc_triple: MulTriple,
        fgh_triple: MulTriple,
        t_bracket: Vec<Polynomial>,
        players: &Vec<Player>)
    -> Vec<Polynomial> {

        let amount_of_players = players.len();
        let (a_angle, b_angle, c_angle) = abc_triple;
        let (f_angle, g_angle, h_angle) = fgh_triple;

        //CODE FOR ACTIVE SEC MISSING HERE
        
        // Check if ab = c in first triple by using the second triple

        // Compute epsilon
        let mut epsilon_shares = vec![polynomial![]; players.len()];
        for i in 0..amount_of_players {
            epsilon_shares[i] = x[i + 1].clone() - a_angle[i + 1].clone();
        }
        let epsilon = open_shares(&params, epsilon_shares);

        // Compute delta
        let mut delta_shares = vec![polynomial![]; players.len()];
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

        let mut fx_vec = vec![BigInt::zero(); params.n + 1];
        fx_vec[0] = BigInt::one();
        fx_vec[params.n] = BigInt::one();
        let fx = Polynomial::from(fx_vec);
        let rt = Rq::new(params.t.clone(), fx);

        // Should get own opened instead of just getting 1'st players
        let amount_opened = players[0].opened.len();
        let amount_of_players = players.len();

        // CODE FOR ACTIVE SEC MISSING HERE

        // Open e_bracket to get e

        // Gen e_i's

        // Commit to MAC's + yi

        // Open global key alpha

        // Open commitments and compute y_i's

        // CALCULATE y
        let shares = y_angle.iter().skip(1).take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
        let y = open_shares(&params, shares);
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
