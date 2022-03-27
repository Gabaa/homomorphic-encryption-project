//! Online phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 2)

use crate::{polynomial, poly::Polynomial, mpc::Player, encryption::Parameters};

pub struct ProtocolOnline {}

impl ProtocolOnline {
    pub fn input(params: &Parameters, x_i: Polynomial, r_pair: (Vec<Polynomial>, Vec<Polynomial>), players: &Vec<Player>) -> Vec<Polynomial> {
        let rq = &params.quotient_ring;
        let amount_of_players = players.len();
        let (r_bracket, r_angle) = r_pair;
        

        // Open r_bracket to P_i
        let mut r = polynomial![0];
        for i in 0..amount_of_players {
            r = (r + r_bracket[i].clone()).modulo(&params.t);
        }

        // P_i broadcasts this
        let eps = (x_i - r).modulo(&params.t);
        
        // All parties compute
        let mut x_i_angle_shares = r_angle.clone();
        x_i_angle_shares[0] = (r_angle[0].clone() - eps.clone()).modulo(&params.t);
        x_i_angle_shares[1] = (r_angle[1].clone() + eps).modulo(&params.t);

        x_i_angle_shares
    }

    pub fn add(params: &Parameters, x: Vec<Polynomial>, y: Vec<Polynomial>) -> Vec<Polynomial> {
        // Players just add shares locally
        let mut res = vec![polynomial![0]; x.len()];
        for i in 0..x.len() {
            res[i] = (x[i].clone() + y[i].clone()).modulo(&params.t);
        }
        res
    }

    pub fn multiply() -> Vec<Polynomial> {
        todo!()
    }

    pub fn output(params: &Parameters, y_angle: Vec<Polynomial>, e_bracket: Vec<Polynomial>, opened: Vec<Polynomial>, shared_sk: Vec<Polynomial>, players: Vec<Player>) -> Polynomial {
        let amount_opened = opened.len();
        let amount_of_players = players.len();

        /* // ALL OF THIS IS ONLY FOR ACTIVE SEC
        // Open e_bracket
        let mut e = polynomial![0];
        for i in 0..e_bracket.len() {
            e = e + e_bracket[i].clone()
        }

        // Compute e_i's
        let mut e_is = vec![polynomial![0]; amount_opened];
        e_is[0] = e.clone();
        for i in 1..amount_opened {
            e_is[i] = e_is[i-1].clone() * e.clone()
        }

        let mut a = polynomial![0];
        for j in 0..amount_opened {
            a = a + (e_is[j].clone() * opened[j].clone())
        }

        // USE COMMITMENT SCHEME

        // Open shared sk alpha
        let mut alpha = polynomial![0];
        for i in 0..shared_sk.len() {
            alpha = alpha + shared_sk[i].clone()
        }

        // OPEN COMMITMENT */

        // CALCULATE y
        let mut y = polynomial![0];
        for i in 1..amount_of_players + 1 {
            y = (y + y_angle[i].clone()).modulo(&params.t);
        }
        
        y
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
        let x_output = ProtocolOnline::output(&params, x, e_bracket, vec![], global_key, initialized_players);
        
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
        let output = ProtocolOnline::output(&params, res, e_bracket, vec![], global_key, initialized_players);

        assert_eq!(polynomial![9], output)
    }

    /* #[test]
    fn test_multiply() {
        let players = vec![Player::new(); 3];

        let params = secure_params();

        let (initialized_players, global_key) = ProtocolPrep::initialize(&params, &players);
        let r1_pair = ProtocolPrep::pair(&params, &initialized_players);
        let r2_pair = ProtocolPrep::pair(&params, &initialized_players);

        let x = ProtocolOnline::input(&params, polynomial![2], r1_pair, &initialized_players);
        let y = ProtocolOnline::input(&params, polynomial![7], r2_pair, &initialized_players);

        let (e_bracket, _) = ProtocolPrep::pair(&params, &initialized_players);

        let res = ProtocolOnline::multiply();
        let output = ProtocolOnline::output(&params, res, e_bracket, vec![], global_key, initialized_players);

        assert_eq!(polynomial![14], output)

    } */
}
