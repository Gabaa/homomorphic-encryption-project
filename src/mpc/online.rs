//! Online phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 2)

use crate::{polynomial, poly::Polynomial, mpc::Player};

pub struct ProtocolOnline {}

impl ProtocolOnline {
    pub fn input(x_i: Polynomial, r_pair: (Vec<Polynomial>, Vec<Polynomial>), players: Vec<Player>) -> Vec<Polynomial> {
        let (r_angle, r_bracket) = r_pair;
        let amount_of_players = players.len();

        // Open r_bracket to P_i
        let mut r = polynomial![0];
        for i in 0..r_bracket.len() {
            r = r + r_bracket[i].clone()
        }

        // P_i broadcasts this
        let eps = x_i - r;
        
        // All parties compute
        let mut x_i_angle_shares = vec![polynomial![0]; amount_of_players];
        for i in 0..amount_of_players {
            x_i_angle_shares[i] = r_angle[i].clone() + eps.clone();
        }

        x_i_angle_shares
    }

    pub fn add(x: Vec<Polynomial>, y: Vec<Polynomial>) -> Vec<Polynomial> {
        // Players just add shares locally
        let mut res = vec![polynomial![0]; x.len()];
        for i in 0..x.len() {
            res[i] = x[i].clone() + y[i].clone()
        }
        res
    }

    pub fn multiply() {
        
    }

    pub fn output(e_bracket: Vec<Polynomial>, opened: Vec<Polynomial>, shared_sk: Vec<Polynomial>) -> Polynomial {
        let amount_opened = opened.len();

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

        // OPEN COMMITMENT

        // CALCULATE y
        let y = polynomial![0];

        y
    }
}