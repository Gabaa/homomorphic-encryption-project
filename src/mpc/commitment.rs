use crate::mpc::open_shares;
use crate::Parameters;
use crate::Polynomial;

pub fn commit(params: &Parameters, r_bracket: Vec<Polynomial>, x: Polynomial, amount_of_players: usize) -> Polynomial {
    let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
    let r = open_shares(&params, shares);
    let c = r + x;
    c
}

pub fn open(params: &Parameters, r_bracket: Vec<Polynomial>, c: Polynomial, amount_of_players: usize) -> Polynomial {
    let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
    let r = open_shares(&params, shares);
    let x = c - r;
    x
}