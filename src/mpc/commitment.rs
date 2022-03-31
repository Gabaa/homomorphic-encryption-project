use crate::BigInt;
use crate::mpc::Bracket;
use crate::mpc::open_shares;
use crate::Parameters;

pub fn commit(params: &Parameters, r_bracket: Bracket, x: BigInt, amount_of_players: usize) -> BigInt {
    let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<BigInt>>();
    let r = open_shares(&params, shares);
    let c = r + x;
    c
}

pub fn open(params: &Parameters, r_bracket: Bracket, c: BigInt, amount_of_players: usize) -> BigInt {
    let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<BigInt>>();
    let r = open_shares(&params, shares);
    let x = c - r;
    x
}