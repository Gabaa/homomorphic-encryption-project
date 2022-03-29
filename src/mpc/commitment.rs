pub fn commit(r_bracket: Vec<Polynomial>, x: Polynomial) -> Polynomial {
    let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
    let r = open_shares(&params, shares);
    let c = r + x;
    c
}

pub fn open(r_bracket: Vec<Polynomial>, c: Polynomial) -> Polynomial {
    let shares = r_bracket.iter().take(amount_of_players).cloned().collect::<Vec<Polynomial>>();
    let r = open_shares(&params, shares);
    let x = c - r;
    x
}