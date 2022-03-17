use num::BigInt;

use crate::poly::*;
use crate::prob::sample_from_uniform;
use crate::Parameters;
use crate::{encryption::*, polynomial};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Player {
    sk_i1: Polynomial,
    sk_i2: Polynomial,
    pk: PublicKey,
}

#[allow(dead_code)]
impl Player {
    pub fn new() -> Player {
        Player {
            sk_i1: polynomial![0],
            sk_i2: polynomial![0],
            pk: (polynomial![0], polynomial![0]),
        }
    }

    pub fn broadcast() {
        todo!();
    }
}

// Function for functionality in Fkey_gen figure 2 of the MPC article.
#[allow(dead_code)]
pub fn distribute_keys(params: &Parameters, mut players: Vec<Player>) -> Vec<Player> {
    let rq = &params.quotient_ring;
    let n = players.len();

    // set sk and pk for the first n-1 players.
    let (pk, sk) = generate_key_pair(params);
    for i in 0..players.len() - 1 {
        players[i].sk_i1 = sample_from_uniform(&rq.q, params.n);
        players[i].sk_i2 = sample_from_uniform(&rq.q, params.n);
        players[i].pk = pk.clone();
    }

    // set sk and pk for the n'th player.
    let mut sk_n2 = rq.mul(&sk, &sk);
    let mut sk_n1 = sk;
    for player in players.iter().take(n - 1) {
        sk_n1 = rq.add(&sk_n1, &(rq.neg(&player.sk_i1.clone())));
        sk_n2 = rq.add(&sk_n2, &(rq.neg(&player.sk_i2.clone())));
    }

    players[n - 1].sk_i1 = sk_n1;
    players[n - 1].sk_i2 = sk_n2;
    players[n - 1].pk = pk;

    players
}

// Function for "dec" functionality in Fkey_gen_dec figure 3 of the MPC article.
#[allow(dead_code)]
pub fn ddec(params: &Parameters, players: Vec<Player>, mut c: Ciphertext) -> Polynomial {
    let rq = &params.quotient_ring;
    let mut v = vec![polynomial![0]; players.len()];

    // Need to ensure that there are 3 elements (there can never be < 2)
    if c.len() == 2 {
        c.push(polynomial![0])
    }
    c[1] = rq.neg(&c[1]); //Hvorfor er definitionen anderledes i IdealHom teksten og i 535 teksten?

    for i in 0..players.len() {
        let p = &players[i];
        let sk1i_mul_c1 = rq.mul(&p.sk_i1, &c[1]);
        let sk2i_mul_c2 = rq.mul(&p.sk_i2, &c[2]);
        let sub = rq.add(&sk1i_mul_c1, &rq.neg(&sk2i_mul_c2));
        let sub_neg = rq.neg(&sub);
        if i == 0 {
            v[i] = rq.add(&c[0], &sub_neg)
        } else {
            v[i] = sub_neg
        }
    }

    //Random element does not currently have a bounded l_inf norm
    let t: Vec<Polynomial> = v
        .iter()
        .map(|v_i| {
            rq.add(
                v_i,
                &rq.times(
                    &sample_from_uniform(&BigInt::from(1000_i32), params.n),
                    &params.t,
                ),
            )
        }) // 1000 is placeholder, since q needs to be a lot higher for this to work properly
        .collect();

    let t_prime = t
        .iter()
        .fold(polynomial![0], |acc, elem| rq.add(&acc, elem));

    t_prime.modulo(&params.t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::*;

    #[test]
    fn test_all_players_pk_are_equal() {
        let mut player_array = vec![Player::new(); 5];
        let params = Parameters::default();
        player_array = distribute_keys(&params, player_array);

        let pk = player_array[0].pk.clone();
        for player in player_array {
            assert_eq!(player.pk, pk);
        }
    }

    #[test]
    fn test_sk_shares_are_correct() {
        let mut players = vec![Player::new(); 5];
        let params = Parameters::default();
        let rq = &params.quotient_ring;

        players = distribute_keys(&params, players);

        let mut s = polynomial![0];
        for player in &players {
            s = rq.add(&s, &player.sk_i1)
        }

        let pk = players[0].pk.clone();

        let msg = polynomial![0];
        let cipher = encrypt(&params, msg, &pk);
        let decrypted = decrypt(&params, cipher, &s);

        assert_eq!(decrypted.unwrap(), polynomial![0]);
        // At this point we know that s = sk

        let s_mul_s = rq.mul(&s, &s);

        let mut s_mul_s_from_players = polynomial![0];
        for player in players {
            s_mul_s_from_players = rq.add(&s_mul_s_from_players, &player.sk_i2)
        }

        assert_eq!(s_mul_s, s_mul_s_from_players);
    }

    #[test]
    fn test_distributed_decryption_works() {
        let mut player_array = vec![Player::new(); 5];
        let params = Parameters::default();
        player_array = distribute_keys(&params, player_array);

        let pk = player_array[0].pk.clone();

        let msg = polynomial![0];
        let cipher = encrypt(&params, msg, &pk);
        let decrypted = ddec(&params, player_array, cipher);

        assert_eq!(decrypted, polynomial![0]);
    }
}
