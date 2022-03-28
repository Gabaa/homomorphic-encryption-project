use num::BigInt;

use crate::poly::*;
use crate::prob::sample_from_uniform;
use crate::Parameters;
use crate::{encryption::*, polynomial};

mod online;
mod prep;

#[derive(Clone, Debug)]
pub struct Player {
    sk_i1: Polynomial,
    sk_i2: Polynomial,
    pk: PublicKey,
    e_beta_is: Vec<Ciphertext>,
    e_alpha: Ciphertext
}

impl Player {
    pub fn new() -> Player {
        Player {
            sk_i1: polynomial![0],
            sk_i2: polynomial![0],
            pk: (polynomial![0], polynomial![0]),
            e_beta_is: vec![],
            e_alpha: vec![polynomial![0]]
        }
    }

    pub fn broadcast() {
        todo!();
    }
}

/// Function for functionality in Fkey_gen figure 2 of the MPC article.
pub fn distribute_keys(params: &Parameters, mut players: Vec<Player>) -> Vec<Player> {
    let rq = &params.quotient_ring;
    let n = players.len();

    // set sk and pk for the first n-1 players.
    let (pk, sk) = generate_key_pair(params);
    for player in players.iter_mut().take(n - 1) {
        player.sk_i1 = sample_from_uniform(&rq.q, params.n);
        player.sk_i2 = sample_from_uniform(&rq.q, params.n);
        player.pk = pk.clone();
    }

    // set sk and pk for the n'th player.
    let mut sk_n2 = rq.mul(&sk, &sk);
    let mut sk_n1 = sk;
    for player in players.iter().take(n - 1) {
        sk_n1 = rq.sub(&sk_n1, &player.sk_i1.clone());
        sk_n2 = rq.sub(&sk_n2, &player.sk_i2.clone());
    }

    players[n - 1].sk_i1 = sk_n1;
    players[n - 1].sk_i2 = sk_n2;
    players[n - 1].pk = pk;

    players
}

/// Function for "dec" functionality in Fkey_gen_dec figure 3 of the MPC article.
pub fn ddec(params: &Parameters, players: &Vec<Player>, mut c: Ciphertext) -> Polynomial {
    let rq = &params.quotient_ring;
    let mut v = vec![polynomial![0]; players.len()];

    // Need to ensure that there are 3 elements (there can never be < 2)
    if c.len() == 2 {
        c.push(polynomial![0])
    }
    //c[1] = rq.neg(&c[1]); //Hvorfor er definitionen anderledes i IdealHom teksten og i 535 teksten?

    for i in 0..players.len() {
        let p = &players[i];
        let si1_ci1 = rq.mul(&p.sk_i1, &c[1]);
        let si2_ci2 = rq.mul(&p.sk_i2, &c[2]);
        let sum = rq.add(&si1_ci1, &si2_ci2);
        if i == 0 {
            v[i] = rq.add(&c[0], &sum)
        } else {
            v[i] = sum
        }
    }

    //Random element does not currently have a bounded l_inf norm
    let norm_bound: BigInt = BigInt::from(2_i32) ^ &BigInt::from(256_i32);
    let t: Vec<Polynomial> = v
        .iter()
        .map(|v_i| {
            rq.add(
                v_i,
                &rq.times(
                    &sample_from_uniform(&norm_bound, params.n),
                    &params.t,
                ),
            )
        }) // norm_bound is placeholder, since q needs to be a lot higher for this to work properly
        .collect();

    let t_prime = t
        .iter()
        .fold(polynomial![0], |acc, elem| rq.add(&acc, elem));

    // Compute msg minus q if x > q/2
    let msg_minus_q = Polynomial::from(
        t_prime.coefficients()
            .map(|x| {
                if x > &(&rq.q / 2_i32) {
                    x - &rq.q
                } else {
                    x.to_owned()
                }
            })
            .collect::<Vec<BigInt>>(),
    )
    .trim_res();

    msg_minus_q.modulo(&params.t)
}

pub fn diag(params: &Parameters, a: BigInt) -> Polynomial {
    Polynomial::new(vec![a; params.n])
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
        let params = secure_params();
        player_array = distribute_keys(&params, player_array);

        let pk = player_array[0].pk.clone();

        let msg = polynomial![0];
        let cipher = encrypt(&params, msg, &pk);
        let decrypted = ddec(&params, &player_array, cipher);

        assert_eq!(decrypted, polynomial![0]);

        let msg2 = polynomial![5, 7, 3];
        let cipher2 = encrypt(&params, msg2, &pk);
        let decrypted2 = ddec(&params, &player_array, cipher2);

        assert_eq!(decrypted2, polynomial![5, 7, 3]);
    }
}
