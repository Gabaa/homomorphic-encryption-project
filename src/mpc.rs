use crate::prob::sample_from_uniform;
use crate::Parameters;
use crate::poly::*;
use crate::encryption::*;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Player {
    sk_i: Polynomial,
    pk: PublicKey
}

#[allow(dead_code)]
impl Player {
    pub fn new() -> Player {
        return Player {
            sk_i: Polynomial(vec![0]),
            pk: (Polynomial(vec![0]), Polynomial(vec![0]))
        }
    }

    pub fn broadcast() {
        todo!();
    }
}

// Function for functionality in Fkey_gen figure 2 of the MPC article.
pub fn key_gen(params: &Parameters, mut players: Vec<Player>) -> Vec<Player> {
    // set sk and pk for the first n-1 players.
    let (pk, sk) = generate_key_pair(&params);
    for i in 0..players.len() - 1 {
        players[i].sk_i = Polynomial(sample_from_uniform(params.q, params.n));
        players[i].pk = pk.clone();
    }
    // set sk and pk for the n'th player.
    let mut sk_n = sk;
    let amount_of_players = players.len();
    for i in 0..amount_of_players - 1 {
        sk_n = sk_n + (-players[i].sk_i.clone())
    }
    players[amount_of_players - 1].sk_i = sk_n;
    players[amount_of_players - 1].pk = pk.clone();

    players
}

#[cfg(test)]
mod tests {
    use crate::encryption::*;
    use super::*; 
    
    #[test]
    fn mpc_example_with_5_players() {
        let mut player_array = vec![Player::new(); 5];
        let params = Parameters::default();
        key_gen(&params, player_array);
    }

    #[test]
    fn test_all_players_pk_are_equal() {
        let mut player_array = vec![Player::new(); 5];
        let params = Parameters::default();
        player_array = key_gen(&params, player_array);

        let pk = player_array[0].pk.clone();
        for i in 1..5 {
            assert_eq!(player_array[i].pk, pk);
        }
    }

    #[test]
    fn test_sk_shares_are_correct() {
        let mut player_array = vec![Player::new(); 5];
        let params = Parameters::default();
        player_array = key_gen(&params, player_array);

        let mut sk = Polynomial(vec![0]);
        let pk = player_array[0].pk.clone();
        for i in 0..5 {
            sk = sk + player_array[i].sk_i.clone();
        }

        let msg = Polynomial(vec![0]);
        let cipher = encrypt(&params, msg, &pk);
        let decrypted = decrypt(&params, cipher, &sk).unwrap();
        
        assert_eq!(decrypted, Polynomial(vec![0]));
    }

    #[test]
    fn test_if_one_sk_i_is_missing_decryption_fails() {
        let mut player_array = vec![Player::new(); 5];
        let params = Parameters::default();
        player_array = key_gen(&params, player_array);

        let mut sk = Polynomial(vec![0]);
        let pk = player_array[0].pk.clone();
        for i in 0..4 {
            sk = sk + player_array[i].sk_i.clone();
        }

        let msg = Polynomial(vec![0]);
        let cipher = encrypt(&params, msg, &pk);
        let decrypted = decrypt(&params, cipher, &sk).unwrap();
        
        assert_ne!(decrypted, Polynomial(vec![0]));
    }

}