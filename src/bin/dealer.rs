use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
};

use homomorphic_encryption_project::{
    encryption::{generate_key_pair, Parameters, PublicKey, SecretKey},
    prob::sample_from_uniform,
    protocol::{KeyMaterial, PrepMessage},
};

const NUM_PLAYERS: usize = 2;

/// A black box that facilitates the communication for the Dealer.
trait DealerFacilitator {
    /// Wait until all players have connected and sent the "Start" message.
    fn wait_until_ready(&mut self) -> io::Result<()>;
    /// Return the number of players currently connected.
    fn player_count(&self) -> usize;
    /// Send the public key and secret key shares to all players.
    fn send_key_material(&mut self, key_materials: Vec<KeyMaterial>) -> io::Result<()>;
}

struct DealerFacilitatorImpl {
    players: Vec<SocketAddr>,
}

impl DealerFacilitatorImpl {
    fn new() -> Self {
        Self { players: vec![] }
    }
}

impl DealerFacilitator for DealerFacilitatorImpl {
    fn wait_until_ready(&mut self) -> io::Result<()> {
        let listener = TcpListener::bind("localhost:9000")?;
        println!("Ready to receive connections...");

        while NUM_PLAYERS > self.players.len() {
            let (stream, _) = listener.accept().unwrap();
            let msg: PrepMessage = serde_json::from_reader(stream).unwrap();
            let new_player = match msg {
                PrepMessage::Start(player_addr) => player_addr,
                _ => panic!("Expected Start message, got {:?}", msg),
            };
            println!("{} is ready to start.", new_player);

            // Send all existing players to the new player
            for player in &self.players {
                let msg = PrepMessage::PlayerConnected(*player);
                let stream = TcpStream::connect(new_player).unwrap();
                serde_json::to_writer(stream, &msg).unwrap();
            }

            self.players.push(new_player);

            // Send the new player to all players (including the new player himself)
            for player in &self.players {
                let msg = PrepMessage::PlayerConnected(new_player);
                let stream = TcpStream::connect(player).unwrap();
                serde_json::to_writer(stream, &msg).unwrap();
            }
        }

        println!("{} players have connected.", NUM_PLAYERS);

        Ok(())
    }

    fn player_count(&self) -> usize {
        self.players.len()
    }

    fn send_key_material(&mut self, key_materials: Vec<KeyMaterial>) -> io::Result<()> {
        for (player, key_material) in self.players.iter().zip(key_materials) {
            let msg = PrepMessage::KeyMaterial(key_material);
            let stream = TcpStream::connect(player).unwrap();
            serde_json::to_writer(stream, &msg).unwrap();
        }

        Ok(())
    }
}

fn main() -> io::Result<()> {
    let mut facilitator = DealerFacilitatorImpl::new();

    println!("Generating and distributing key material...");
    let params = Parameters::default();
    let (pk, sk) = generate_key_pair(&params);
    distribute_keys(&mut facilitator, pk, sk, &params)
}

/// Function for functionality in Fkey_gen figure 2 of the MPC article.
fn distribute_keys<Facilitator>(
    facilitator: &mut Facilitator,
    pk: PublicKey,
    sk: SecretKey,
    params: &Parameters,
) -> io::Result<()>
where
    Facilitator: DealerFacilitator,
{
    facilitator.wait_until_ready()?;

    let rq = &params.quotient_ring;
    let n = facilitator.player_count();

    let mut key_materials = vec![];

    // set sk shares and pk for the first n-1 players.
    for _ in 0..n - 1 {
        key_materials.push(KeyMaterial {
            pk: pk.clone(),
            sk_i1: sample_from_uniform(&rq.q, params.n),
            sk_i2: sample_from_uniform(&rq.q, params.n),
        });
    }

    // set sk shares and pk for the n'th player.
    let mut sk_n2 = rq.mul(&sk, &sk);
    let mut sk_n1 = sk;

    for key_material in &key_materials {
        sk_n1 = rq.sub(&sk_n1, &key_material.sk_i1);
        sk_n2 = rq.sub(&sk_n2, &key_material.sk_i2);
    }

    key_materials.push(KeyMaterial {
        sk_i1: sk_n1,
        sk_i2: sk_n2,
        pk,
    });

    // Send all key material
    facilitator.send_key_material(key_materials)
}

#[cfg(test)]
mod tests {
    use homomorphic_encryption_project::{
        encryption::{decrypt, encrypt},
        poly::Polynomial,
        polynomial,
    };

    use super::*;

    #[test]
    fn send_correct_pk() {
        let mut facilitator = TestDealerFacilitator {
            player_count: NUM_PLAYERS,
            key_materials: None,
        };

        let params = Parameters::default();
        let (pk, sk) = generate_key_pair(&params);
        let pk_clone = pk.clone();
        distribute_keys(&mut facilitator, pk, sk, &params).unwrap();

        for key_material in &facilitator.key_materials.unwrap() {
            assert_eq!(pk_clone, key_material.pk);
        }
    }

    #[test]
    fn send_correct_sk_shares() {
        let mut facilitator = TestDealerFacilitator {
            player_count: NUM_PLAYERS,
            key_materials: None,
        };

        let params = Parameters::default();
        let rq = &params.quotient_ring;
        let (pk, sk) = generate_key_pair(&params);
        let pk_clone = pk.clone();
        distribute_keys(&mut facilitator, pk, sk, &params).unwrap();

        let key_materials = facilitator.key_materials.unwrap();
        let mut s = polynomial![0];
        for key_material in &key_materials {
            s = rq.add(&s, &key_material.sk_i1)
        }

        let msg = polynomial![0];
        let cipher = encrypt(&params, msg, &pk_clone);
        let decrypted = decrypt(&params, cipher, &s);

        assert_eq!(decrypted.unwrap(), polynomial![0]);
        // At this point we know that s = sk

        let s_mul_s = rq.mul(&s, &s);

        let mut s_mul_s_from_players = polynomial![0];
        for key_material in &key_materials {
            s_mul_s_from_players = rq.add(&s_mul_s_from_players, &key_material.sk_i2)
        }

        assert_eq!(s_mul_s, s_mul_s_from_players);
    }

    struct TestDealerFacilitator {
        player_count: usize,
        key_materials: Option<Vec<KeyMaterial>>,
    }

    impl DealerFacilitator for TestDealerFacilitator {
        fn wait_until_ready(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn player_count(&self) -> usize {
            self.player_count
        }

        fn send_key_material(&mut self, key_materials: Vec<KeyMaterial>) -> io::Result<()> {
            self.key_materials = Some(key_materials);
            Ok(())
        }
    }
}
