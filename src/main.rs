mod encryption;
mod poly;
mod prob;
mod quotient_ring;

use crate::encryption::Parameters;
use crate::poly::Polynomial;

fn main() {
    let params = default_params();

    let (pk, sk) = encryption::generate_key_pair(&params);

    let msg = Polynomial(vec![1]);

    let encrypted_msg = encryption::encrypt(&params, msg, &pk);
    println!("c_0: {}", encrypted_msg.0);
    println!("c_1: {}", encrypted_msg.1);

    let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk);
    println!("decrypted: {}", decrypted_msg.unwrap());
}

fn default_params() -> Parameters {
    let q = 65537; // TODO: don't hardcode this
    let modulo_poly = Polynomial(vec![1, 0, 0, 0, 1]); // TODO: don't hardcode this (get it from n)

    let quotient_ring = quotient_ring::Rq::new(q, modulo_poly);
    return Parameters {
        quotient_ring,
        r: 1.0,
        r_prime: 2.0,
        n: 4,
        q,
        t: 7,
    };
}

#[cfg(test)]
mod tests {
    use crate::poly::Polynomial;

    use super::{default_params, encryption, prob};

    #[test]
    fn decrypt_and_encrypt_many_times() {
        let params = default_params();

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg = Polynomial(vec![1]);
            let encrypted_msg = encryption::encrypt(&params, msg, &pk);
            let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk).unwrap();

            assert_eq!(decrypted_msg, Polynomial(vec![1]));
        }
    }

    #[test]
    fn decrypt_and_encrypt_random_messages() {
        let params = default_params();

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg = Polynomial(prob::sample_from_uniform(params.t - 1, params.n)).trim_res();
            let expected = msg.clone();

            let encrypted_msg = encryption::encrypt(&params, msg, &pk);
            let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk).unwrap();

            assert_eq!(decrypted_msg, expected);
        }
    }
}
