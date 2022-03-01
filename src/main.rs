mod encryption;
mod poly;
mod prob;
mod quotient_ring;

use crate::encryption::Parameters;
use crate::poly::Polynomial;

fn main() {
    let params = default_params();

    //Construct noisy params
    let noisy_params = encryption::new_params(65537, (2.0 as i32).pow(10) as f64, (2.0 as i32) as f64, 4, 7);

    let (pk, sk) = encryption::generate_key_pair(&params);
    let msg = Polynomial(vec![1]);

    let encrypted_msg = encryption::encrypt(&params, msg, &pk);
    println!("{:?}", encrypted_msg);

    let noisy_ciphertext = encryption::drown_noise(&params, &noisy_params, encrypted_msg, pk);
    println!("{:?}", noisy_ciphertext);

    let decrypted_noisy = encryption::decrypt(&params, noisy_ciphertext, &sk);
    println!("{:?}", decrypted_noisy)
}

fn default_params() -> Parameters {
    return encryption::new_params(65537, 1.0, 2.0, 4, 7)
}

// Loosely based on http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
// security level (quantum): 128 bits
// q: 27 bit prime
// n: 1024
// t: 2
// r: 2 = w * sqrt(log2(1024)) = 0.632 * 3.162
// r_prime: 80 >= 2^(0.632 * log2(1024)) = 2^(0.632 * 10)
fn secure_params() -> Parameters {
    return encryption::new_params(80708963, 2.0, 80.0, 1024, 2)
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

    #[test]
    fn add_ciphertexts() {
        let params = default_params();

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg1 = Polynomial(vec![1, 4]);
            let msg2 = Polynomial(vec![2, 1]);
            let encrypted_msg1 = encryption::encrypt(&params, msg1, &pk);
            let encrypted_msg2 = encryption::encrypt(&params, msg2, &pk);
            let added_encrypted_msg = encryption::add(&params, encrypted_msg1, encrypted_msg2);
            let decrypted_msg = encryption::decrypt(&params, added_encrypted_msg, &sk).unwrap();

            assert_eq!(decrypted_msg, Polynomial(vec![3 % default_params().t, 5 % default_params().t]));
        }
    }

    #[test]
    fn mul_ciphertexts() {
        let params = default_params();

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg1 = Polynomial(vec![2]);
            let msg2 = Polynomial(vec![2]);
            let encrypted_msg1 = encryption::encrypt(&params, msg1, &pk);
            let encrypted_msg2 = encryption::encrypt(&params, msg2, &pk);
            let added_encrypted_msg = encryption::mul(&params, encrypted_msg1, encrypted_msg2);
            let decrypted_msg = encryption::decrypt(&params, added_encrypted_msg, &sk).unwrap();

            assert_eq!(decrypted_msg, Polynomial(vec![4 % default_params().t]));
        }
    }
}
