mod encryption;
mod mpc;
mod poly;
mod prob;
mod quotient_ring;

use crate::encryption::Parameters;
use crate::poly::Polynomial;
use num::{BigInt, One, Zero};

fn main() {
    let params = Parameters::default();

    //Construct noisy params
    let noisy_params =
        Parameters::new::<i32>(65537, 2_u32.pow(2) as f64, 2_u32.pow(10) as f64, 4, 7);

    let (pk, sk) = encryption::generate_key_pair(&params);

    let msg_bob = polynomial![1];
    let msg_alice = polynomial![1];

    let encrypted_msg_bob = encryption::encrypt(&params, msg_bob, &pk);
    let encrypted_msg_alice = encryption::encrypt(&params, msg_alice, &pk);

    let encrypted_res = encryption::mul(&params, &encrypted_msg_bob, &encrypted_msg_alice);
    println!("{:?}", encrypted_res);

    let noisy_ciphertext = encryption::drown_noise(&params, &noisy_params, encrypted_res, pk);
    println!("{:?}", noisy_ciphertext);

    let decrypted_noisy = encryption::decrypt(&params, noisy_ciphertext, &sk);
    println!("{:?}", decrypted_noisy)
}

// Loosely based on http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
// security level (quantum): 128 bits
// q: 27 bit prime
// n: 1024
// t: 2
// r: 2 = w * sqrt(log2(1024)) = 0.632 * 3.162
// r_prime: 80 >= 2^(0.632 * log2(1024)) = 2^(0.632 * 10)
#[allow(dead_code)]
fn secure_params() -> Parameters {
    // TODO: Shouldn't hardcode `q`
    Parameters::new(80708963, 2.0, 80.0, 1024, 2)
}

fn mpc_secure_params() -> Parameters {
    // q not accurate, still should reflect real performance
    Parameters::new(80708963, 2.0, 80.0, 12900, 128)
}

#[cfg(test)]
mod tests {
    use num::{BigInt, One};

    use crate::{encryption::Parameters, poly::Polynomial, polynomial};

    use super::{encryption, prob, mpc_secure_params, secure_params};

    #[test]
    fn decrypt_and_encrypt_many_times() {
        let params = Parameters::default();

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let coefficients: Vec<u32> = vec![1];
            let msg = Polynomial::from(coefficients);
            let encrypted_msg = encryption::encrypt(&params, msg, &pk);
            let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk).unwrap();

            assert_eq!(decrypted_msg, polynomial![1]);
        }
    }

    #[test]
    fn decrypt_and_encrypt_random_messages() {
        let params = Parameters::default();

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg = prob::sample_from_uniform(&(params.t.to_owned() - BigInt::one()), params.n)
                .trim_res();
            let expected = msg.clone();

            let encrypted_msg = encryption::encrypt(&params, msg, &pk);
            let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk).unwrap();

            assert_eq!(decrypted_msg, expected);
        }
    }

    #[test]
    fn add_ciphertexts() {
        let params = Parameters::default();
        let t = &params.t;

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg1 = polynomial![1, 4];
            let msg2 = polynomial![2, 1];
            let encrypted_msg1 = encryption::encrypt(&params, msg1, &pk);
            let encrypted_msg2 = encryption::encrypt(&params, msg2, &pk);
            let added_encrypted_msg = encryption::add(&params, &encrypted_msg1, &encrypted_msg2);
            let decrypted_msg = encryption::decrypt(&params, added_encrypted_msg, &sk).unwrap();

            assert_eq!(
                decrypted_msg,
                Polynomial::new(vec![
                    3 % t,
                    5 % t
                ])
            );
        }
    }

    #[test]
    fn mul_ciphertexts() {
        let params = Parameters::default();
        let t = &params.t;

        for _ in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg1 = polynomial![2];
            let msg2 = polynomial![2];
            let encrypted_msg1 = encryption::encrypt(&params, msg1, &pk);
            let encrypted_msg2 = encryption::encrypt(&params, msg2, &pk);
            let added_encrypted_msg = encryption::mul(&params, &encrypted_msg1, &encrypted_msg2);
            let decrypted_msg = encryption::decrypt(&params, added_encrypted_msg, &sk).unwrap();

            assert_eq!(
                decrypted_msg,
                Polynomial::new(vec![4 % t])
            );
        }
    }

    /* #[test]
    fn bench_single_mpc_enc() {
        let params = mpc_secure_params();

        let (pk, _) = encryption::generate_key_pair(&params);
        encryption::encrypt(&params, polynomial![2], &pk);
    } */

    /* #[test]
    fn bench_single_rqmul() {
        let params = mpc_secure_params();
        let rq = &params.quotient_ring;
        let op1 = prob::sample_from_uniform(&rq.q, params.n);
        let op2 = prob::sample_from_uniform(&rq.q, params.n);
        let test = rq.mul(&op1, &op2);
    } */
}
