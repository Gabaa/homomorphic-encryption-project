pub mod encryption;
pub mod mpc;
pub mod poly;
pub mod prob;
pub mod protocol;
pub mod quotient_ring;

#[cfg(test)]
mod tests {
    use rug::Integer;

    use super::{encryption, prob};
    use crate::{
        encryption::*, poly::Polynomial, polynomial, prob::sample_from_uniform, quotient_ring::Rq,
    };

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

            let msg =
                prob::sample_from_uniform(&(params.t.to_owned() - Integer::from(1)), params.n)
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
                Polynomial::new(vec![(3_i32 % t).into(), (5_i32 % t).into()])
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

            assert_eq!(decrypted_msg, Polynomial::new(vec![(4_i32 % t).into()]));
        }
    }

    // A little unsure about this one, is this intended behaviour?
    #[test]
    fn mul_with_overflow() {
        let params = secure_params();
        let mut fx_vec = vec![Integer::ZERO; params.n + 1];
        fx_vec[0] = Integer::from(1);
        fx_vec[params.n] = Integer::from(1);
        let fx = Polynomial::from(fx_vec);
        let rt = Rq::new(params.t.clone(), fx);

        let (pk, sk) = encryption::generate_key_pair(&params);

        let a = sample_from_uniform(&params.t, params.n);
        let b = sample_from_uniform(&params.t, params.n);
        let ab = rt.mul(&a, &b);

        let e_a = encrypt(&params, a, &pk);
        let e_b = encrypt(&params, b, &pk);

        let e_c = mul(&params, &e_a, &e_b);

        let c = decrypt(&params, e_c, &sk).unwrap();
        assert_eq!(c, ab);
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
