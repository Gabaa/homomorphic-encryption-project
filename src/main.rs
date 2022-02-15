mod encryption;
mod prob;
mod quotient_ring;

use rand::rngs::OsRng;

use crate::encryption::Parameters;
use crate::quotient_ring::pretty_pol;

fn main() {
    let params = default_params();

    let (pk, sk) = encryption::generate_key_pair(&params);

    let msg = vec![1];
    // let (a0, b0) = &pk;
    let encrypted_msg = encryption::encrypt(&params, msg, &pk);
    println!("c_0: {}", pretty_pol(&encrypted_msg.0));
    println!("c_1: {}", pretty_pol(&encrypted_msg.1));

    let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk);
    println!("decrypted: {:?}", pretty_pol(&decrypted_msg));
}

fn default_params() -> Parameters {
    let q = 65537; // TODO: don't hardcode this
    let modulo_poly = vec![1, 0, 0, 0, 1]; // TODO: don't hardcode this (get it from n)

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
    use super::{default_params, encryption};

    #[test]
    fn run_many_times() {
        let params = default_params();

        for i in 0..1000 {
            let (pk, sk) = encryption::generate_key_pair(&params);

            let msg = vec![1];
            let encrypted_msg = encryption::encrypt(&params, msg, &pk);
            let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk);

            assert_eq!(decrypted_msg, vec![1], "");
        }
    }
}

/* fn print_polynomial(p: &Vec<BigInt>) {
    println!("[ {} ]",
        p.iter()
            .map(|c| format!("{}", c))
            .collect::<Vec<String>>()
            .join(", ")
    );
} */
