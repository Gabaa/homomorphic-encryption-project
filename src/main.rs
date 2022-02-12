mod encryption;
mod prob;
mod quotient_ring;

use crate::encryption::Parameters;

fn main() {
    // TODO: don't hardcode this
    let q = 311;

    let quotient_ring = quotient_ring::Rq::new(q, vec![ 1, 0, 0, 0, 1]);
    let params = Parameters {
        quotient_ring,
        r: 10.0,
        r_prime: 20000.0,
        n: 4,
        q,
        t: 7,
    };

    let (pk, sk) = encryption::generate_key_pair(&params);

    let msg = vec![1];
    let (a0, b0) = &pk;
    let encrypted_msg = encryption::encrypt(&params, msg, &pk);
    //print_polynomial(&encrypted_msg.0);
    //print_polynomial(&encrypted_msg.1);

    let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk);
    println!("{:?}", decrypted_msg)
} 

/* fn print_polynomial(p: &Vec<BigInt>) {
    println!("[ {} ]",
        p.iter()
            .map(|c| format!("{}", c))
            .collect::<Vec<String>>()
            .join(", ")
    );
} */
