mod encryption;
mod prob;

use abstalg::{Domain, Integers, PolynomialAlgebra, QuotientField, QuotientRing, ZZ};

use crate::encryption::Parameters;

type BigInt = <Integers as Domain>::Elem;

fn main() {
    // TODO: don't hardcode this
    let q = 311;

    let galois_field = QuotientField::new(ZZ, BigInt::from(q));
    let polynomial_domain = PolynomialAlgebra::new(galois_field);
    let quotient_ring = QuotientRing::new(
        polynomial_domain,
        // TODO: don't hardcode this
        vec![
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
        ],
    );
    let params = Parameters {
        quotient_ring,
        r: 10.0,
        r_prime: 20000.0,
        n: 4,
        q,
        t: 2,
    };

    let (pk, sk) = encryption::generate_key_pair(&params);

    let msg = vec![
        BigInt::from(1),
    ];
    let encrypted_msg = encryption::encrypt(&params, msg, &pk);
    print_polynomial(&encrypted_msg.0);
    print_polynomial(&encrypted_msg.1);

    let decrypted_msg = encryption::decrypt(&params, encrypted_msg, &sk);
    print_polynomial(&decrypted_msg);
}

fn print_polynomial(p: &Vec<BigInt>) {
    println!("[ {} ]",
        p.iter()
            .map(|c| format!("{}", c))
            .collect::<Vec<String>>()
            .join(", ")
    );
}
