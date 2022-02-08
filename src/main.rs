mod encryption;
mod prob;

use abstalg::{Domain, Integers, PolynomialAlgebra, QuotientField, QuotientRing, ZZ};

use crate::encryption::KeyGenerationParameters;

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
    let params = KeyGenerationParameters {
        quotient_ring,
        r: 10.0,
        n: 4,
        q,
        t: 2,
    };

    let (pk, sk) = encryption::generate_key_pair(params);

    println!("Public key: {:?}", pk);
    println!("Secret key: {:?}", sk);
}
