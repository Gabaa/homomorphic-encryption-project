use abstalg::{
    AbelianGroup, Domain, Integers, PolynomialAlgebra, QuotientField, QuotientRing, Semigroup,
};

use crate::prob::{sample_from_gaussian, sample_from_uniform};

type BigInt = <Integers as Domain>::Elem;
type Polynomial = Vec<BigInt>;
type SecretKey = Polynomial;
type PublicKey = (Polynomial, Polynomial);

pub fn _encrypt() {
    // TODO: implement this
}

pub fn _decrypt() {
    // TODO: implement this
}

pub struct KeyGenerationParameters {
    pub quotient_ring: QuotientRing<PolynomialAlgebra<QuotientField<Integers>>>,
    pub t: isize,
    pub r: f64,
    pub n: usize,
    pub q: i128,
}

pub fn generate_key_pair(params: KeyGenerationParameters) -> (PublicKey, SecretKey) {
    let KeyGenerationParameters {
        quotient_ring,
        t,
        r,
        n,
        q,
    } = params;
    let poly = quotient_ring.base();

    let sk: Polynomial = sample_from_gaussian(r, n)
        .iter()
        .map(|&i| BigInt::from(i))
        .collect();

    let a0: Polynomial = sample_from_uniform(q, n)
        .iter()
        .map(|&i| BigInt::from(i))
        .collect();

    let e0: Polynomial = sample_from_gaussian(r, n)
        .iter()
        .map(|&i| BigInt::from(i))
        .collect();

    let elem1 = poly.mul(&a0, &sk);
    let elem2 = poly.times(t, &e0);
    let pk = (a0, poly.add(&elem1, &elem2));

    (pk, sk)
}
