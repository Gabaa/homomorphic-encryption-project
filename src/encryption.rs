use abstalg::{
    AbelianGroup, Domain, Integers, PolynomialAlgebra, QuotientField, QuotientRing, Semigroup,
};

use crate::quotient_ring::*;
use crate::prob::{sample_from_gaussian, sample_from_uniform};

pub type Polynomial = Vec<i128>;
type SecretKey = Polynomial;
type PublicKey = (Polynomial, Polynomial);

pub struct Parameters {
    pub quotient_ring: Rq,
    pub t: i128,
    pub r: f64,
    pub r_prime: f64,
    pub n: usize,
    pub q: i128,
}

pub fn encrypt(params: &Parameters, m: Polynomial, pk: &(Polynomial, Polynomial)) -> (Polynomial, Polynomial) {
    let rq = &params.quotient_ring;

    let (a0, b0) = pk;

    let v: Polynomial = sample_from_gaussian(params.r, params.n);
    let e_prime: Polynomial = sample_from_gaussian(params.r, params.n);
    let e_prime_prime: Polynomial = sample_from_gaussian(params.r_prime, params.n);

    let a0_mul_v = rq.mul(&a0, &v);
    let t_mul_e_prime = rq.times(&e_prime, params.t);
    let a = rq.add(&a0_mul_v, &t_mul_e_prime);

    let b0_mul_v = rq.mul(&b0, &v);
    let t_mul_e_prime_prime = rq.times(&e_prime_prime, params.t);
    let b = rq.add(&b0_mul_v, &t_mul_e_prime_prime);

    let c0 = rq.add(&b, &m);
    //println!("a: {:?}", a);
    let c1 = rq.neg(&a);
    //println!("c1: {:?}", c1);
    (c0, c1)
}

pub fn decrypt(params: &Parameters, c: (Polynomial, Polynomial), sk: &Polynomial) -> Polynomial {
    let rq = &params.quotient_ring;

    let (c0, c1) = c;
    let tmp = rq.mul(&c1, &sk); 
    let msg = rq.add(&c0, &tmp);
    mod_coefficients(&msg, params.t)
}

/* fn print_polynomial(p: &Vec<BigInt>) {
    println!("[ {} ]",
        p.iter()
            .map(|c| format!("{}", c))
            .collect::<Vec<String>>()
            .join(", ")
    );
} */

pub fn generate_key_pair(params: &Parameters) -> (PublicKey, SecretKey) {
    let Parameters {
        quotient_ring: rq,
        t,
        r,
        r_prime: _,
        n,
        q,
    } = params;

    let sk: Polynomial = sample_from_gaussian(*r, *n);
    let a0: Polynomial = sample_from_uniform(*q, *n);
    let e0: Polynomial = sample_from_gaussian(*r, *n);

    let elem1 = rq.mul(&a0, &sk);
    let elem2 = rq.times(&e0, *t);
    let pk = (a0, rq.add(&elem1, &elem2));

    (pk, sk)
}

#[cfg(test)]
mod tests {

    #[test]
    fn should_do_x() {
        assert_eq!(2, 1);
    }
}