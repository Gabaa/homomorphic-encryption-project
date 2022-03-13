use num::BigInt;

use crate::poly::Polynomial;

pub struct Rq {
    q: BigInt,
    modulo: Polynomial,
}

impl Rq {
    pub fn new<Int: Into<BigInt>>(q: Int, modulo: Polynomial) -> Rq {
        Rq {
            q: q.into(),
            modulo,
        }
    }

    // Returns the remainder found by doing polynomial long division https://rosettacode.org/wiki/Polynomial_long_division
    // Bug/missing: Reduce actually has a bug that does not impact our case of f(x) = 1 + x^n.
    // The bug occurs when t is not an integer. In this case the algorithm does not terminate.
    // This situation never arises due to the coefficients of f(x) all either being 1 or 0.
    pub fn reduce(&self, pol: &Polynomial) -> Polynomial {
        let mut r = pol.clone();

        while r != Polynomial(vec![0]) && r.degree() >= self.modulo.degree() {
            let t = r.0[r.degree()] / self.modulo.0[self.modulo.degree()];

            let to_shift = -(self.modulo.clone() * t);
            let extra_zeros = vec![0; r.degree() - self.modulo.degree()];
            let shifted_vec = [extra_zeros.as_slice(), to_shift.0.as_slice()].concat();
            r = r + Polynomial(shifted_vec);
        }
        // Reduce coefficients mod q
        r % self.q
    }

    pub fn add(&self, a: &Polynomial, b: &Polynomial) -> Polynomial {
        let res = a.clone() + b.clone();
        self.reduce(&res)
    }

    pub fn times<Int: Into<BigInt>>(&self, pol: &Polynomial, t: Int) -> Polynomial {
        let res = pol.clone() * t.into();
        self.reduce(&res)
    }

    pub fn neg(&self, pol: &Polynomial) -> Polynomial {
        let res = -pol.clone();
        self.reduce(&res)
    }

    pub fn mul(&self, a: &Polynomial, b: &Polynomial) -> Polynomial {
        let res = a.clone() * b.clone();
        self.reduce(&res)
    }
}

#[cfg(test)]
mod tests {

    use crate::poly::Polynomial;
    use crate::quotient_ring::*;

    #[test]
    fn test_reduce() {
        let fx = Polynomial(vec![1, 3]);
        let quot_ring = Rq::new(32, fx);
        let to_reduce = Polynomial(vec![5, 7, 3]);
        assert_eq!(quot_ring.reduce(&to_reduce), Polynomial(vec![3]));

        let fx_2 = Polynomial(vec![1, 0, 1]);
        let quot_ring_2 = Rq::new(32, fx_2);
        let to_reduce_2 = Polynomial(vec![-17, 38, -12, 1]);
        assert_eq!(quot_ring_2.reduce(&to_reduce_2), Polynomial(vec![27, 5]));

        let fx_3 = Polynomial(vec![1, 0, 0, 0, 0, 1]);
        let quot_ring_3 = Rq::new(32, fx_3);
        let to_reduce_3 = Polynomial(vec![13, 2, 5, -1]);
        assert_eq!(
            quot_ring_3.reduce(&to_reduce_3),
            Polynomial(vec![13, 2, 5, 31])
        );
    }

    #[test]
    fn test_add() {
        let fx = Polynomial(vec![1, 0, 1]);
        let quot_ring = Rq::new(32, fx);
        let lhs = Polynomial(vec![3, 6, 4, 2, 1]);
        let rhs = Polynomial(vec![-17, 38, -12, 1]);
        assert_eq!(quot_ring.add(&lhs, &rhs), Polynomial(vec![27, 9]));
    }

    #[test]
    fn test_mul() {
        let fx = Polynomial(vec![1, 0, 1]);
        let quot_ring = Rq::new(32, fx);
        let lhs = Polynomial(vec![3, 5, 0, 8]);
        let rhs = Polynomial(vec![1, 1, 5]);
        assert_eq!(quot_ring.mul(&lhs, &rhs), Polynomial(vec![23, 15]));
    }

    #[test]
    fn test_times() {
        let fx = Polynomial(vec![1, 0, 1]);
        let quot_ring = Rq::new(32, fx);
        let lhs = Polynomial(vec![3, 17, 2, -3, 6]);
        let rhs = 3;
        assert_eq!(quot_ring.times(&lhs, rhs), Polynomial(vec![21, 28]));
    }

    #[test]
    fn test_neg() {
        let fx = Polynomial(vec![1, 0, 1]);
        let quot_ring = Rq::new(32, fx);
        let to_reduce = Polynomial(vec![-13, 4, -2, 6]);
        assert_eq!(quot_ring.neg(&to_reduce), Polynomial(vec![11, 2]));
    }
}
