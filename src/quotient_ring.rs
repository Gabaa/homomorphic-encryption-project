use crate::poly::Polynomial;

pub struct Rq {
    q: i128,
    modulo: Polynomial,
}

impl Rq {
    pub fn new(q: i128, modulo: Polynomial) -> Rq {
        Rq { q, modulo }
    }

    // Returns the remainder found by doing polynomial long division https://rosettacode.org/wiki/Polynomial_long_division
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

    pub fn times(&self, pol: &Polynomial, t: i128) -> Polynomial {
        let res = pol.clone() * t;
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
    use crate::quotient_ring;

    #[test]
    fn test() {
        assert_eq!(2 + 2, 4);
    }
}

