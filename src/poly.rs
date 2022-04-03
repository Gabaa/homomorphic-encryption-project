use std::{
    cmp,
    fmt::Display,
    ops::{Add, Mul, Neg, Sub},
    slice::Iter,
};

use num::{bigint::ToBigInt, BigInt, One, Zero};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Polynomial(Vec<BigInt>);

impl Polynomial {
    pub fn new(coefficients: Vec<BigInt>) -> Polynomial {
        Polynomial(coefficients)
    }

    pub fn degree(&self) -> usize {
        self.0.len() - 1
    }

    pub fn trim_res(&self) -> Polynomial {
        let mut res = self.clone();
        while let Some(true) = res
            .0
            .last()
            .map(|x| *x == BigInt::zero() && res.degree() > 0)
        {
            res.0.pop();
        }
        res
    }

    pub fn shift_poly(&self, n: usize) -> Polynomial {
        let mut vec = vec![BigInt::zero(); n];
        vec.extend(self.0.clone());
        Polynomial::new(vec)
    }

    pub fn l_inf_norm(&self) -> BigInt {
        let mut norm = BigInt::zero();
        for i in 0..self.degree() + 1 {
            let (_, data) = self.0[i].to_owned().into_parts();
            let abs_value = data.to_bigint().expect("unreachable");
            norm = cmp::max(norm, abs_value);
        }
        norm
    }

    pub fn coefficients(&self) -> Iter<BigInt> {
        self.0.iter()
    }

    pub fn coefficient(&self, index: usize) -> &BigInt {
        &self.0[index]
    }

    pub fn modulo(&self, modulus: &BigInt) -> Polynomial {
        let mod_pol = Polynomial(
            self.coefficients()
                .map(|x| x.modpow(&BigInt::one(), modulus))
                .collect(),
        );
        mod_pol.trim_res()
    }
}

impl<Int: Into<BigInt> + Clone> From<Vec<Int>> for Polynomial {
    fn from(val: Vec<Int>) -> Self {
        Polynomial(val.iter().map(|v| v.to_owned().into()).collect())
    }
}

#[macro_export]
macro_rules! polynomial {
    [ $( $x:expr ),* ] => {
        {
            let coefficients = vec![$(num::BigInt::from($x as i32)),*];
            Polynomial::new(coefficients)
        }
    };
    [ $( $x:expr ),* ; $typ:ty ] => {
        {
            let coefficients = vec![$(num::BigInt::from($x as $typ)),*];
            Polynomial::new(coefficients)
        }
    };
}

impl Add for Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Self) -> Self::Output {
        let max = cmp::max(self.degree(), rhs.degree());
        let mut res = vec![BigInt::zero(); max + 1];

        for (i, coefficient) in self.coefficients().enumerate() {
            res[i] += coefficient;
        }
        for (i, coefficient) in rhs.coefficients().enumerate() {
            res[i] += coefficient;
        }

        Polynomial(res).trim_res()
    }
}

impl Sub for Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: Self) -> Self::Output {
        let max = cmp::max(self.degree(), rhs.degree());
        let mut res = vec![BigInt::zero(); max + 1];

        for (i, coefficient) in self.coefficients().enumerate() {
            res[i] += coefficient;
        }
        for (i, coefficient) in rhs.coefficients().enumerate() {
            res[i] -= coefficient;
        }

        Polynomial(res).trim_res()
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    fn neg(self) -> Self::Output {
        let negated = Polynomial(self.coefficients().map(|x| -x).collect());
        negated.trim_res()
    }
}

impl Mul for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut res = vec![BigInt::zero(); self.degree() + rhs.degree() + 1];

        for i in 0..self.degree() + 1 {
            for j in 0..rhs.degree() + 1 {
                res[i + j] += &self.0[i] * &rhs.0[j]
            }
        }

        let pol = Polynomial(res);
        pol.trim_res()
    }
}

impl<Int> Mul<Int> for Polynomial
where
    Int: Into<BigInt> + Clone,
{
    type Output = Polynomial;

    fn mul(self, rhs: Int) -> Self::Output {
        let pol = Polynomial(
            self.coefficients()
                .map(|x| x * rhs.to_owned().into())
                .collect(),
        );
        pol.trim_res()
    }
}

impl Display for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut res: String = self.0[0].to_string();
        for i in 1..self.degree() + 1 {
            res = res + " + " + &self.0[i].to_string() + "*a^" + &i.to_string()
        }
        write!(f, "{}", res)
    }
}

#[cfg(test)]
mod tests {

    use num::BigInt;

    use crate::poly::Polynomial;

    #[test]
    fn test_add() {
        let rhs = polynomial![1, 2];
        let lhs = polynomial![0];
        assert_eq!(rhs + lhs, polynomial![1, 2]);

        let rhs_2 = polynomial![17, 42];
        let lhs_2 = polynomial![73, 100];
        assert_eq!(rhs_2 + lhs_2, polynomial![90, 142]);

        let rhs_3 = polynomial![0, 2, 3, 6, 3, 2];
        let lhs_3 = polynomial![2, 4, 0, 5];
        assert_eq!(rhs_3 + lhs_3, polynomial![2, 6, 3, 11, 3, 2]);
    }

    #[test]
    fn test_mul() {
        let rhs = polynomial![3, 5];
        let lhs = polynomial![2, 7, 2];
        assert_eq!(rhs * lhs, polynomial![6, 31, 41, 10]);

        let rhs_2 = polynomial![3, 2, 0, 5];
        let lhs_2 = polynomial![0, 1, 8, 2];
        assert_eq!(rhs_2 * lhs_2, polynomial![0, 3, 26, 22, 9, 40, 10]);

        let rhs_3 = polynomial![1];
        let lhs_3 = polynomial![1, 6, 2, 1];
        assert_eq!(rhs_3 * lhs_3, polynomial![1, 6, 2, 1]);

        let rhs_4 = polynomial![17, 3, 1, 0];
        let lhs_4 = polynomial![0];
        assert_eq!(rhs_4 * lhs_4, polynomial![0]);
    }

    #[test]
    fn test_mul_scalar() {
        let poly = polynomial![42, 10, 30];
        let scalar = 7;
        assert_eq!(
            poly * scalar,
            polynomial![42 * scalar, 10 * scalar, 30 * scalar]
        );
    }

    #[test]
    fn test_neg() {
        let poly = polynomial![1, 2];
        assert_eq!(-poly, polynomial![-1, -2]);

        let poly2 = polynomial![15, 23, 1, 0, 2];
        assert_eq!(-poly2, polynomial![-15, -23, -1, 0, -2]);
    }

    #[test]
    fn test_mod_coefficients() {
        let poly = polynomial![83, 2, 10, 7, 0, 1, 100; i32];
        let modulus = BigInt::from(7);
        assert_eq!(poly.modulo(&modulus), polynomial![6, 2, 3, 0, 0, 1, 2]);
    }
}
