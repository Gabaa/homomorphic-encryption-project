use std::{
    cmp,
    fmt::Display,
    ops::{Add, Mul, Neg, Rem},
};

use num::{bigint::ToBigInt, BigInt, Zero};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Polynomial(pub Vec<BigInt>);

impl Polynomial {
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

    pub fn l_inf_norm(&self) -> BigInt {
        let mut norm = BigInt::zero();
        for i in 0..self.degree() + 1 {
            let (sign, data) = self.0[i].into_parts();
            let abs_value = data.to_bigint().expect("unreachable");
            norm = cmp::max(norm, abs_value);
        }
        norm
    }
}

impl Add for Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Self) -> Self::Output {
        let max = cmp::max(self.degree(), rhs.degree());
        let mut res = vec![BigInt::zero(); max + 1];

        for i in 0..self.degree() + 1 {
            res[i] += self.0[i];
        }
        for i in 0..rhs.degree() + 1 {
            res[i] += rhs.0[i];
        }

        Polynomial(res).trim_res()
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    fn neg(self) -> Self::Output {
        let negated = Polynomial(self.0.iter().map(|x| -x).collect());
        negated.trim_res()
    }
}

impl Mul for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut res = vec![BigInt::zero(); self.degree() + rhs.degree() + 1];

        for i in 0..self.degree() + 1 {
            for j in 0..rhs.degree() + 1 {
                res[i + j] += self.0[i] * rhs.0[j]
            }
        }

        let pol = Polynomial(res);
        pol.trim_res()
    }
}

impl Mul<BigInt> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: BigInt) -> Self::Output {
        let pol = Polynomial(self.0.iter().map(|x| x * rhs).collect());
        pol.trim_res()
    }
}

impl Rem<BigInt> for Polynomial {
    type Output = Polynomial;

    fn rem(self, rhs: BigInt) -> Self::Output {
        let mod_pol = Polynomial(self.0.iter().map(|x| x.rem_euclid(rhs)).collect());
        mod_pol.trim_res()
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

    use crate::poly::Polynomial;

    #[test]
    fn test_add() {
        let rhs = Polynomial(vec![1, 2]);
        let lhs = Polynomial(vec![0]);
        assert_eq!(rhs + lhs, Polynomial(vec![1, 2]));

        let rhs_2 = Polynomial(vec![17, 42]);
        let lhs_2 = Polynomial(vec![73, 100]);
        assert_eq!(rhs_2 + lhs_2, Polynomial(vec![90, 142]));

        let rhs_3 = Polynomial(vec![0, 2, 3, 6, 3, 2]);
        let lhs_3 = Polynomial(vec![2, 4, 0, 5]);
        assert_eq!(rhs_3 + lhs_3, Polynomial(vec![2, 6, 3, 11, 3, 2]));
    }

    #[test]
    fn test_mul() {
        let rhs = Polynomial(vec![3, 5]);
        let lhs = Polynomial(vec![2, 7, 2]);
        assert_eq!(rhs * lhs, Polynomial(vec![6, 31, 41, 10]));

        let rhs_2 = Polynomial(vec![3, 2, 0, 5]);
        let lhs_2 = Polynomial(vec![0, 1, 8, 2]);
        assert_eq!(rhs_2 * lhs_2, Polynomial(vec![0, 3, 26, 22, 9, 40, 10]));

        let rhs_3 = Polynomial(vec![1]);
        let lhs_3 = Polynomial(vec![1, 6, 2, 1]);
        assert_eq!(rhs_3 * lhs_3, Polynomial(vec![1, 6, 2, 1]));

        let rhs_4 = Polynomial(vec![17, 3, 1, 0]);
        let lhs_4 = Polynomial(vec![0]);
        assert_eq!(rhs_4 * lhs_4, Polynomial(vec![0]));
    }

    #[test]
    fn test_mul_scalar() {
        let poly = Polynomial(vec![42, 10, 30]);
        let scalar = 7;
        assert_eq!(
            poly * scalar,
            Polynomial(vec![42 * scalar, 10 * scalar, 30 * scalar])
        );
    }

    #[test]
    fn test_neg() {
        let poly = Polynomial(vec![1, 2]);
        assert_eq!(-poly, Polynomial(vec![-1, -2]));

        let poly2 = Polynomial(vec![15, 23, 1, 0, 2]);
        assert_eq!(-poly2, Polynomial(vec![-15, -23, -1, 0, -2]));
    }

    #[test]
    fn test_mod_coefficients() {
        let poly = Polynomial(vec![83, 2, 10, 7, 0, 1, 100]);
        let modulo = 7;
        assert_eq!(poly % modulo, Polynomial(vec![6, 2, 3, 0, 0, 1, 2]));
    }
}
