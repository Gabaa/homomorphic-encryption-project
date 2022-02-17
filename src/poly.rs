use std::{
    cmp,
    fmt::Display,
    ops::{Add, Mul, Neg, Rem},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Polynomial(pub Vec<i128>);

impl Polynomial {
    pub fn degree(&self) -> usize {
        return self.0.len() - 1;
    }

    pub fn trim_res(&self) -> Polynomial {
        let mut res = self.clone();
        while let Some(true) = res.0.last().map(|x| *x == 0 && res.degree() > 0) {
            res.0.pop();
        }
        res
    }

    pub fn l_inf_norm(&self) -> i128 {
        let mut norm = 0;
        for i in 0..self.degree() + 1 {
            norm = cmp::max(norm, self.0[i].abs());
        }
        norm
    }
}

impl Add for Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Self) -> Self::Output {
        let max = cmp::max(self.degree(), rhs.degree());
        let mut res = vec![0; max + 1];

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
        let mut res = vec![0; self.degree() + rhs.degree() + 1];

        for i in 0..self.degree() + 1 {
            for j in 0..rhs.degree() + 1 {
                res[i + j] += self.0[i] * rhs.0[j]
            }
        }

        let pol = Polynomial(res);
        pol.trim_res()
    }
}

impl Mul<i128> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: i128) -> Self::Output {
        let pol = Polynomial(self.0.iter().map(|x| x * rhs).collect());
        pol.trim_res()
    }
}

impl Rem<i128> for Polynomial {
    type Output = Polynomial;

    fn rem(self, rhs: i128) -> Self::Output {
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
