use std::cmp;

pub type Polynomial = Vec<i128>;

pub struct Rq {
    q: i128,
    modulo: Polynomial,
}

impl Rq {
    pub fn new(q: i128, modulo: Polynomial) -> Rq {
        Rq { q: q, modulo: modulo }
    }
    // Returns the remainder found by doing polynomial long division
    pub fn reduce(&self, pol: &Polynomial) -> Polynomial {
        //let q = 0;
        let mut r = pol.clone();

        while r != vec![0] && r.len() >= self.modulo.len() {
            let t = r[0] / self.modulo[0];
            //let q = q + t;
            r = pol_add(&r, &pol_neg(&pol_times(&self.modulo, t)));
        };
        // Reduce coefficients mod q
        mod_coefficients(&r, self.q)
    }

    pub fn add(&self, a: &Polynomial, b: &Polynomial) -> Polynomial {
        let res = pol_add(a, b);
        self.reduce(&res)
    }

    pub fn times(&self, pol: &Polynomial, t: i128) -> Polynomial {
        let res = pol_times(pol, t);
        self.reduce(&res)
    }

    pub fn neg(&self, pol: &Polynomial) -> Polynomial {
        let res = pol_neg(pol);
        self.reduce(&res)
    }

    pub fn mul(&self, a: &Polynomial, b: &Polynomial) -> Polynomial {
        let res = pol_mul(a, b);
        self.reduce(&res)
    }
}

pub fn mod_coefficients(pol: &Polynomial, modulus: i128) -> Polynomial {
    pol.iter().map(|x| x.rem_euclid(modulus)).collect()
}

pub fn pol_add(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let max = cmp::max(a.len(), b.len());
    let mut res = vec![0; max];

    for i in 0..a.len() {
        res[i] += a[i];
    };
    for i in 0..b.len() {
        res[i] += b[i];
    };

    pol_trim_res(&res)
}

pub fn pol_mul(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let mut res = vec![0; a.len() + b.len() - 1];

    for i in 0..a.len() {
        for j in 0..b.len() {
            res[i + j] += a[i] * b[j]
        }
    }

    pol_trim_res(&res)
}

pub fn pol_times(pol: &Polynomial, t: i128) -> Polynomial {
    pol.iter().map(|x| x * t ).collect()
}

pub fn pol_neg(pol: &Polynomial) -> Polynomial {
    pol.iter().map(|x| -x ).collect()
}

pub fn pol_trim_res(pol: &Polynomial) -> Polynomial {
    let mut res = pol.clone();
    while let Some(true) = res.first().map(|x| *x == 0) {
        res.remove(0);
    };
    res
}