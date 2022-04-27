use crate::poly::Polynomial;
use probability::prelude::{source, Gaussian, Independent};
use rand::{rngs::OsRng, RngCore};
use rug::{
    rand::{RandGen, RandState},
    Integer,
};

/// Creating Source to use rand package as source of randomness
struct Source<T>(T);

impl<T: RngCore> source::Source for Source<T> {
    fn read_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
}

/// Returns sample from n-dimensional discrete Gaussian distribution with standard deviation sd.
pub fn sample_from_gaussian(sd: f64, n: usize) -> Polynomial {
    // Using OsRng which reads randomness from the source that the operating system provides, this makes it cryptographically secure
    let mut source = Source(OsRng);

    // Getting samples from non-discrete Gaussian distribution and collecting them in n-dimensional vector.
    let distribution = Gaussian::new(0.0, sd);
    let sampler = Independent(&distribution, &mut source);
    let samples = sampler.take(n).collect::<Vec<_>>();

    // Rounding to make samples discrete
    Polynomial::from(
        samples
            .iter()
            .map(|x| Integer::from(x.round() as i128))
            .collect::<Vec<Integer>>(),
    )
}

/// Implement OsRng adapter for rug::rand
struct OsRngRandGen;

impl RandGen for OsRngRandGen {
    fn gen(&mut self) -> u32 {
        OsRng.next_u32()
    }
}

/// Returns n samples from a Uniform distribution in the interval [0, q)
pub fn sample_from_uniform(q: &Integer, n: usize) -> Polynomial {
    let mut rand_gen = OsRngRandGen;
    let mut rand_state = RandState::new_custom(&mut rand_gen);

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        samples.push(q.to_owned().random_below(&mut rand_state))
    }

    Polynomial::from(samples)
}

pub fn sample_single(t: &Integer) -> Integer {
    let mut rand_gen = OsRngRandGen;
    let mut rand_state = RandState::new_custom(&mut rand_gen);

    t.to_owned().random_below(&mut rand_state)
}
