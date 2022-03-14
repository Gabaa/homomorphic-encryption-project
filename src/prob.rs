use crate::poly::Polynomial;
use num::{BigInt, Zero};
use probability::prelude::{source, Gaussian, Independent};
use rand::{distributions::Uniform, rngs::OsRng, Rng, RngCore};

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
            .map(|x| BigInt::from(x.round() as i128))
            .collect::<Vec<BigInt>>(),
    )
}

/// Returns n samples from a Uniform distribution in the interval [0, q)
pub fn sample_from_uniform(q: &BigInt, n: usize) -> Polynomial {
    let rng = OsRng;
    let range = Uniform::new(BigInt::zero(), q);

    let samples: Vec<BigInt> = rng.sample_iter(&range).take(n).collect();

    Polynomial::from(samples)
}
