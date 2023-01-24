use rand::{CryptoRng, Error, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Provides a seeded RNG, where the randomly chosen seed is printed on standard output.
pub fn reproducible_rng() -> impl Rng + CryptoRng {
    ReproducibleRng::new()
}

/// Wraps the logic of [`reproducible_rng`] into a separate struct.
///
/// This is needed when [`reproducible_rng`] cannot be used because its
/// return type `impl Rng + CryptoRng` can only be used as function parameter
/// or as return type
/// (See [impl trait type](https://doc.rust-lang.org/reference/types/impl-trait.html)).
pub struct ReproducibleRng {
    rng: ChaCha20Rng,
}

impl ReproducibleRng {
    pub fn new() -> Self {
        let mut thread_rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        thread_rng.fill(&mut seed);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        println!("Copy the seed below to reproduce the failed test.");
        println!("let seed: [u8; 32] = {:?};", &seed);
        let rng = ChaCha20Rng::from_seed(seed);
        Self { rng }
    }
}

impl Default for ReproducibleRng {
    fn default() -> Self {
        ReproducibleRng::new()
    }
}

impl RngCore for ReproducibleRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for ReproducibleRng {}
