//! Offers cryptographically secure pseudorandom number generation (CSPRNG).
use RandomnessPurpose::*;
use ic_crypto_internal_seed::Seed;
use ic_types::Randomness;
use ic_types::consensus::RandomBeacon;
use ic_types::crypto::crypto_hashable_to_randomness;
use rand::{CryptoRng, Error, RngCore};
use rand_chacha::ChaCha20Rng;
use std::fmt;
use strum_macros::{EnumCount, EnumIter};

#[cfg(test)]
mod tests;

/// A cryptographically secure pseudorandom number generator (CSPRNG).
///
/// The algorithm used to generate random numbers is deterministic but *must*
/// not be considered reproducible because it may be changed (e.g., in future
/// protocol versions) as new evidence of security and performance becomes
/// available.
///
/// The current algorithm used is the ChaCha stream cipher with 20 rounds.
///
/// The trait `rand::SeedableRng` is intentionally not implemented because with
/// `seed_from_u64` it provides a way to (e.g., accidentally) construct a PRNG
/// that is unsuitable for the intended use in cryptography.
#[cfg_attr(test, derive(Clone))]
pub struct Csprng {
    rng: ChaCha20Rng,
}

impl Csprng {
    /// Creates a CSPRNG from the given seed for the given purpose.
    pub fn from_seed_and_purpose(seed: Seed, purpose: &RandomnessPurpose) -> Self {
        let seed_for_purpose = seed.derive(&purpose.domain_separator());
        Csprng {
            rng: seed_for_purpose.into_rng(),
        }
    }

    /// Creates a seed from the given randomness.
    pub fn seed_from_randomness(randomness: &Randomness) -> Seed {
        Seed::from_bytes(&randomness.get())
    }

    /// Creates a seed from the given random beacon.
    pub fn seed_from_random_beacon(random_beacon: &RandomBeacon) -> Seed {
        let randomness = crypto_hashable_to_randomness(random_beacon);
        Csprng::seed_from_randomness(&randomness)
    }
}

/// The purpose the randomness is used for.
#[derive(Clone, Eq, PartialEq, Debug, EnumCount, EnumIter)]
pub enum RandomnessPurpose {
    CommitteeSampling,
    BlockmakerRanking,
    ExecutionThread(u32),
}

impl RandomnessPurpose {
    fn domain_separator(&self) -> String {
        match self {
            CommitteeSampling => "ic-crypto-prng-committee-sampling".to_string(),
            BlockmakerRanking => "ic-crypto-prng-blockmaker-ranking".to_string(),
            ExecutionThread(thread_id) => format!("ic-crypto-prng-execution-thread-{}", thread_id),
        }
    }
}

// Custom Debug implementation that does not expose the internal state
impl fmt::Debug for Csprng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Csprng {{}}")
    }
}

// Implementing `RngCore` automatically implements its extension trait `Rng`
impl RngCore for Csprng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for Csprng {}
