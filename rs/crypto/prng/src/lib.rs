//! Offers cryptographically secure pseudorandom number generation (CSPRNG).
use RandomnessPurpose::*;
use ic_crypto_internal_seed::Seed;
use ic_types::Randomness;
use ic_types::consensus::RandomBeacon;
use ic_types::crypto::randomness_from_crypto_hashable;
use rand::{Rng, TryCryptoRng, TryRng};
use rand_chacha::ChaCha20Rng;
use std::convert::Infallible;
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
    /// Creates a CSPRNG from the given random beacon for the given purpose.
    pub fn from_random_beacon_and_purpose(
        random_beacon: &RandomBeacon,
        purpose: &RandomnessPurpose,
    ) -> Self {
        let randomness = randomness_from_crypto_hashable(random_beacon);
        Self::from_randomness_and_purpose(&randomness, purpose)
    }

    /// Creates a CSPRNG from the Randomness value for the given purpose.
    pub fn from_randomness_and_purpose(seed: &Randomness, purpose: &RandomnessPurpose) -> Self {
        let seed = Seed::from_bytes(&seed.get());
        let seed_for_purpose = seed.derive(&purpose.domain_separator());
        Csprng::from_seed(seed_for_purpose)
    }

    /// Creates a CSPRNG from the given seed.
    fn from_seed(seed: ic_crypto_internal_seed::Seed) -> Self {
        Csprng {
            rng: seed.into_rng(),
        }
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

// Implementing `TryRng` with an infallible error type automatically implements
// `Rng` and its extension trait `RngExt`, and `TryCryptoRng` adds `CryptoRng`.
impl TryRng for Csprng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.rng.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.rng.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.rng.fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for Csprng {}
