//! Offers cryptographically secure pseudorandom number generation (CSPRNG).
use ic_crypto_internal_types::context::{Context, DomainSeparationContext};
use ic_crypto_sha256::Sha256;
use ic_interfaces::crypto::CryptoHashable;
use ic_types::consensus::{RandomBeacon, RandomTape};
use ic_types::Randomness;
use rand::{CryptoRng, Error, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fmt;
use strum_macros::{EnumCount, EnumIter};
use RandomnessPurpose::*;

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
        let seed = Self::seed_from_crypto_hashable(random_beacon);
        Csprng::from_seed_and_purpose(&seed, purpose)
    }

    /// Creates a CSPRNG from the given seed for the given purpose.
    pub fn from_seed_and_purpose(seed: &Randomness, purpose: &RandomnessPurpose) -> Self {
        let mut hasher = Sha256::new();
        hasher.write(&seed.get());
        hasher.write(&purpose.domain_separator());
        Csprng::from_seed(hasher.finish())
    }

    /// Creates a CSPRNG from the given seed.
    fn from_seed(seed: [u8; 32]) -> Self {
        Csprng {
            rng: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Creates a CSPRNG seed from the given random tape.
    ///
    /// The returned seed can be used to create a CSPRNG with
    /// `Csprng::from_seed_and_purpose`.
    pub fn seed_from_random_tape(random_tape: &RandomTape) -> Randomness {
        Csprng::seed_from_crypto_hashable(random_tape)
    }

    /// Creates a CSPRNG seed from the given crypto hashable.
    fn seed_from_crypto_hashable<T: CryptoHashable>(crypto_hashable: &T) -> Randomness {
        let mut hasher = Sha256::new();
        hasher.write(DomainSeparationContext::new(crypto_hashable.domain()).as_bytes());
        crypto_hashable.hash(&mut hasher);
        Randomness::from(hasher.finish())
    }
}

/// The purpose the randomness is used for.
#[derive(Clone, Debug, Eq, PartialEq, EnumCount, EnumIter)]
pub enum RandomnessPurpose {
    CommitteeSampling,
    BlockmakerRanking,
    DkgCommitteeSampling,
    ExecutionThread(u32),
}

const COMMITTEE_SAMPLING_SEPARATOR_BYTE: u8 = 1;
const BLOCKMAKER_RANKING_SEPARATOR_BYTE: u8 = 2;
const DKG_COMMITTEE_SAMPLING_SEPARATOR_BYTE: u8 = 3;
const EXECUTION_THREAD_SEPARATOR_BYTE: u8 = 4;

impl RandomnessPurpose {
    fn domain_separator(&self) -> Vec<u8> {
        match self {
            CommitteeSampling => vec![COMMITTEE_SAMPLING_SEPARATOR_BYTE],
            BlockmakerRanking => vec![BLOCKMAKER_RANKING_SEPARATOR_BYTE],
            DkgCommitteeSampling => vec![DKG_COMMITTEE_SAMPLING_SEPARATOR_BYTE],
            ExecutionThread(thread_id) => {
                let mut bytes = vec![EXECUTION_THREAD_SEPARATOR_BYTE];
                bytes.extend_from_slice(&thread_id.to_be_bytes());
                bytes
            }
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
