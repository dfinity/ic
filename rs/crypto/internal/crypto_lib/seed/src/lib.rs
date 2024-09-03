//! # Seed
//!
//! The [`Seed`] type encapsulates a crypto variable which can be
//! used to derive additional values (using XMD) or be turned into
//! a random number generator (ChaCha20).

use core::fmt::{self, Debug};
use rand::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod xmd;

pub use xmd::*;

/// The internal length of a Seed
///
/// This must not exceed 8160 bytes due to limitations of XMD
const SEED_LEN: usize = 32;

/// A Seed is a cryptovariable
///
/// A Seed can be converted into an (deterministic) random number generator. It
/// is also possible to derive new distinct Seeds from a source Seed. This
/// derivation also takes a domain separator, so it is possible to derive
/// multiple unrelated Seeds from a single source Seed.
///
/// It is not possible to extract the value of a Seed.
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct Seed {
    value: [u8; SEED_LEN],
}

impl Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed - REDACTED")
    }
}

impl Seed {
    fn new(input: &[u8], domain_separator: &str) -> Self {
        let derived = xmd::<ic_crypto_sha2::Sha256>(input, domain_separator.as_bytes(), SEED_LEN)
            .expect("Unable to derive SEED_LEN bytes from XMD");
        Self {
            value: derived.try_into().expect("Unexpected size"),
        }
    }

    /// Create a Seed from some input string
    ///
    /// If the Seed is intended to be random the input should be at least 256
    /// bits long.
    pub fn from_bytes(value: &[u8]) -> Self {
        Self::new(value, "ic-crypto-seed-from-bytes")
    }

    /// Create a Seed from a random number generator
    ///
    /// The security of the Seed depends on the security of the RNG
    pub fn from_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut rng_output = [0u8; SEED_LEN];
        rng.fill_bytes(&mut rng_output);
        Self::new(&rng_output, "ic-crypto-seed-from-rng")
    }

    /// Derive a new Seed from self
    ///
    /// The domain_separator should be distinct for every derivation
    pub fn derive(&self, domain_separator: &str) -> Self {
        Self::new(&self.value, domain_separator)
    }

    /// Convert a Seed into a random number generator
    ///
    /// The Seed is consumed by this operation
    pub fn into_rng(self) -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed(self.value)
    }
}
