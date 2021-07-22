//! Types for Ed25519 basic signatures
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)
use ic_crypto_secrets_containers::SecretArray;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

mod conversions;
mod generic_traits;

/// A wrapper for Ed25519 secret key bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize)]
pub struct SecretKeyBytes(pub SecretArray<{ SecretKeyBytes::SIZE }>);
impl SecretKeyBytes {
    pub const SIZE: usize = 32;
}

/// A wrapper for Ed25519 public key bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PublicKeyBytes(pub [u8; PublicKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PublicKeyBytes, PublicKeyBytes::SIZE);
impl PublicKeyBytes {
    pub const SIZE: usize = 32;
}

/// A wrapper for Ed25519 signature bytes.
#[derive(Copy, Clone)]
pub struct SignatureBytes(pub [u8; SignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SignatureBytes, SignatureBytes::SIZE);
impl SignatureBytes {
    pub const SIZE: usize = 64;
}
