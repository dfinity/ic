//! BLS12-381 multisignature types.
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)
use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, Scalar};
use ic_crypto_secrets_containers::SecretArray;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
pub mod arbitrary;

pub mod conversions;

/// A BLS secret key is a field element.
pub type SecretKey = Scalar;

/// A BLS public key is a curve point in the G2 group.
pub type PublicKey = G2Affine;

/// A BLS combined public key is a curve point in the G2 group.
pub type CombinedPublicKey = G2Affine;

/// A BLS signature is a curve point in the G1 group.
pub type IndividualSignature = G1Affine;

/// A BLS Proof of Possession is a curve point in the G1 group (a
/// domain-separated signature on the public key).
pub type Pop = G1Affine;

/// A BLS multisignature is a curve point in the G1 group.
pub type CombinedSignature = G1Affine;

/// Wrapper for a serialized secret key.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub(crate) SecretArray<{ SecretKeyBytes::SIZE }>);
impl SecretKeyBytes {
    pub const SIZE: usize = Scalar::BYTES;

    pub fn new(val: SecretArray<{ SecretKeyBytes::SIZE }>) -> Self {
        Self(val)
    }
}

// Note: This is needed to keep sensitive material from getting Debug logged.
impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

/// Wrapper for a serialized individual signature.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct IndividualSignatureBytes(pub [u8; IndividualSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(IndividualSignatureBytes, IndividualSignatureBytes::SIZE);
impl IndividualSignatureBytes {
    pub const SIZE: usize = G1Affine::BYTES;
}

impl fmt::Debug for IndividualSignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

/// Wrapper for a serialized proof of possession.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct PopBytes(pub [u8; PopBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PopBytes, PopBytes::SIZE);
impl PopBytes {
    pub const SIZE: usize = G1Affine::BYTES;
}

impl fmt::Debug for PopBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}

/// Wrapper for a serialized combined signature.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct CombinedSignatureBytes(pub [u8; CombinedSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(CombinedSignatureBytes, CombinedSignatureBytes::SIZE);
impl CombinedSignatureBytes {
    pub const SIZE: usize = G1Affine::BYTES;
}

impl fmt::Debug for CombinedSignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

/// Wrapper for a serialized public key.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct PublicKeyBytes(pub [u8; PublicKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PublicKeyBytes, PublicKeyBytes::SIZE);
impl PublicKeyBytes {
    pub const SIZE: usize = G2Affine::BYTES;
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
