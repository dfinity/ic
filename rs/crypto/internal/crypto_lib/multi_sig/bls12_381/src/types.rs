//! BLS12-381 multisignature types.
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)
use ic_crypto_internal_bls12_381_type::{G1Projective, G2Projective, Scalar};
use ic_crypto_secrets_containers::SecretArray;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
pub mod arbitrary;

pub mod conversions;
mod generic_traits;

/// A BLS secret key is a field element.
pub type SecretKey = Scalar;

/// A BLS public key is a curve point in the G2 group.
pub type PublicKey = G2Projective;

/// A BLS combined public key is a curve point in the G2 group.
pub type CombinedPublicKey = G2Projective;

/// A BLS signature is a curve point in the G1 group.
pub type IndividualSignature = G1Projective;

/// A BLS Proof of Possession is a curve point in the G1 group (a
/// domain-separated signature on the public key).
pub type Pop = G1Projective;

/// A BLS multisignature is a curve point in the G1 group.
pub type CombinedSignature = G1Projective;

/// Wrapper for a serialized secret key.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SecretKeyBytes(pub(crate) SecretArray<{ SecretKeyBytes::SIZE }>);
impl SecretKeyBytes {
    pub const SIZE: usize = Scalar::BYTES;

    pub fn new(val: SecretArray<{ SecretKeyBytes::SIZE }>) -> Self {
        Self(val)
    }
}

/// Wrapper for a serialized individual signature.
#[derive(Copy, Clone)]
pub struct IndividualSignatureBytes(pub [u8; IndividualSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(IndividualSignatureBytes, IndividualSignatureBytes::SIZE);
impl IndividualSignatureBytes {
    pub const SIZE: usize = G1Projective::BYTES;
}

/// Wrapper for a serialized proof of possession.
#[derive(Copy, Clone)]
pub struct PopBytes(pub [u8; PopBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PopBytes, PopBytes::SIZE);
impl PopBytes {
    pub const SIZE: usize = G1Projective::BYTES;
}

/// Wrapper for a serialized combined signature.
#[derive(Copy, Clone)]
pub struct CombinedSignatureBytes(pub [u8; CombinedSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(CombinedSignatureBytes, CombinedSignatureBytes::SIZE);
impl CombinedSignatureBytes {
    pub const SIZE: usize = G1Projective::BYTES;
}

/// Wrapper for a serialized public key.
#[derive(Copy, Clone)]
pub struct PublicKeyBytes(pub [u8; PublicKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PublicKeyBytes, PublicKeyBytes::SIZE);
impl PublicKeyBytes {
    pub const SIZE: usize = G2Projective::BYTES;
}
