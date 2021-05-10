//! BLS12-381 multisignature types.
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)
use ic_crypto_internal_bls12381_common as bls;
use pairing::bls12_381::{FrRepr, G1, G2};
use zeroize::Zeroize;

#[cfg(test)]
pub mod arbitrary;

pub mod conversions;
mod generic_traits;

/// A BLS secret key is a field element.
pub type SecretKey = FrRepr;

/// A BLS public key is a curve point in the G2 group.
pub type PublicKey = G2;

/// A BLS combined public key is a curve point in the G2 group.
pub type CombinedPublicKey = G2;

/// A BLS signature is a curve point in the G1 group.
pub type IndividualSignature = G1;

/// A BLS Proof of Possession is a curve point in the G1 group (a
/// domain-separated signature on the public key).
pub type Pop = G1;

/// A BLS multisignature is a curve point in the G1 group.
pub type CombinedSignature = G1;

/// Wrapper for a serialized secret key.
#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKeyBytes(pub [u8; SecretKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SecretKeyBytes, SecretKeyBytes::SIZE);
impl SecretKeyBytes {
    pub const SIZE: usize = bls::FR_SIZE;
}

/// Wrapper for a serialized individual signature.
#[derive(Copy, Clone)]
pub struct IndividualSignatureBytes(pub [u8; IndividualSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(IndividualSignatureBytes, IndividualSignatureBytes::SIZE);
impl IndividualSignatureBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

/// Wrapper for a serialized proof of possession.
#[derive(Copy, Clone)]
pub struct PopBytes(pub [u8; PopBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PopBytes, PopBytes::SIZE);
impl PopBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

/// Wrapper for a serialized combined signature.
#[derive(Copy, Clone)]
pub struct CombinedSignatureBytes(pub [u8; CombinedSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(CombinedSignatureBytes, CombinedSignatureBytes::SIZE);
impl CombinedSignatureBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

/// Wrapper for a serialized public key.
#[derive(Copy, Clone)]
pub struct PublicKeyBytes(pub [u8; PublicKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PublicKeyBytes, PublicKeyBytes::SIZE);
impl PublicKeyBytes {
    pub const SIZE: usize = bls::G2_SIZE;
}
