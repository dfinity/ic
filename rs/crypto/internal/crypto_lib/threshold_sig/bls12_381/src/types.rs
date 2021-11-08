//! Threshold signature and DKG types.
// Clippy does not like Arbitrary.  We disable clippy warnings for the whole
// module because they apply to generated code, meaning we can't locally disable
// the warnings (the code is defined in another module).
#![allow(clippy::unit_arg)]

use bls12_381::{G1Projective, G2Projective, Scalar};
use ic_crypto_internal_bls12381_common as bls;
use zeroize::Zeroize;

// A polynomial is a vector of (usually secret) field elements
// TODO (CRP-310): Consider making the polynomials private again
pub mod polynomial;
pub use polynomial::Polynomial;

// 'PublicCoefficients' is a vector of exponents and is the public version of
// 'polynomial'.
pub mod public_coefficients;
pub use public_coefficients::PublicCoefficients;

#[cfg(test)]
pub mod arbitrary;
mod conversions;
mod generic_traits;

pub(super) type Signature = G1Projective;

pub(super) type IndividualSignature = Signature;

/// A serialized individual BLS signature.
#[derive(Copy, Clone)]
pub struct IndividualSignatureBytes(pub [u8; bls::G1_SIZE]);
ic_crypto_internal_types::derive_serde!(IndividualSignatureBytes, IndividualSignatureBytes::SIZE);
impl IndividualSignatureBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

pub(super) type CombinedSignature = Signature;

/// A serialized combined (threshold-signed) BLS signature.
#[derive(Copy, Clone)]
pub struct CombinedSignatureBytes(pub [u8; bls::G1_SIZE]);
ic_crypto_internal_types::derive_serde!(CombinedSignatureBytes, CombinedSignatureBytes::SIZE);
impl CombinedSignatureBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

pub(super) type SecretKey = Scalar;

/// A serialized BLS secret key.
#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKeyBytes(pub [u8; bls::FR_SIZE]);
ic_crypto_internal_types::derive_serde!(SecretKeyBytes, SecretKeyBytes::SIZE);
impl SecretKeyBytes {
    pub const SIZE: usize = bls::FR_SIZE;
}

/// A wrapped BLS public key.
///
/// Doing this (instead of a type) allows for From conversions in
/// this crate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(pub G2Projective);

/// Interpolation failed because of duplicate x-coordinates.
#[derive(Copy, Clone, Debug)]
pub enum ThresholdError {
    DuplicateX,
}
