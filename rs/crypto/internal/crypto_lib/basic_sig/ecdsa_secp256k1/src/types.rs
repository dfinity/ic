//! Types for ECDSA secp256k1 signatures
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

mod conversions;
mod generic_traits;

/// The size of the secp256k1 field (256 bits, 32 bytes)
pub const FIELD_SIZE: usize = 32;

// NOTE: PublicKeyBytes, SecretKeyDerBytes, use Vec<u8>
// (rather than [u8; <KEY_SIZE>]) for convenience and to avoid copying,
// as Rust OpenSSL works mostly Vec<u8>.

/// ECDSA secp256k1 secret key bytes.
///
/// An unsigned big integer in DER-encoding.
#[derive(Zeroize, Serialize, Deserialize)]
pub struct SecretKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// ECDSA secp256k1 public key bytes, in uncompressed format
///
/// The public key is a point (x, y) on secp256k1, uncompressed.
/// Affine coordinates of the public key.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PublicKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);
impl PublicKeyBytes {
    // 1-byte prefix + 2 coordinates.
    pub const SIZE: usize = 1 + 2 * FIELD_SIZE;
}

/// ECDSA secp256k1 signature
///
/// Signature consists of two unsigned big integers (r,s),
/// each of FIELD_SIZE bytes, concatenated yielding exactly
/// SignatureBytes::SIZE bytes.
#[derive(Copy, Clone)]
pub struct SignatureBytes(pub [u8; SignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SignatureBytes, SignatureBytes::SIZE);

impl SignatureBytes {
    pub const SIZE: usize = 2 * FIELD_SIZE;
}
