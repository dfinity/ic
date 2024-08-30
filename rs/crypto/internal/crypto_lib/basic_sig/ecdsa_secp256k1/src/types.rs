//! Types for ECDSA secp256k1 signatures

use ic_crypto_secrets_containers::SecretVec;
use ic_types::crypto::{AlgorithmId, CryptoError};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The size of the secp256k1 field (256 bits, 32 bytes)
pub const FIELD_SIZE: usize = 32;

/// ECDSA secp256k1 secret key bytes.
///
/// RFC5915 DER encoding
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub SecretVec);

/// ECDSA secp256k1 public key bytes, in uncompressed format
///
/// The public key is a point (x, y) on secp256k1, uncompressed.
/// Affine coordinates of the public key.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);
impl PublicKeyBytes {
    // 1-byte prefix + 2 coordinates.
    pub const SIZE: usize = 1 + 2 * FIELD_SIZE;
}

// From vector of bytes.
impl From<Vec<u8>> for PublicKeyBytes {
    fn from(key: Vec<u8>) -> Self {
        PublicKeyBytes(key)
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

/// ECDSA secp256k1 signature
///
/// Signature consists of two unsigned big integers (r,s),
/// each of FIELD_SIZE bytes, concatenated yielding exactly
/// SignatureBytes::SIZE bytes.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct SignatureBytes(pub [u8; SignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SignatureBytes, SignatureBytes::SIZE);

impl SignatureBytes {
    pub const SIZE: usize = 2 * FIELD_SIZE;
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

// From vector of bytes.
impl TryFrom<Vec<u8>> for SignatureBytes {
    type Error = CryptoError;
    fn try_from(sig: Vec<u8>) -> Result<Self, CryptoError> {
        if sig.len() != Self::SIZE {
            let sig_len = sig.len();
            Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::EcdsaSecp256k1,
                sig_bytes: sig,
                internal_error: format!(
                    "SECP256K1 signature must have {} bytes, got {}.",
                    Self::SIZE,
                    sig_len
                ),
            })
        } else {
            let mut bytes = [0u8; Self::SIZE];
            bytes.copy_from_slice(&sig);
            Ok(Self(bytes))
        }
    }
}
