//! Simple signature types
use ic_crypto_secrets_containers::SecretVec;
use ic_types::crypto::{AlgorithmId, CryptoError};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The size of a secp256r1 field element (256 bits, 32 bytes)
pub const FIELD_SIZE: usize = 32;

/// ECDSA secp256r1 secret key bytes
///
/// An unsigned big integer in DER-encoding.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub SecretVec);

/// ECDSA secp256r1 public key bytes, in uncompressed format
///
/// The public key is a point (x, y) on secp256r1, uncompressed.
/// Affine coordinates of the public key.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct PublicKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);
impl PublicKeyBytes {
    // 1-byte prefix + 2 coordinates.
    pub const SIZE: usize = 1 + 2 * FIELD_SIZE;
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", base64::encode(&self.0[..]))
    }
}

// From vector of bytes.
impl From<Vec<u8>> for PublicKeyBytes {
    fn from(key: Vec<u8>) -> Self {
        PublicKeyBytes(key)
    }
}

/// ECDSA secp256r1 signature
///
/// Signature consists of two unsigned big integers (r,s), each of FIELD_SIZE
/// bytes, concatenated yielding exactly SignatureBytes::SIZE bytes.
///
/// SignatureBytes holds raw bytes (rather than DER-encoding, which is preferred
/// by OpenSSL), as this is a requirement for the intended use of verification
/// of signatures created by Web Crypto API.
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
                algorithm: AlgorithmId::EcdsaP256,
                sig_bytes: sig,
                internal_error: format!(
                    "ECDSA signature must have {} bytes, got {}.",
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
