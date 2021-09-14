//! Reasonably simple type conversions
//!
//! # Byte encoding
//! Types typically have a custom byte encoding.
//! # String encoding
//! Standard base64 is used for conversions from bytes to strings.

use super::*;
use crate::api::threshold_sign_error::ClibThresholdSignError;
use ff::PrimeField;
use ic_crypto_internal_bls12381_common::{
    fr_from_bytes, fr_to_bytes, g1_from_bytes, g1_to_bytes, g2_from_bytes, g2_from_bytes_unchecked,
    g2_to_bytes,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::{
    PublicKeyBytes, ThresholdSigPublicKeyBytesConversionError,
};
use ic_types::crypto::{AlgorithmId, CryptoError};
use pairing::bls12_381::{Fr, FrRepr};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

impl From<&PublicKey> for PublicKeyBytes {
    fn from(public_key: &PublicKey) -> PublicKeyBytes {
        PublicKeyBytes(g2_to_bytes(&public_key.0))
    }
}

impl From<PublicKey> for PublicKeyBytes {
    fn from(public_key: PublicKey) -> PublicKeyBytes {
        PublicKeyBytes::from(&public_key)
    }
}

impl PublicKey {
    /// Deserializes a `PublicKey` from a *trusted* source.
    ///
    /// # Security Notice
    /// This uses the "unchecked" G2 deserialization (no subgroup check),
    /// so should only be used on `PublicKeyBytes` obtained
    /// from a known, trusted source.
    pub fn from_trusted_bytes(
        bytes: &PublicKeyBytes,
    ) -> Result<Self, ThresholdSigPublicKeyBytesConversionError> {
        g2_from_bytes_unchecked(&bytes.0)
            .map_err(|_| ThresholdSigPublicKeyBytesConversionError::Malformed {
                key_bytes: Some(bytes.0.to_vec()),
                internal_error: "Invalid public key".to_string(),
            })
            .map(PublicKey)
    }
}

impl TryFrom<&PublicKeyBytes> for PublicKey {
    type Error = ThresholdSigPublicKeyBytesConversionError;
    fn try_from(bytes: &PublicKeyBytes) -> Result<Self, Self::Error> {
        g2_from_bytes(&bytes.0)
            .map_err(|_| ThresholdSigPublicKeyBytesConversionError::Malformed {
                key_bytes: Some(bytes.0.to_vec()),
                internal_error: "Invalid public key".to_string(),
            })
            .map(PublicKey)
    }
}

impl From<SecretKey> for SecretKeyBytes {
    fn from(key: SecretKey) -> Self {
        Self(fr_to_bytes(&FrRepr::from(key)))
    }
}
impl From<&SecretKey> for SecretKeyBytes {
    fn from(key: &SecretKey) -> Self {
        Self(fr_to_bytes(&FrRepr::from(*key)))
    }
}
impl TryFrom<&SecretKeyBytes> for SecretKey {
    type Error = ClibThresholdSignError;
    fn try_from(bytes: &SecretKeyBytes) -> Result<SecretKey, ClibThresholdSignError> {
        Fr::from_repr(fr_from_bytes(&bytes.0)).map_err(|_| {
            ClibThresholdSignError::MalformedSecretKey {
                algorithm: AlgorithmId::ThresBls12_381,
            }
        })
    }
}

impl From<&IndividualSignature> for IndividualSignatureBytes {
    fn from(signature: &IndividualSignature) -> Self {
        IndividualSignatureBytes(g1_to_bytes(signature))
    }
}
impl From<IndividualSignature> for IndividualSignatureBytes {
    fn from(signature: IndividualSignature) -> Self {
        IndividualSignatureBytes::from(&signature)
    }
}
impl TryFrom<&IndividualSignatureBytes> for IndividualSignature {
    type Error = CryptoError;
    fn try_from(bytes: &IndividualSignatureBytes) -> Result<IndividualSignature, CryptoError> {
        g1_from_bytes(&bytes.0).map_err(|_| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: bytes.0.to_vec(),
            internal_error: "Invalid individual signature".to_string(),
        })
    }
}

impl From<&CombinedSignature> for CombinedSignatureBytes {
    fn from(signature: &CombinedSignature) -> Self {
        CombinedSignatureBytes(g1_to_bytes(signature))
    }
}
impl From<CombinedSignature> for CombinedSignatureBytes {
    fn from(signature: CombinedSignature) -> Self {
        CombinedSignatureBytes::from(&signature)
    }
}
impl TryFrom<&CombinedSignatureBytes> for CombinedSignature {
    type Error = CryptoError;
    fn try_from(bytes: &CombinedSignatureBytes) -> Result<CombinedSignature, CryptoError> {
        g1_from_bytes(&bytes.0).map_err(|_| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: bytes.0.to_vec(),
            internal_error: "Invalid combined signature".to_string(),
        })
    }
}

impl From<SecretKeyBytes> for String {
    fn from(bytes: SecretKeyBytes) -> String {
        base64::encode(&bytes.0[..])
    }
}
impl TryFrom<&str> for SecretKeyBytes {
    type Error = CryptoError;

    fn try_from(string: &str) -> Result<Self, CryptoError> {
        let bytes = base64::decode(string).map_err(|e| CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::ThresBls12_381,
            internal_error: format!("Secret key is not a valid base64 encoded string: {}", e),
        })?;
        if bytes.len() != SecretKeyBytes::SIZE {
            return Err(CryptoError::MalformedSecretKey {
                algorithm: AlgorithmId::ThresBls12_381,
                internal_error: "Secret key length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; SecretKeyBytes::SIZE];
        buffer.copy_from_slice(&bytes);
        Ok(SecretKeyBytes(buffer))
    }
}
impl TryFrom<&String> for SecretKeyBytes {
    type Error = CryptoError;
    fn try_from(string: &String) -> Result<Self, CryptoError> {
        Self::try_from(string as &str)
    }
}

impl From<IndividualSignatureBytes> for String {
    fn from(bytes: IndividualSignatureBytes) -> String {
        base64::encode(&bytes.0[..])
    }
}
impl TryFrom<&str> for IndividualSignatureBytes {
    type Error = CryptoError;

    fn try_from(string: &str) -> Result<Self, CryptoError> {
        let signature = base64::decode(string).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: string.as_bytes().to_vec(),
            internal_error: format!("Signature is not a valid base64 encoded string: {}", e),
        })?;
        if signature.len() != IndividualSignatureBytes::SIZE {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: string.as_bytes().to_vec(),
                internal_error: "Signature length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; IndividualSignatureBytes::SIZE];
        buffer.copy_from_slice(&signature);
        Ok(IndividualSignatureBytes(buffer))
    }
}
impl TryFrom<&String> for IndividualSignatureBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}

impl From<CombinedSignatureBytes> for String {
    fn from(bytes: CombinedSignatureBytes) -> String {
        base64::encode(&bytes.0[..])
    }
}
impl TryFrom<&str> for CombinedSignatureBytes {
    type Error = CryptoError;

    fn try_from(string: &str) -> Result<Self, CryptoError> {
        let signature = base64::decode(string).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: string.as_bytes().to_vec(),
            internal_error: format!("Signature is not a valid base64 encoded string: {}", e),
        })?;
        Self::try_from(&signature)
    }
}

impl TryFrom<&Vec<u8>> for CombinedSignatureBytes {
    type Error = CryptoError;

    fn try_from(sig_bytes: &Vec<u8>) -> Result<Self, CryptoError> {
        if sig_bytes.len() != CombinedSignatureBytes::SIZE {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: sig_bytes.to_owned(),
                internal_error: "Signature length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; CombinedSignatureBytes::SIZE];
        buffer.copy_from_slice(sig_bytes);
        Ok(CombinedSignatureBytes(buffer))
    }
}
impl TryFrom<&String> for CombinedSignatureBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}
