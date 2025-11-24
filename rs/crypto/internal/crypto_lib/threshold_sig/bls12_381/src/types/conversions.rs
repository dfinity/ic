//! Reasonably simple type conversions
//!
//! # Byte encoding
//! Types typically have a custom byte encoding.
//! # String encoding
//! Standard base64 is used for conversions from bytes to strings.

use super::*;
use crate::api::threshold_sign_error::ClibThresholdSignError;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::{
    PublicKeyBytes, ThresholdSigPublicKeyBytesConversionError,
};
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

impl From<&PublicKey> for PublicKeyBytes {
    fn from(public_key: &PublicKey) -> PublicKeyBytes {
        PublicKeyBytes(public_key.0.serialize())
    }
}

impl From<PublicKey> for PublicKeyBytes {
    fn from(public_key: PublicKey) -> PublicKeyBytes {
        PublicKeyBytes::from(&public_key)
    }
}

impl PublicKey {
    /// Deserializes a `PublicKey` with caching
    ///
    /// This is useful if it is expected that the same point will
    /// be seen again, for example a peer's public key
    pub fn deserialize_cached(
        bytes: &PublicKeyBytes,
    ) -> Result<Self, ThresholdSigPublicKeyBytesConversionError> {
        G2Projective::deserialize_unchecked(&bytes.0)
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
        G2Projective::deserialize(&bytes.0)
            .map_err(|_| ThresholdSigPublicKeyBytesConversionError::Malformed {
                key_bytes: Some(bytes.0.to_vec()),
                internal_error: "Invalid public key".to_string(),
            })
            .map(PublicKey)
    }
}

impl From<SecretKey> for SecretKeyBytes {
    fn from(key: SecretKey) -> Self {
        Self::from(&key)
    }
}
impl From<&SecretKey> for SecretKeyBytes {
    fn from(key: &SecretKey) -> Self {
        let mut bytes = key.serialize();
        Self(ic_crypto_secrets_containers::SecretArray::new_and_zeroize_argument(&mut bytes))
    }
}
impl TryFrom<&SecretKeyBytes> for SecretKey {
    type Error = ClibThresholdSignError;
    fn try_from(bytes: &SecretKeyBytes) -> Result<SecretKey, ClibThresholdSignError> {
        Scalar::deserialize(&bytes.0.expose_secret()).map_err(|_| {
            ClibThresholdSignError::MalformedSecretKey {
                algorithm: AlgorithmId::ThresBls12_381,
            }
        })
    }
}

impl From<&IndividualSignature> for IndividualSignatureBytes {
    fn from(signature: &IndividualSignature) -> Self {
        IndividualSignatureBytes(signature.serialize())
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
        G1Projective::deserialize(&bytes.0).map_err(|_| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: bytes.0.to_vec(),
            internal_error: "Invalid individual signature".to_string(),
        })
    }
}

impl From<&CombinedSignature> for CombinedSignatureBytes {
    fn from(signature: &CombinedSignature) -> Self {
        CombinedSignatureBytes(signature.serialize())
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
        G1Projective::deserialize(&bytes.0).map_err(|_| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: bytes.0.to_vec(),
            internal_error: "Invalid combined signature".to_string(),
        })
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
