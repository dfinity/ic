use super::*;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::TryFrom;

pub mod protobuf;

#[cfg(test)]
mod tests;

impl TryFrom<Vec<u8>> for PublicKeyBytes {
    type Error = CryptoError;

    fn try_from(key: Vec<u8>) -> Result<Self, CryptoError> {
        let array = <[u8; PublicKeyBytes::SIZE]>::try_from(key).map_err(|key| {
            CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::Ed25519,
                internal_error: format!(
                    "Incorrect key length: expected {}, got {}.",
                    PublicKeyBytes::SIZE,
                    key.len()
                ),
                key_bytes: Some(key),
            }
        })?;
        Ok(PublicKeyBytes(array))
    }
}

impl TryFrom<Vec<u8>> for SignatureBytes {
    type Error = CryptoError;

    fn try_from(signature_bytes: Vec<u8>) -> Result<Self, CryptoError> {
        let array = <[u8; SignatureBytes::SIZE]>::try_from(signature_bytes).map_err(|sig| {
            CryptoError::MalformedSignature {
                algorithm: AlgorithmId::Ed25519,
                internal_error: format!(
                    "Incorrect signature length: expected {}, got {}.",
                    SignatureBytes::SIZE,
                    sig.len()
                ),
                sig_bytes: sig,
            }
        })?;
        Ok(SignatureBytes(array))
    }
}
