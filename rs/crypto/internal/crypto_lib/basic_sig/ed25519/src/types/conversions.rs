use super::*;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::TryFrom;

pub mod protobuf;

#[cfg(test)]
mod tests;

impl TryFrom<&Vec<u8>> for PublicKeyBytes {
    type Error = CryptoError;

    fn try_from(key: &Vec<u8>) -> Result<Self, CryptoError> {
        if key.len() != PublicKeyBytes::SIZE {
            return Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::Ed25519,
                key_bytes: Some(key.to_vec()),
                internal_error: format!(
                    "Incorrect key length: expected {}, got {}.",
                    PublicKeyBytes::SIZE,
                    key.len()
                ),
            });
        }
        let mut buffer = [0u8; PublicKeyBytes::SIZE];
        buffer.copy_from_slice(key);
        Ok(PublicKeyBytes(buffer))
    }
}

impl TryFrom<&Vec<u8>> for SignatureBytes {
    type Error = CryptoError;

    fn try_from(signature_bytes: &Vec<u8>) -> Result<Self, CryptoError> {
        if signature_bytes.len() != SignatureBytes::SIZE {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::Ed25519,
                sig_bytes: signature_bytes.clone(),
                internal_error: format!(
                    "Incorrect signature length: expected {}, got {}.",
                    SignatureBytes::SIZE,
                    signature_bytes.len()
                ),
            });
        }
        let mut buffer = [0u8; SignatureBytes::SIZE];
        buffer.copy_from_slice(signature_bytes);
        Ok(SignatureBytes(buffer))
    }
}
