use super::*;
use ic_crypto_secrets_containers::SecretArray;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::TryFrom;

pub mod protobuf;

#[cfg(test)]
mod tests;

impl From<SecretKeyBytes> for String {
    fn from(val: SecretKeyBytes) -> Self {
        base64::encode(val.0.expose_secret())
    }
}
impl TryFrom<&str> for SecretKeyBytes {
    type Error = CryptoError;

    fn try_from(key: &str) -> Result<Self, CryptoError> {
        let mut key = base64::decode(key).map_err(|e| CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::Ed25519,
            internal_error: format!("Key is not a valid base64 encoded string: {}", e),
        })?;
        if key.len() != SecretKeyBytes::SIZE {
            return Err(CryptoError::MalformedSecretKey {
                algorithm: AlgorithmId::Ed25519,
                internal_error: "Key length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; SecretKeyBytes::SIZE];
        buffer.copy_from_slice(&key);
        key.zeroize();
        let ret = SecretKeyBytes(SecretArray::new_and_zeroize_argument(&mut buffer));
        Ok(ret)
    }
}
impl TryFrom<&String> for SecretKeyBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}

impl From<PublicKeyBytes> for String {
    fn from(val: PublicKeyBytes) -> Self {
        base64::encode(&val.0[..])
    }
}

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
        buffer.copy_from_slice(&key);
        Ok(PublicKeyBytes(buffer))
    }
}

impl TryFrom<&str> for PublicKeyBytes {
    type Error = CryptoError;

    fn try_from(key: &str) -> Result<Self, CryptoError> {
        let key = base64::decode(key).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: None,
            internal_error: format!("Key {} is not a valid base64 encoded string: {}", key, e),
        })?;
        PublicKeyBytes::try_from(&key)
    }
}

impl TryFrom<&String> for PublicKeyBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}

impl From<SignatureBytes> for String {
    fn from(val: SignatureBytes) -> Self {
        base64::encode(&val.0[..])
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
        buffer.copy_from_slice(&signature_bytes);
        Ok(SignatureBytes(buffer))
    }
}

impl TryFrom<&str> for SignatureBytes {
    type Error = CryptoError;

    fn try_from(signature: &str) -> Result<Self, CryptoError> {
        let signature = base64::decode(signature).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::Ed25519,
            sig_bytes: Vec::new(),
            internal_error: format!(
                "Signature {} is not a valid base64 encoded string: {}",
                signature, e
            ),
        })?;
        if signature.len() != SignatureBytes::SIZE {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::Ed25519,
                sig_bytes: signature,
                internal_error: "Signature length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; SignatureBytes::SIZE];
        buffer.copy_from_slice(&signature);
        Ok(Self(buffer))
    }
}
impl TryFrom<&String> for SignatureBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}
