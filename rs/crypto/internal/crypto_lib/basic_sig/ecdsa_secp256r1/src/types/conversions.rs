use super::*;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::{From, TryFrom};

// From vector of bytes.
impl From<Vec<u8>> for PublicKeyBytes {
    fn from(key: Vec<u8>) -> Self {
        PublicKeyBytes(key)
    }
}

impl From<PublicKeyBytes> for String {
    fn from(val: PublicKeyBytes) -> Self {
        base64::encode(&val.0[..])
    }
}

impl TryFrom<&str> for PublicKeyBytes {
    type Error = CryptoError;

    fn try_from(key: &str) -> Result<Self, CryptoError> {
        let key = base64::decode(key).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: None,
            internal_error: format!("Key {} is not a valid base64 encoded string: {}", key, e),
        })?;
        Ok(PublicKeyBytes(key))
    }
}

impl TryFrom<&String> for PublicKeyBytes {
    type Error = CryptoError;
    fn try_from(pk_string: &String) -> Result<Self, CryptoError> {
        Self::try_from(pk_string as &str)
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

impl From<SignatureBytes> for String {
    fn from(val: SignatureBytes) -> Self {
        base64::encode(&val.0.to_vec())
    }
}

impl TryFrom<&str> for SignatureBytes {
    type Error = CryptoError;

    fn try_from(signature: &str) -> Result<Self, CryptoError> {
        let signature = base64::decode(signature).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::EcdsaP256,
            sig_bytes: Vec::new(),
            internal_error: format!(
                "Signature {} is not a valid base64 encoded string: {}",
                signature, e
            ),
        })?;
        SignatureBytes::try_from(signature)
    }
}

impl TryFrom<&String> for SignatureBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::SignatureBytes;
    use std::convert::TryFrom;

    #[test]
    fn should_convert_vector_to_signature_bytes() {
        let bytes = vec![0; SignatureBytes::SIZE];
        let _sig_bytes = SignatureBytes::try_from(bytes).expect("conversion failed");
    }

    #[test]
    fn should_fail_conversion_to_signature_bytes_if_vector_too_long() {
        let bytes = vec![0; SignatureBytes::SIZE + 1];
        let result = SignatureBytes::try_from(bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_malformed_signature());
    }

    #[test]
    fn should_fail_conversion_to_signature_bytes_if_vector_too_short() {
        let bytes = vec![0; SignatureBytes::SIZE - 1];
        let result = SignatureBytes::try_from(bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_malformed_signature());
    }
}
