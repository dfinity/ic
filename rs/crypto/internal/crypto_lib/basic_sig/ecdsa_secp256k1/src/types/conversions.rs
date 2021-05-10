use super::*;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::{From, TryFrom};

// From vector of bytes.
impl From<Vec<u8>> for SecretKeyBytes {
    fn from(key: Vec<u8>) -> Self {
        SecretKeyBytes(key)
    }
}

// From vector of bytes.
impl From<Vec<u8>> for PublicKeyBytes {
    fn from(key: Vec<u8>) -> Self {
        PublicKeyBytes(key)
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
