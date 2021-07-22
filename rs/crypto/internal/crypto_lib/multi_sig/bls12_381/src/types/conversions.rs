//! Type conversions for BLS12-381 multisignatures.
use super::*;
use ic_crypto_internal_bls12381_common as bls;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::{TryFrom, TryInto};

pub mod protobuf;

#[cfg(test)]
mod tests;

impl From<SecretKeyBytes> for SecretKey {
    fn from(val: SecretKeyBytes) -> Self {
        bls::fr_from_bytes(&val.0)
    }
}
impl From<SecretKey> for SecretKeyBytes {
    fn from(secret_key: SecretKey) -> SecretKeyBytes {
        SecretKeyBytes(bls::fr_to_bytes(&secret_key))
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = CryptoError;

    fn try_from(public_key_bytes: PublicKeyBytes) -> Result<Self, Self::Error> {
        bls::g2_from_bytes(&public_key_bytes.0).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::MultiBls12_381,
            key_bytes: Some(public_key_bytes.0.to_vec()),
            internal_error: e.to_string(),
        })
    }
}
impl From<PublicKey> for PublicKeyBytes {
    fn from(public_key: PublicKey) -> PublicKeyBytes {
        PublicKeyBytes(bls::g2_to_bytes(&public_key))
    }
}

impl TryInto<IndividualSignature> for IndividualSignatureBytes {
    type Error = CryptoError;

    fn try_into(self) -> Result<IndividualSignature, CryptoError> {
        bls::g1_from_bytes(&self.0).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::MultiBls12_381,
            sig_bytes: self.0.to_vec(),
            internal_error: e.to_string(),
        })
    }
}
impl From<IndividualSignature> for IndividualSignatureBytes {
    fn from(signature: IndividualSignature) -> IndividualSignatureBytes {
        IndividualSignatureBytes(bls::g1_to_bytes(&signature))
    }
}

impl TryFrom<PopBytes> for Pop {
    type Error = CryptoError;

    fn try_from(pop_bytes: PopBytes) -> Result<Self, Self::Error> {
        bls::g1_from_bytes(&pop_bytes.0).map_err(|e| CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: pop_bytes.0.to_vec(),
            internal_error: e.to_string(),
        })
    }
}
impl From<Pop> for PopBytes {
    fn from(pop: Pop) -> PopBytes {
        PopBytes(bls::g1_to_bytes(&pop))
    }
}

impl TryInto<CombinedSignature> for CombinedSignatureBytes {
    type Error = CryptoError;

    fn try_into(self) -> Result<CombinedSignature, CryptoError> {
        bls::g1_from_bytes(&self.0).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::MultiBls12_381,
            sig_bytes: self.0.to_vec(),
            internal_error: e.to_string(),
        })
    }
}
impl From<CombinedSignature> for CombinedSignatureBytes {
    fn from(signature: CombinedSignature) -> CombinedSignatureBytes {
        CombinedSignatureBytes(bls::g1_to_bytes(&signature))
    }
}

impl From<IndividualSignatureBytes> for String {
    fn from(val: IndividualSignatureBytes) -> Self {
        base64::encode(&val.0[..])
    }
}
impl TryFrom<&str> for IndividualSignatureBytes {
    type Error = CryptoError;

    fn try_from(signature: &str) -> Result<Self, CryptoError> {
        let signature = base64::decode(signature).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::MultiBls12_381,
            sig_bytes: Vec::new(),
            internal_error: format!(
                "Signature {} is not a valid base64 encoded string: {}",
                signature, e
            ),
        })?;
        if signature.len() != IndividualSignatureBytes::SIZE {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::MultiBls12_381,
                sig_bytes: signature,
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

impl From<PopBytes> for String {
    fn from(pop_bytes: PopBytes) -> Self {
        base64::encode(&pop_bytes.0[..])
    }
}
impl TryFrom<&str> for PopBytes {
    type Error = CryptoError;

    fn try_from(pop: &str) -> Result<Self, CryptoError> {
        let pop = base64::decode(pop).map_err(|e| CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: Vec::new(),
            internal_error: format!("PoP {} is not a valid base64 encoded string: {}", pop, e),
        })?;
        if pop.len() != PopBytes::SIZE {
            return Err(CryptoError::MalformedPop {
                algorithm: AlgorithmId::MultiBls12_381,
                pop_bytes: pop,
                internal_error: "PoP length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; PopBytes::SIZE];
        buffer.copy_from_slice(&pop);
        Ok(PopBytes(buffer))
    }
}
impl TryFrom<&String> for PopBytes {
    type Error = CryptoError;
    fn try_from(pop: &String) -> Result<Self, CryptoError> {
        Self::try_from(pop as &str)
    }
}

impl From<CombinedSignatureBytes> for String {
    fn from(val: CombinedSignatureBytes) -> Self {
        base64::encode(&val.0[..])
    }
}
impl TryFrom<&str> for CombinedSignatureBytes {
    type Error = CryptoError;

    fn try_from(signature: &str) -> Result<Self, CryptoError> {
        let signature = base64::decode(signature).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::MultiBls12_381,
            sig_bytes: Vec::new(),
            internal_error: format!(
                "Signature {} is not a valid base64 encoded string: {}",
                signature, e
            ),
        })?;
        if signature.len() != CombinedSignatureBytes::SIZE {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::MultiBls12_381,
                sig_bytes: signature,
                internal_error: "Signature length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; CombinedSignatureBytes::SIZE];
        buffer.copy_from_slice(&signature);
        Ok(CombinedSignatureBytes(buffer))
    }
}
impl TryFrom<&String> for CombinedSignatureBytes {
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
impl TryFrom<&str> for PublicKeyBytes {
    type Error = CryptoError;

    fn try_from(key: &str) -> Result<Self, CryptoError> {
        let key = base64::decode(key).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::MultiBls12_381,
            key_bytes: None,
            internal_error: format!("Key {} is not a valid base64 encoded string: {}", key, e),
        })?;
        if key.len() != PublicKeyBytes::SIZE {
            return Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::MultiBls12_381,
                key_bytes: Some(key),
                internal_error: "Key length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; PublicKeyBytes::SIZE];
        buffer.copy_from_slice(&key);
        Ok(PublicKeyBytes(buffer))
    }
}
impl TryFrom<&String> for PublicKeyBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}

impl From<SecretKeyBytes> for String {
    fn from(val: SecretKeyBytes) -> Self {
        base64::encode(&val.0[..])
    }
}
impl TryFrom<&str> for SecretKeyBytes {
    type Error = CryptoError;

    fn try_from(key: &str) -> Result<Self, CryptoError> {
        let key = base64::decode(key).map_err(|e| CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::MultiBls12_381,
            internal_error: format!("Key is not a valid base64 encoded string: {}", e),
        })?;
        if key.len() != SecretKeyBytes::SIZE {
            return Err(CryptoError::MalformedSecretKey {
                algorithm: AlgorithmId::MultiBls12_381,
                internal_error: "Key length is incorrect".to_string(),
            });
        }
        let mut buffer = [0u8; SecretKeyBytes::SIZE];
        buffer.copy_from_slice(&key);
        Ok(SecretKeyBytes(buffer))
    }
}
impl TryFrom<&String> for SecretKeyBytes {
    type Error = CryptoError;
    fn try_from(signature: &String) -> Result<Self, CryptoError> {
        Self::try_from(signature as &str)
    }
}
