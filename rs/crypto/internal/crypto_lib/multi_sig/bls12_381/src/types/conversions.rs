//! Type conversions for BLS12-381 multisignatures.
use super::*;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::convert::TryFrom;

pub mod protobuf;

#[cfg(test)]
mod tests;

impl From<&SecretKeyBytes> for SecretKey {
    fn from(val: &SecretKeyBytes) -> Self {
        SecretKey::deserialize_unchecked(val.0.expose_secret())
    }
}
impl From<&SecretKey> for SecretKeyBytes {
    fn from(secret_key: &SecretKey) -> SecretKeyBytes {
        let mut bytes = secret_key.serialize();
        SecretKeyBytes(
            ic_crypto_secrets_containers::SecretArray::new_and_zeroize_argument(&mut bytes),
        )
    }
}

impl TryFrom<&PublicKeyBytes> for PublicKey {
    type Error = CryptoError;

    fn try_from(public_key_bytes: &PublicKeyBytes) -> Result<Self, Self::Error> {
        G2Affine::deserialize(&public_key_bytes.0).map_err(|_| {
            CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::MultiBls12_381,
                key_bytes: Some(public_key_bytes.0.to_vec()),
                internal_error: "Point decoding failed".to_string(),
            }
        })
    }
}
impl From<&PublicKey> for PublicKeyBytes {
    fn from(public_key: &PublicKey) -> PublicKeyBytes {
        PublicKeyBytes(public_key.serialize())
    }
}

impl TryFrom<&IndividualSignatureBytes> for IndividualSignature {
    type Error = CryptoError;
    fn try_from(signature: &IndividualSignatureBytes) -> Result<Self, Self::Error> {
        G1Affine::deserialize(&signature.0).map_err(|_| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::MultiBls12_381,
            sig_bytes: signature.0.to_vec(),
            internal_error: "Point decoding failed".to_string(),
        })
    }
}

impl From<&IndividualSignature> for IndividualSignatureBytes {
    fn from(signature: &IndividualSignature) -> IndividualSignatureBytes {
        IndividualSignatureBytes(signature.serialize())
    }
}

impl TryFrom<&PopBytes> for Pop {
    type Error = CryptoError;

    fn try_from(pop_bytes: &PopBytes) -> Result<Self, Self::Error> {
        G1Affine::deserialize(&pop_bytes.0).map_err(|_| CryptoError::MalformedPop {
            algorithm: AlgorithmId::MultiBls12_381,
            pop_bytes: pop_bytes.0.to_vec(),
            internal_error: "Point decoding failed".to_string(),
        })
    }
}
impl From<&Pop> for PopBytes {
    fn from(pop: &Pop) -> PopBytes {
        PopBytes(pop.serialize())
    }
}

impl TryFrom<&CombinedSignatureBytes> for CombinedSignature {
    type Error = CryptoError;
    fn try_from(signature: &CombinedSignatureBytes) -> Result<Self, Self::Error> {
        G1Affine::deserialize(&signature.0).map_err(|_| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::MultiBls12_381,
            sig_bytes: signature.0.to_vec(),
            internal_error: "Point decoding failed".to_string(),
        })
    }
}
impl From<&CombinedSignature> for CombinedSignatureBytes {
    fn from(signature: &CombinedSignature) -> CombinedSignatureBytes {
        CombinedSignatureBytes(signature.serialize())
    }
}
