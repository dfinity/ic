//! Type conversion utilities

use super::{
    CspPop, CspPublicKey, CspSecretKey, CspSignature, MultiBls12_381_Signature, SigConverter,
    ThresBls12_381_Signature,
};
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::{AlgorithmId, CryptoError, UserPublicKey};
use std::convert::TryFrom;
use std::fmt;

use ic_crypto_internal_multi_sig_bls12381::types::conversions::protobuf::PopBytesFromProtoError;

#[cfg(test)]
mod tests;

impl From<&CspPublicKey> for AlgorithmId {
    fn from(public_key: &CspPublicKey) -> Self {
        match public_key {
            CspPublicKey::EcdsaP256(_) => AlgorithmId::EcdsaP256,
            CspPublicKey::EcdsaSecp256k1(_) => AlgorithmId::EcdsaSecp256k1,
            CspPublicKey::Ed25519(_) => AlgorithmId::Ed25519,
            CspPublicKey::MultiBls12_381(_) => AlgorithmId::MultiBls12_381,
            CspPublicKey::RsaSha256(_) => AlgorithmId::RsaSha256,
        }
    }
}

impl TryFrom<CspPublicKey> for UserPublicKey {
    type Error = CryptoError;
    fn try_from(pk: CspPublicKey) -> Result<Self, CryptoError> {
        match pk {
            CspPublicKey::EcdsaP256(pk) => Ok(UserPublicKey {
                key: pk.0.to_vec(),
                algorithm_id: AlgorithmId::EcdsaP256,
            }),
            CspPublicKey::Ed25519(pk) => Ok(UserPublicKey {
                key: pk.0.to_vec(),
                algorithm_id: AlgorithmId::Ed25519,
            }),
            _ => Err(CryptoError::InvalidArgument {
                message: format!(
                    "Unsupported conversion from CspPublicKey to UserPublicKey: {:?}",
                    pk
                ),
            }),
        }
    }
}

impl TryFrom<PublicKeyProto> for CspPublicKey {
    type Error = CryptoError;
    // TODO (CRP-540): move the key bytes from pk_proto.key_value to the
    //   resulting csp_pk (instead of copying/cloning them).
    fn try_from(pk_proto: PublicKeyProto) -> Result<Self, Self::Error> {
        Self::try_from(&pk_proto)
    }
}

impl TryFrom<&PublicKeyProto> for CspPublicKey {
    type Error = CryptoError;
    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, Self::Error> {
        match AlgorithmId::from(pk_proto.algorithm) {
            AlgorithmId::Ed25519 => {
                let public_key_bytes =
                    ed25519_types::PublicKeyBytes::try_from(pk_proto).map_err(|e| {
                        CryptoError::MalformedPublicKey {
                            algorithm: AlgorithmId::Ed25519,
                            key_bytes: Some(e.key_bytes),
                            internal_error: e.internal_error,
                        }
                    })?;
                Ok(CspPublicKey::Ed25519(public_key_bytes))
            }
            AlgorithmId::MultiBls12_381 => {
                let public_key_bytes =
                    multi_types::PublicKeyBytes::try_from(pk_proto).map_err(|e| {
                        CryptoError::MalformedPublicKey {
                            algorithm: AlgorithmId::MultiBls12_381,
                            key_bytes: Some(e.key_bytes),
                            internal_error: e.internal_error,
                        }
                    })?;
                Ok(CspPublicKey::MultiBls12_381(public_key_bytes))
            }
            algorithm => Err(CryptoError::AlgorithmNotSupported {
                algorithm,
                reason: "Could not convert to CspPublicKey".to_string(),
            }),
        }
    }
}

impl TryFrom<&PublicKeyProto> for CspPop {
    type Error = CspPopFromPublicKeyProtoError;

    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, Self::Error> {
        let pop_bytes = multi_types::PopBytes::try_from(pk_proto)?;
        Ok(CspPop::MultiBls12_381(pop_bytes))
    }
}

/// A problem while reading PoP from a public key protobuf
#[derive(Clone, Eq, PartialEq)]
pub enum CspPopFromPublicKeyProtoError {
    NoPopForAlgorithm {
        algorithm: AlgorithmId,
    },
    MissingProofData,
    MalformedPop {
        pop_bytes: Vec<u8>,
        internal_error: String,
    },
}
impl fmt::Debug for CspPopFromPublicKeyProtoError {
    /// Prints in a developer-friendly format.
    ///
    /// The standard rust encoding is used for all fields except the PoP, which
    /// is encoded as hex rather than arrays of integers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CspPopFromPublicKeyProtoError::*;
        match self {
            NoPopForAlgorithm{ algorithm } => write!(f, "CspPopFromPublicKeyProtoError::NoPopForAlgorithm{{ algorithm: {:?} }}", algorithm),
            MissingProofData => write!(f, "CspPopFromPublicKeyProtoError::MissingProofData"),
            MalformedPop{ pop_bytes, internal_error } => write!(f, "CspPopFromPublicKeyProtoError::MalformedPop{{ pop_bytes: {:?}, internal_error: {} }}", hex::encode(&pop_bytes[..]), internal_error),
        }
    }
}

impl From<PopBytesFromProtoError> for CspPopFromPublicKeyProtoError {
    fn from(pop_bytes_from_proto_error: PopBytesFromProtoError) -> Self {
        match pop_bytes_from_proto_error {
            PopBytesFromProtoError::UnknownAlgorithm { algorithm } => {
                CspPopFromPublicKeyProtoError::NoPopForAlgorithm {
                    algorithm: AlgorithmId::from(algorithm),
                }
            }
            PopBytesFromProtoError::MissingProofData => {
                CspPopFromPublicKeyProtoError::MissingProofData
            }
            PopBytesFromProtoError::InvalidLength {
                pop_bytes,
                internal_error,
            } => CspPopFromPublicKeyProtoError::MalformedPop {
                pop_bytes,
                internal_error,
            },
        }
    }
}

// This is a temporary way to get to the raw bytes of CspPublicKey until
// we have consolidated the key/signatures types which will likely involve
// removing the CspPublicKey type. Because this impl is temporary, there are
// no associated tests.
// TODO (CRP-218): Remove as part of CRP-218
impl AsRef<[u8]> for CspPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            CspPublicKey::EcdsaP256(bytes) => &bytes.0,
            CspPublicKey::EcdsaSecp256k1(bytes) => &bytes.0,
            CspPublicKey::Ed25519(bytes) => &bytes.0,
            CspPublicKey::MultiBls12_381(public_key_bytes) => &public_key_bytes.0,
            CspPublicKey::RsaSha256(public_key_bytes) => public_key_bytes.as_der(),
        }
    }
}

// This is a temporary way to get to the raw bytes of CspPop until
// we have consolidated the key/signatures types which will likely involve
// removing the CspPop type. Because this impl is temporary, there are
// no associated tests.
// TODO (CRP-218): Remove as part of CRP-218
impl AsRef<[u8]> for CspPop {
    fn as_ref(&self) -> &[u8] {
        match self {
            CspPop::MultiBls12_381(sig_bytes) => &sig_bytes.0,
        }
    }
}

// This is a temporary way to get to the raw bytes of CspSignature until
// we have consolidated the key/signatures types which will likely involve
// removing the CspSignature type. Because this impl is temporary, there are
// no associated tests.
// TODO (CRP-218): Remove as part of CRP-218
impl AsRef<[u8]> for CspSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            CspSignature::EcdsaP256(bytes) => &bytes.0,
            CspSignature::EcdsaSecp256k1(bytes) => &bytes.0,
            CspSignature::Ed25519(bytes) => &bytes.0,
            CspSignature::MultiBls12_381(sig) => match sig {
                MultiBls12_381_Signature::Individual(sig_bytes) => &sig_bytes.0,
                MultiBls12_381_Signature::Combined(sig_bytes) => &sig_bytes.0,
            },
            CspSignature::ThresBls12_381(sig) => match sig {
                ThresBls12_381_Signature::Individual(sig_bytes) => &sig_bytes.0,
                ThresBls12_381_Signature::Combined(sig_bytes) => &sig_bytes.0,
            },
            CspSignature::RsaSha256(bytes) => bytes,
        }
    }
}

impl TryFrom<&UserPublicKey> for CspPublicKey {
    type Error = CryptoError;

    fn try_from(user_public_key: &UserPublicKey) -> Result<Self, Self::Error> {
        match user_public_key.algorithm_id {
            AlgorithmId::Ed25519 => {
                const PUBKEY_LEN: usize = ed25519_types::PublicKeyBytes::SIZE;

                if user_public_key.key.len() != PUBKEY_LEN {
                    return Err(CryptoError::MalformedPublicKey {
                        algorithm: AlgorithmId::Ed25519,
                        key_bytes: Some(user_public_key.key.to_owned()),
                        internal_error: format!(
                            "Invalid length: Expected Ed25519 public key with {} bytes but got {} bytes",
                            PUBKEY_LEN,
                            user_public_key.key.len()
                        ),
                    });
                }
                let mut bytes: [u8; PUBKEY_LEN] = [0; PUBKEY_LEN];
                bytes.copy_from_slice(&user_public_key.key[0..PUBKEY_LEN]);
                Ok(CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(bytes)))
            }
            AlgorithmId::EcdsaP256 => Ok(CspPublicKey::EcdsaP256(
                ecdsa_secp256r1_types::PublicKeyBytes(user_public_key.key.to_owned()),
            )),
            AlgorithmId::EcdsaSecp256k1 => Ok(CspPublicKey::EcdsaSecp256k1(
                ecdsa_secp256k1_types::PublicKeyBytes(user_public_key.key.to_owned()),
            )),
            AlgorithmId::RsaSha256 => Ok(CspPublicKey::RsaSha256(
                rsa::RsaPublicKey::from_der_spki(&user_public_key.key)?,
            )),
            algorithm => Err(CryptoError::AlgorithmNotSupported {
                algorithm,
                reason: "Could not convert UserPublicKey to CspPublicKey".to_string(),
            }),
        }
    }
}

impl TryFrom<CspSecretKey> for threshold_types::SecretKeyBytes {
    type Error = CspSecretKeyConversionError;
    fn try_from(value: CspSecretKey) -> Result<Self, Self::Error> {
        if let CspSecretKey::ThresBls12_381(key) = &value {
            Ok(key.clone())
        } else {
            // TODO (CRP-822): Add the error type to the error message.
            Err(CspSecretKeyConversionError::WrongSecretKeyType {})
        }
    }
}

/// Error while converting secret key
pub enum CspSecretKeyConversionError {
    WrongSecretKeyType,
}

impl TryFrom<CspSignature> for threshold_types::IndividualSignatureBytes {
    type Error = CryptoError;
    fn try_from(value: CspSignature) -> Result<Self, Self::Error> {
        if let CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(signature)) = value
        {
            Ok(signature)
        } else {
            Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: value.as_ref().to_owned(),
                internal_error: "Not an individual threshold signature".to_string(),
            })
        }
    }
}

impl TryFrom<CspSignature> for threshold_types::CombinedSignatureBytes {
    type Error = CryptoError;
    fn try_from(value: CspSignature) -> Result<Self, Self::Error> {
        if let CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(signature)) = value {
            Ok(signature)
        } else {
            Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: value.as_ref().to_owned(),
                internal_error: "Not a combined threshold signature".to_string(),
            })
        }
    }
}

impl SigConverter {
    pub fn for_target(algorithm: AlgorithmId) -> Self {
        SigConverter {
            target_algorithm: algorithm,
        }
    }
}
