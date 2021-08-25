//! Type conversion utilities

use super::{
    CspDealing, CspDkgTranscript, CspPop, CspPublicCoefficients, CspPublicKey, CspSecretKey,
    CspSignature, MultiBls12_381_Signature, SigConverter, ThresBls12_381_Signature,
};
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::EphemeralKeySetBytes;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::dkg::EncryptionPublicKeyPop;
use ic_types::crypto::dkg::{Transcript, TranscriptBytes};
use ic_types::crypto::{AlgorithmId, CryptoError, KeyId, UserPublicKey};
use std::convert::TryFrom;

pub mod dkg_id_to_key_id;

use crate::types::CspEncryptedSecretKey;
use ic_crypto_internal_multi_sig_bls12381::types::conversions::protobuf::PopBytesFromProtoError;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::CLibDealingBytes;
use ic_crypto_sha256::{Context, DomainSeparationContext};
use openssl::sha::Sha256;

#[cfg(test)]
mod tests;

/// Create a key identifier from the public coefficients
// TODO (CRP-821): Tests - take the existing ones from classic DKG.
// TODO (CRP-821): Remove classic DKG conversion.
pub fn key_id_from_csp_pub_coeffs(csp_public_coefficients: &CspPublicCoefficients) -> KeyId {
    let mut hash = Sha256::new();
    hash.update(
        DomainSeparationContext::new("KeyId from threshold public coefficients").as_bytes(),
    );
    hash.update(
        &serde_cbor::to_vec(&csp_public_coefficients)
            .expect("Failed to serialize public coefficients"),
    );
    KeyId::from(hash.finish())
}

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

impl From<&CspDkgTranscript> for CspPublicCoefficients {
    fn from(csp_dkg_transcript: &CspDkgTranscript) -> Self {
        match csp_dkg_transcript {
            CspDkgTranscript::Secp256k1(clib_transcript) => {
                CspPublicCoefficients::Bls12_381(clib_transcript.public_coefficients.clone())
            }
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
        match AlgorithmId::from(pk_proto.algorithm) {
            AlgorithmId::Ed25519 => {
                let public_key_bytes =
                    ed25519_types::PublicKeyBytes::try_from(&pk_proto).map_err(|e| {
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
                    multi_types::PublicKeyBytes::try_from(&pk_proto).map_err(|e| {
                        CryptoError::MalformedPublicKey {
                            algorithm: AlgorithmId::MultiBls12_381,
                            key_bytes: Some(e.key_bytes),
                            internal_error: e.internal_error,
                        }
                    })?;
                Ok(CspPublicKey::MultiBls12_381(public_key_bytes))
            }
            _ => Err(CryptoError::AlgorithmNotSupported {
                algorithm: AlgorithmId::from(pk_proto.algorithm),
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
            CspPublicKey::RsaSha256(public_key_bytes) => &public_key_bytes.as_der(),
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
            CspPop::Secp256k1(sig_bytes) => &sig_bytes.0,
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
            CspSignature::RsaSha256(bytes) => &bytes,
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
        if let CspSecretKey::ThresBls12_381(key) = value {
            Ok(key)
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

impl TryFrom<CspSecretKey> for EphemeralKeySetBytes {
    type Error = dkg_errors::MalformedSecretKeyError;
    fn try_from(value: CspSecretKey) -> Result<Self, Self::Error> {
        if let CspSecretKey::Secp256k1WithPublicKey(key_set) = value {
            Ok(key_set)
        } else {
            Err(dkg_errors::MalformedSecretKeyError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "Could not parse ephemeral key set".to_string(),
            })
        }
    }
}

impl From<CLibDealingBytes> for CspDealing {
    fn from(clib_dealing: CLibDealingBytes) -> CspDealing {
        CspDealing {
            common_data: CspPublicCoefficients::Bls12_381(clib_dealing.public_coefficients),
            receiver_data: clib_dealing
                .receiver_data
                .iter()
                .map(|data_maybe| data_maybe.map(CspEncryptedSecretKey::ThresBls12_381))
                .collect(),
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

impl From<&CspPop> for EncryptionPublicKeyPop {
    fn from(csp_pop: &CspPop) -> Self {
        EncryptionPublicKeyPop(
            serde_cbor::to_vec(csp_pop).expect("Cannot serialize csp encryption public key pop"),
        )
    }
}

/// Decode the public coefficients from a transcript
pub fn csp_pub_coeffs_from_transcript(transcript: &Transcript) -> CspPublicCoefficients {
    let csp_transcript = CspDkgTranscript::from(&transcript.transcript_bytes);
    CspPublicCoefficients::from(&csp_transcript)
}

// TODO (CRP-362): implement the conversion properly once we have agreement
impl From<&TranscriptBytes> for CspDkgTranscript {
    fn from(transcript_bytes: &TranscriptBytes) -> Self {
        serde_cbor::from_slice(transcript_bytes.0.as_slice())
            .expect("cannot deserialize transcript bytes into CSP transcript")
    }
}

// TODO (CRP-362): implement the conversion properly once we have agreement
impl From<&CspDkgTranscript> for TranscriptBytes {
    fn from(csp_dkg_transcript: &CspDkgTranscript) -> Self {
        TranscriptBytes(
            serde_cbor::to_vec(csp_dkg_transcript).expect("Cannot serialize CSP DKG transcript"),
        )
    }
}
