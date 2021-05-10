//! Conversions to/from protobuf for BLS12-381 multisignature types.
use crate::types::{PopBytes, PublicKeyBytes};
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use std::convert::TryFrom;
use std::fmt;

#[cfg(test)]
mod tests;

impl TryFrom<&PublicKeyProto> for PublicKeyBytes {
    type Error = PublicKeyBytesFromProtoError;

    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, Self::Error> {
        if AlgorithmIdProto::from_i32(pk_proto.algorithm) != Some(AlgorithmIdProto::MultiBls12381) {
            return Err(PublicKeyBytesFromProtoError {
                key_bytes: pk_proto.clone().key_value,
                internal_error: format!("Unknown algorithm: {}", pk_proto.algorithm),
            });
        }
        if pk_proto.key_value.len() != PublicKeyBytes::SIZE {
            return Err(PublicKeyBytesFromProtoError {
                key_bytes: pk_proto.clone().key_value,
                internal_error: format!(
                    "Wrong data length {}, expected length {}.",
                    pk_proto.key_value.len(),
                    PublicKeyBytes::SIZE,
                ),
            });
        }
        let mut buf = [0; PublicKeyBytes::SIZE];
        buf.copy_from_slice(&pk_proto.key_value);
        Ok(PublicKeyBytes(buf))
    }
}

/// Parsing a public key from protobuf failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyBytesFromProtoError {
    pub key_bytes: Vec<u8>,
    pub internal_error: String,
}

impl fmt::Display for PublicKeyBytesFromProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKeyBytesFromProtoError {{  key_bytes: 0x{}, internal_error: {} }}",
            hex::encode(&self.key_bytes),
            self.internal_error
        )
    }
}

impl TryFrom<&PublicKeyProto> for PopBytes {
    type Error = PopBytesFromProtoError;

    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, Self::Error> {
        if AlgorithmIdProto::from_i32(pk_proto.algorithm) != Some(AlgorithmIdProto::MultiBls12381) {
            return Err(PopBytesFromProtoError::UnknownAlgorithm {
                algorithm: pk_proto.algorithm,
            });
        }
        let proof_bytes = pk_proto
            .proof_data
            .as_ref()
            .ok_or(PopBytesFromProtoError::MissingProofData)?;
        if proof_bytes.len() != PopBytes::SIZE {
            return Err(PopBytesFromProtoError::InvalidLength {
                pop_bytes: proof_bytes.clone(),
                internal_error: format!(
                    "Wrong pop length {}, expected length {}.",
                    proof_bytes.len(),
                    PopBytes::SIZE,
                ),
            });
        }
        let mut buf = [0; PopBytes::SIZE];
        buf.copy_from_slice(proof_bytes);
        Ok(PopBytes(buf))
    }
}

/// Parsing a PoP from protobuf failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PopBytesFromProtoError {
    UnknownAlgorithm {
        algorithm: i32,
    },
    MissingProofData,
    InvalidLength {
        pop_bytes: Vec<u8>,
        internal_error: String,
    },
}

impl fmt::Display for PopBytesFromProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PopBytesFromProtoError::InvalidLength {
                pop_bytes,
                internal_error,
            } => write!(
                f,
                "PopBytesFromProtoError {{ pop_bytes: 0x{}, internal_error: {} }}",
                hex::encode(pop_bytes),
                internal_error
            ),
            _ => write!(f, "{:?}", self),
        }
    }
}
