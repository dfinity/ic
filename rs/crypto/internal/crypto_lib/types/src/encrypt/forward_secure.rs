//! Types for forward-secure encryption used for distributed key generation

use crate::curves::bls12_381;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use strum_macros::IntoStaticStr;

#[cfg(test)]
mod tests;

/// Forward secure encryption public key
#[derive(Copy, Clone, Debug, Eq, IntoStaticStr, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CspFsEncryptionPublicKey {
    Groth20_Bls12_381(groth20_bls12_381::FsEncryptionPublicKey),
}

/// Forward secure encryption proof of possession.
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoStaticStr, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CspFsEncryptionPop {
    Groth20WithPop_Bls12_381(groth20_bls12_381::FsEncryptionPop),
}

impl TryFrom<PublicKeyProto> for CspFsEncryptionPublicKey {
    type Error = MalformedFsEncryptionPublicKeyError;

    fn try_from(pk_proto: PublicKeyProto) -> Result<Self, MalformedFsEncryptionPublicKeyError> {
        Self::try_from(&pk_proto)
    }
}

impl TryFrom<&PublicKeyProto> for CspFsEncryptionPublicKey {
    type Error = MalformedFsEncryptionPublicKeyError;

    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, MalformedFsEncryptionPublicKeyError> {
        if pk_proto.algorithm != AlgorithmIdProto::Groth20Bls12381 as i32 {
            return Err(MalformedFsEncryptionPublicKeyError {
                key_bytes: pk_proto.clone().key_value,
                internal_error: format!("Unknown algorithm: {}", pk_proto.algorithm),
            });
        }
        if pk_proto.key_value.len() != groth20_bls12_381::FsEncryptionPublicKey::SIZE {
            return Err(MalformedFsEncryptionPublicKeyError {
                key_bytes: pk_proto.clone().key_value,
                internal_error: format!(
                    "Wrong data length {}, expected length {}.",
                    pk_proto.key_value.len(),
                    bls12_381::G1Bytes::SIZE
                ),
            });
        }
        let mut pk_array = [0u8; bls12_381::G1Bytes::SIZE];
        pk_array[..].copy_from_slice(&pk_proto.key_value);
        Ok(CspFsEncryptionPublicKey::Groth20_Bls12_381(
            groth20_bls12_381::FsEncryptionPublicKey(bls12_381::G1Bytes(pk_array)),
        ))
    }
}

/// A forward secure encryption public key is malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedFsEncryptionPublicKeyError {
    pub key_bytes: Vec<u8>,
    pub internal_error: String,
}

impl fmt::Display for MalformedFsEncryptionPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MalformedFsEncryptionPublicKeyError {{  key_bytes: 0x{}, internal_error: {} }}",
            hex::encode(&self.key_bytes[..]),
            self.internal_error
        )
    }
}

impl TryFrom<&PublicKeyProto> for CspFsEncryptionPop {
    type Error = CspFsEncryptionPopFromPublicKeyProtoError;

    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, Self::Error> {
        if pk_proto.algorithm != AlgorithmIdProto::Groth20Bls12381 as i32 {
            return Err(
                CspFsEncryptionPopFromPublicKeyProtoError::UnknownAlgorithm {
                    algorithm: pk_proto.algorithm,
                },
            );
        }
        let proof_bytes = pk_proto
            .proof_data
            .as_ref()
            .ok_or(CspFsEncryptionPopFromPublicKeyProtoError::MissingProofData)?;
        serde_cbor::from_slice::<CspFsEncryptionPop>(proof_bytes).map_err(|e| {
            CspFsEncryptionPopFromPublicKeyProtoError::MalformedPop {
                pop_bytes: proof_bytes.clone(),
                internal_error: format!("{}", e),
            }
        })
    }
}

/// The forward secure encryption proof of possession (PoP) cannot be obtained
/// from its protobuf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CspFsEncryptionPopFromPublicKeyProtoError {
    UnknownAlgorithm {
        algorithm: i32,
    },
    MissingProofData,
    MalformedPop {
        pop_bytes: Vec<u8>,
        internal_error: String,
    },
}

impl fmt::Display for CspFsEncryptionPopFromPublicKeyProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CspFsEncryptionPopFromPublicKeyProtoError::UnknownAlgorithm { algorithm } => write!(
                f,
                "Unknown algorithm: {:?}",
                AlgorithmIdProto::try_from(*algorithm)
            ),
            CspFsEncryptionPopFromPublicKeyProtoError::MissingProofData => {
                write!(f, "Missing proof data",)
            }
            CspFsEncryptionPopFromPublicKeyProtoError::MalformedPop {
                pop_bytes,
                internal_error,
            } => write!(
                f,
                "Malformed proof of possession (PoP): {} (0x{})",
                internal_error,
                hex::encode(pop_bytes),
            ),
        }
    }
}

pub mod groth20_bls12_381 {
    //! The forward secure encryption keys used in Groth20.

    use crate::curves::bls12_381::{FrBytes, G1Bytes, G2Bytes};
    use crate::NodeIndex;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    /// Forward secure encryption public key used in Groth20.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct FsEncryptionPublicKey(pub G1Bytes);

    impl FsEncryptionPublicKey {
        pub const SIZE: usize = G1Bytes::SIZE;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
            self.0.as_bytes()
        }
    }

    /// Forward secure encryption proof of possession.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct FsEncryptionPop {
        pub pop_key: G1Bytes,
        pub challenge: FrBytes,
        pub response: FrBytes,
    }

    pub const CHUNK_BYTES: usize = 2;
    pub const NUM_CHUNKS: usize = (FrBytes::SIZE + CHUNK_BYTES - 1) / CHUNK_BYTES;

    // Note: the spec currently has: Vec<(r,s,z)>; this could be represented more
    // strongly as [(G1,G1,G2);NUM_CHUNKS], which is equivalent to the below.
    #[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
    pub struct FsEncryptionCiphertextBytes {
        pub rand_r: [G1Bytes; NUM_CHUNKS],
        pub rand_s: [G1Bytes; NUM_CHUNKS],
        pub rand_z: [G2Bytes; NUM_CHUNKS],
        pub ciphertext_chunks: Vec<[G1Bytes; NUM_CHUNKS]>,
    }
    impl FsEncryptionCiphertextBytes {
        //! Accessors by NodeIndex:
        pub fn len(&self) -> usize {
            self.ciphertext_chunks.len()
        }
        pub fn is_empty(&self) -> bool {
            self.ciphertext_chunks.is_empty()
        }
        pub fn iter(&self) -> impl Iterator<Item = (NodeIndex, &[G1Bytes; NUM_CHUNKS])> + '_ {
            (0_u32..).zip(&self.ciphertext_chunks)
        }
        pub fn get(&self, node_index: NodeIndex) -> Option<&[G1Bytes; NUM_CHUNKS]> {
            usize::try_from(node_index)
                .ok()
                .and_then(|node_index| self.ciphertext_chunks.get(node_index))
        }
    }
}
