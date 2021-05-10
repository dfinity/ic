use crate::types::PublicKeyBytes;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use std::convert::TryFrom;
use std::fmt;

#[cfg(test)]
mod tests;

impl TryFrom<&PublicKeyProto> for PublicKeyBytes {
    type Error = PublicKeyBytesFromProtoError;

    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, Self::Error> {
        if AlgorithmIdProto::from_i32(pk_proto.algorithm) != Some(AlgorithmIdProto::Ed25519) {
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
