//! Defines threshold signature types.
use crate::crypto::threshold_sig::ni_dkg::NiDkgTranscript;
use crate::crypto::AlgorithmId;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
pub use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::ThresholdSigPublicKeyBytesConversionError;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub mod errors;
pub mod ni_dkg;

#[cfg(test)]
mod tests;

/// A threshold signature public key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ThresholdSigPublicKey {
    internal: CspThresholdSigPublicKey,
}
impl ThresholdSigPublicKey {
    pub const SIZE: usize = bls12_381::PublicKeyBytes::SIZE;

    // Returns the public key as raw bytes
    pub fn into_bytes(self) -> [u8; Self::SIZE] {
        bls12_381::PublicKeyBytes::from(self).0
    }
}
impl From<CspThresholdSigPublicKey> for ThresholdSigPublicKey {
    fn from(csp_threshold_sig_pubkey: CspThresholdSigPublicKey) -> Self {
        ThresholdSigPublicKey {
            internal: csp_threshold_sig_pubkey,
        }
    }
}
impl From<ThresholdSigPublicKey> for CspThresholdSigPublicKey {
    fn from(threshold_sig_pubkey: ThresholdSigPublicKey) -> Self {
        threshold_sig_pubkey.internal
    }
}

impl From<&NiDkgTranscript> for ThresholdSigPublicKey {
    fn from(ni_dkg_transcript: &NiDkgTranscript) -> Self {
        let csp_ni_dkg_transcript = CspNiDkgTranscript::from(ni_dkg_transcript);
        let csp_threshold_sig_pubkey = CspThresholdSigPublicKey::from(&csp_ni_dkg_transcript);
        ThresholdSigPublicKey::from(csp_threshold_sig_pubkey)
    }
}
impl From<bls12_381::PublicKeyBytes> for ThresholdSigPublicKey {
    fn from(bls12_381_pubkey_bytes: bls12_381::PublicKeyBytes) -> Self {
        let csp_threshold_sig_pubkey = CspThresholdSigPublicKey::from(bls12_381_pubkey_bytes);
        ThresholdSigPublicKey::from(csp_threshold_sig_pubkey)
    }
}
impl From<ThresholdSigPublicKey> for bls12_381::PublicKeyBytes {
    fn from(threshold_sig_pubkey: ThresholdSigPublicKey) -> Self {
        let csp_threshold_sig_pubkey = CspThresholdSigPublicKey::from(threshold_sig_pubkey);
        bls12_381::PublicKeyBytes::from(csp_threshold_sig_pubkey)
    }
}

impl TryFrom<PublicKeyProto> for ThresholdSigPublicKey {
    type Error = ThresholdSigPublicKeyBytesConversionError;

    fn try_from(public_key: PublicKeyProto) -> Result<Self, Self::Error> {
        if AlgorithmId::from(public_key.algorithm) != AlgorithmId::ThresBls12_381 {
            return Err(ThresholdSigPublicKeyBytesConversionError::Malformed {
                key_bytes: Some(public_key.key_value),
                internal_error: format!(
                    "Invalid algorithm: expected {:?} but got {:?}",
                    AlgorithmId::ThresBls12_381,
                    AlgorithmId::from(public_key.algorithm)
                ),
            });
        }
        const PUBKEY_LEN: usize = bls12_381::PublicKeyBytes::SIZE;
        if public_key.key_value.len() != PUBKEY_LEN {
            return Err(ThresholdSigPublicKeyBytesConversionError::Malformed {
                internal_error: format!(
                    "Invalid length: expected {} but got {}",
                    PUBKEY_LEN,
                    public_key.key_value.len(),
                ),
                key_bytes: Some(public_key.key_value),
            });
        }
        let mut bytes = [0; PUBKEY_LEN];
        bytes.copy_from_slice(&public_key.key_value);
        Ok(Self::from(bls12_381::PublicKeyBytes(bytes)))
    }
}

impl From<ThresholdSigPublicKey> for PublicKeyProto {
    fn from(threshold_sig_pubkey: ThresholdSigPublicKey) -> Self {
        let pubkey_bytes = bls12_381::PublicKeyBytes::from(threshold_sig_pubkey);
        PublicKeyProto {
            algorithm: AlgorithmIdProto::ThresBls12381 as i32,
            key_value: pubkey_bytes.0.to_vec(),
            version: 0,
            proof_data: None,
        }
    }
}
