use crate::crypto::impl_display_using_debug;
use crate::crypto::threshold_sig::errors::threshold_sig_data_not_found_error::ThresholdSigDataNotFoundError;
use crate::crypto::threshold_sig::ni_dkg::NiDkgId;
use crate::crypto::ExtendedDerivationPath;
use crate::crypto::HexEncoding;
use crate::NodeId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(test)]
mod test;

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdArgs {
    pub ni_dkg_id: NiDkgId,
    pub derivation_path: ExtendedDerivationPath,
    #[serde(with = "serde_bytes")]
    pub derivation_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encryption_public_key: Vec<u8>,
}

impl fmt::Debug for VetKdArgs {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("VetKdArgs")
            .field("ni_dkg_id", &self.ni_dkg_id)
            .field("derivation_path", &self.derivation_path)
            .field("derivation_id", &HexEncoding::from(&self.derivation_id))
            .field(
                "encryption_public_key",
                &HexEncoding::from(&self.encryption_public_key),
            )
            .finish()
    }
}
impl_display_using_debug!(VetKdArgs);

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKeyShareContent(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for VetKdEncryptedKeyShareContent {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("VetKdEncryptedKeyShareContent")
            .field(&HexEncoding::from(&self.0))
            .finish()
    }
}
impl_display_using_debug!(VetKdEncryptedKeyShareContent);

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKeyShare {
    pub encrypted_key_share: VetKdEncryptedKeyShareContent,
    /// Node's Ed25519 signature for optimized variant
    #[serde(with = "serde_bytes")]
    pub node_signature: Vec<u8>,
}

impl std::fmt::Debug for VetKdEncryptedKeyShare {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("VetKdEncryptedKeyShare")
            .field("encrypted_key_share", &self.encrypted_key_share)
            .field("node_signature", &HexEncoding::from(&self.node_signature))
            .finish()
    }
}
impl_display_using_debug!(VetKdEncryptedKeyShare);

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKey {
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}

impl std::fmt::Debug for VetKdEncryptedKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("VetKdEncryptedKey")
            .field("encrypted_key", &HexEncoding::from(&self.encrypted_key))
            .finish()
    }
}
impl_display_using_debug!(VetKdEncryptedKey);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareCreationError {
    ThresholdSigDataNotFound(ThresholdSigDataNotFoundError),
    SecretKeyNotFound { dkg_id: NiDkgId, key_id: String },
    KeyIdInstantiationError(String),
    TransientInternalError(String),
}
impl_display_using_debug!(VetKdKeyShareCreationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareVerificationError {
    InvalidSignature,
}
impl_display_using_debug!(VetKdKeyShareVerificationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareCombinationError {
    InvalidShares(Vec<NodeId>),
    UnsatisfiedReconstructionThreshold { threshold: u32, share_count: usize },
}
impl_display_using_debug!(VetKdKeyShareCombinationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyVerificationError {}
impl_display_using_debug!(VetKdKeyVerificationError);
