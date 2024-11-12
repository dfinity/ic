use crate::crypto::canister_threshold_sig::ExtendedDerivationPath;
use crate::crypto::threshold_sig::errors::threshold_sig_data_not_found_error::ThresholdSigDataNotFoundError;
use crate::crypto::threshold_sig::ni_dkg::NiDkgId;
use crate::NodeId;
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! impl_display_using_debug {
    ($t:ty) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };
}

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdArgs {
    pub dkg_id: NiDkgId,
    pub derivation_path: ExtendedDerivationPath,
    #[serde(with = "serde_bytes")]
    pub derivation_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encryption_key: Vec<u8>,
}

impl_display_using_debug!(VetKdArgs);

impl std::fmt::Debug for VetKdArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VetKdArgs {{ ")?;
        write!(f, "dkg_id: {:?}", self.dkg_id)?;
        write!(f, ", derivation_path: {:?}", self.derivation_path)?;
        write!(f, ", derivation_id: 0x{}", hex::encode(&self.derivation_id))?;
        write!(
            f,
            ", encryption_key: 0x{}",
            hex::encode(&self.encryption_key)
        )?;
        write!(f, " }}")?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKeyShare {
    #[serde(with = "serde_bytes")]
    pub encrypted_key_share: Vec<u8>,
    /// Node's Ed25519 signature for optimized variant
    #[serde(with = "serde_bytes")]
    pub node_signature: Vec<u8>,
}

impl_display_using_debug!(VetKdEncryptedKeyShare);

impl std::fmt::Debug for VetKdEncryptedKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VetKdEncryptedKeyShare {{ ")?;
        write!(
            f,
            "encrypted_key_share: 0x{}",
            hex::encode(&self.encrypted_key_share)
        )?;
        write!(
            f,
            ", node_signature: 0x{}",
            hex::encode(&self.node_signature)
        )?;
        write!(f, " }}")?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKey {
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}

impl_display_using_debug!(VetKdEncryptedKey);

impl std::fmt::Debug for VetKdEncryptedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VetKdEncryptedKey {{ ")?;
        write!(f, "encrypted_key: 0x{}", hex::encode(&self.encrypted_key))?;
        write!(f, " }}")?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VedKdKeyShareCreationError {
    ThresholdSigDataNotFound(ThresholdSigDataNotFoundError),
    SecretKeyNotFound { dkg_id: NiDkgId, key_id: String },
    KeyIdInstantiationError(String),
    TransientInternalError(String),
}
impl_display_using_debug!(VedKdKeyShareCreationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareVerificationError {}
impl_display_using_debug!(VetKdKeyShareVerificationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareCombinationError {
    InvalidShares(Vec<NodeId>),
}
impl_display_using_debug!(VetKdKeyShareCombinationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyVerificationError {}
impl_display_using_debug!(VetKdKeyVerificationError);
