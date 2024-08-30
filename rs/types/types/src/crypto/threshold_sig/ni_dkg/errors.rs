//! Errors for non-interactive DKG.
use crate::{NodeId, RegistryVersion};
use ic_crypto_internal_types::encrypt::forward_secure as ifs;
use std::fmt;

pub mod create_dealing_error;
pub mod create_transcript_error;
pub mod key_removal_error;
pub mod load_transcript_error;
pub mod transcripts_to_retain_validation_error;
pub mod verify_dealing_error;

/// Occurs if a node ID that should be a dealer is not a dealer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NotADealerError {
    pub node_id: NodeId,
}

impl fmt::Display for NotADealerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "This operation requires node ({}) to be a dealer, but it is not.",
            self.node_id
        )
    }
}

/// Occurs if the forward-secure encryption public key cannot be found in the
/// registry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FsEncryptionPublicKeyNotInRegistryError {
    pub registry_version: RegistryVersion,
    pub node_id: NodeId,
}

impl fmt::Display for FsEncryptionPublicKeyNotInRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Dealing encryption public key for node id {} not found in registry for version {}",
            self.node_id, self.registry_version,
        )
    }
}

/// Occurs if the forward-secure encryption public key is malformed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MalformedFsEncryptionPublicKeyError {
    pub internal_error: String,
}

impl From<ifs::MalformedFsEncryptionPublicKeyError> for MalformedFsEncryptionPublicKeyError {
    fn from(internal_malformed_fs_enc_pubkey: ifs::MalformedFsEncryptionPublicKeyError) -> Self {
        Self {
            internal_error: format!("{}", internal_malformed_fs_enc_pubkey),
        }
    }
}

impl fmt::Display for MalformedFsEncryptionPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The (forward-secure) encryption public key is malformed: {}",
            &self.internal_error
        )
    }
}
