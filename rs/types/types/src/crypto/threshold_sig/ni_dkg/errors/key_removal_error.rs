//! Errors related to key removal.
use crate::crypto::error::{InternalError, KeyNotFoundError};
use crate::crypto::threshold_sig::ni_dkg::errors::transcripts_to_retain_validation_error::TranscriptsToRetainValidationError;
use crate::crypto::threshold_sig::ni_dkg::errors::{
    FsEncryptionPublicKeyNotInRegistryError, MalformedFsEncryptionPublicKeyError,
};
use crate::registry::RegistryClientError;
use std::fmt;
use std::fmt::Formatter;

/// Occurs if key removal using `NiDkgAlgorithm::retain_only_active_keys` fails.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DkgKeyRemovalError {
    InputValidationError(TranscriptsToRetainValidationError),
    FsEncryptionPublicKeyNotInRegistry(FsEncryptionPublicKeyNotInRegistryError),
    MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError),
    Registry(RegistryClientError),
    FsKeyNotInSecretKeyStoreError(KeyNotFoundError),
    InternalError(InternalError),
}

impl fmt::Display for DkgKeyRemovalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}
