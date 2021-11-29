//! Errors related to loading the transcript.
use crate::crypto::error::{InternalError, InvalidArgumentError};
use crate::crypto::threshold_sig::ni_dkg::errors::{
    FsEncryptionPublicKeyNotInRegistryError, MalformedFsEncryptionPublicKeyError,
};
use crate::registry::RegistryClientError;
use core::fmt;

/// Occurs if loading a transcript using `NiDkgAlgorithm::load_transcript`
/// fails.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DkgLoadTranscriptError {
    FsEncryptionPublicKeyNotInRegistry(FsEncryptionPublicKeyNotInRegistryError),
    Registry(RegistryClientError),
    InvalidTranscript(InvalidArgumentError),
    MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError),
    InternalError(InternalError),
    // Reminder: document error definition changes on `NiDkgAlgorithm::load_transcript`.
}

impl fmt::Display for DkgLoadTranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = "Failed to load transcript: ";
        match self {
            DkgLoadTranscriptError::Registry(error) => write!(f, "{}{}", prefix, error),
            DkgLoadTranscriptError::FsEncryptionPublicKeyNotInRegistry(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgLoadTranscriptError::MalformedFsEncryptionPublicKey(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgLoadTranscriptError::InvalidTranscript(error) => write!(f, "{}{}", prefix, error),
            DkgLoadTranscriptError::InternalError(error) => write!(f, "{}{}", prefix, error),
        }
    }
}
