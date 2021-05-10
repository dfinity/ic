//! Errors related to verifying a dealing.
use super::*;

use crate::crypto::error::{InvalidArgumentError, MalformedPublicKeyError};
use crate::registry::RegistryClientError;

/// Occurs if verifying a dealing using `NiDkgAlgorithm::verify_dealing` fails.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum DkgVerifyDealingError {
    NotADealer(NotADealerError),
    FsEncryptionPublicKeyNotInRegistry(FsEncryptionPublicKeyNotInRegistryError),
    Registry(RegistryClientError),
    MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError),
    MalformedResharingTranscriptInConfig(MalformedPublicKeyError),
    InvalidDealingError(InvalidArgumentError),
    // Reminder: document error definition changes on `NiDkgAlgorithm::verify_dealing`.
}

impl fmt::Display for DkgVerifyDealingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = "Failed to verify dealing: ";
        match self {
            DkgVerifyDealingError::NotADealer(error) => write!(f, "{}{}", prefix, error),
            DkgVerifyDealingError::FsEncryptionPublicKeyNotInRegistry(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgVerifyDealingError::Registry(error) => write!(f, "{}{}", prefix, error),
            DkgVerifyDealingError::MalformedFsEncryptionPublicKey(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgVerifyDealingError::MalformedResharingTranscriptInConfig(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgVerifyDealingError::InvalidDealingError(error) => write!(f, "{}{}", prefix, error),
        }
    }
}

impl fmt::Debug for DkgVerifyDealingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<RegistryClientError> for DkgVerifyDealingError {
    fn from(registry_client_error: RegistryClientError) -> Self {
        DkgVerifyDealingError::Registry(registry_client_error)
    }
}
