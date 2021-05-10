//! Errors related to dealing creation.
use super::*;

use crate::crypto::error::{InvalidArgumentError, KeyNotFoundError};
use crate::registry::RegistryClientError;

/// Occurs if creating a dealing using `NiDkgAlgorithm::create_dealing` fails.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum DkgCreateDealingError {
    NotADealer(NotADealerError),
    FsEncryptionPublicKeyNotInRegistry(FsEncryptionPublicKeyNotInRegistryError),
    Registry(RegistryClientError),
    MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError),
    FsDecryptionKeyNotInSecretKeyStore(KeyNotFoundError),
    InvalidTranscript(InvalidArgumentError),
    // Reminder: document error definition changes on `NiDkgAlgorithm::create_dealing`.
}

impl fmt::Display for DkgCreateDealingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = "Failed to create dealing: ";
        match self {
            DkgCreateDealingError::NotADealer(error) => write!(f, "{}{}", prefix, error),
            DkgCreateDealingError::FsEncryptionPublicKeyNotInRegistry(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgCreateDealingError::Registry(error) => write!(f, "{}{}", prefix, error),
            DkgCreateDealingError::MalformedFsEncryptionPublicKey(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgCreateDealingError::InvalidTranscript(error) => write!(f, "{}{}", prefix, error),
            DkgCreateDealingError::FsDecryptionKeyNotInSecretKeyStore(error) => {
                write!(f, "{}{}", prefix, error)
            }
        }
    }
}

impl fmt::Debug for DkgCreateDealingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}
