use crate::crypto::keygen::IDkgDealingEncryptionKeyRotationError;
use ic_types::crypto::CryptoError;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CurrentNodePublicKeysError {
    TransientInternalError(String),
}

impl fmt::Display for CurrentNodePublicKeysError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CurrentNodePublicKeysError::TransientInternalError(details) => {
                let appendix = if details.is_empty() {
                    String::default()
                } else {
                    format!(": {}", details)
                };

                write!(
                    f,
                    "Transient internal error occurred while retrieving current public keys{appendix}"
                )
            }
        }
    }
}

impl From<CurrentNodePublicKeysError> for IDkgDealingEncryptionKeyRotationError {
    fn from(e: CurrentNodePublicKeysError) -> IDkgDealingEncryptionKeyRotationError {
        match e {
            CurrentNodePublicKeysError::TransientInternalError(details) => {
                IDkgDealingEncryptionKeyRotationError::TransientInternalError(details)
            }
        }
    }
}

impl From<CurrentNodePublicKeysError> for CryptoError {
    fn from(e: CurrentNodePublicKeysError) -> CryptoError {
        match e {
            CurrentNodePublicKeysError::TransientInternalError(details) => {
                CryptoError::TransientInternalError {
                    internal_error: details,
                }
            }
        }
    }
}
