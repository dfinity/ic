use crate::CspPublicKeyStoreError;
use ic_interfaces::crypto::CurrentNodePublicKeysError;
use ic_types::crypto::CryptoError;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodePublicKeyDataError {
    TransientInternalError(String),
}

impl fmt::Display for NodePublicKeyDataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NodePublicKeyDataError::TransientInternalError(details) => {
                let appendix = if details.is_empty() {
                    String::default()
                } else {
                    format!(": {}", details)
                };
                write!(
            f,
            "RPC error occurred while accessing the remote vault for NodePublicKeyData{appendix}"
        )
            }
        }
    }
}

// conversion from the CSP level to the public API level
impl From<NodePublicKeyDataError> for CurrentNodePublicKeysError {
    fn from(e: NodePublicKeyDataError) -> CurrentNodePublicKeysError {
        match e {
            NodePublicKeyDataError::TransientInternalError(details) => {
                CurrentNodePublicKeysError::TransientInternalError(details)
            }
        }
    }
}

impl From<CspPublicKeyStoreError> for NodePublicKeyDataError {
    fn from(e: CspPublicKeyStoreError) -> NodePublicKeyDataError {
        match e {
            CspPublicKeyStoreError::TransientInternalError(details) => {
                NodePublicKeyDataError::TransientInternalError(details)
            }
        }
    }
}

impl From<NodePublicKeyDataError> for CryptoError {
    fn from(e: NodePublicKeyDataError) -> CryptoError {
        match e {
            NodePublicKeyDataError::TransientInternalError(details) => {
                CryptoError::TransientInternalError {
                    internal_error: details,
                }
            }
        }
    }
}
