use crate::CspPublicKeyStoreError;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgLoadPrivateKeyError, CspDkgUpdateFsEpochError, KeyNotFoundError, MalformedDataError,
};
use ic_interfaces::crypto::{CurrentNodePublicKeysError, IdkgDealingEncPubKeysCountError};
use ic_types::crypto::{AlgorithmId, CryptoError};
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

impl From<NodePublicKeyDataError> for DkgDealingEncryptionKeyIdRetrievalError {
    fn from(e: NodePublicKeyDataError) -> DkgDealingEncryptionKeyIdRetrievalError {
        match e {
            NodePublicKeyDataError::TransientInternalError(details) => {
                DkgDealingEncryptionKeyIdRetrievalError::TransientInternalError(details)
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

impl From<NodePublicKeyDataError> for IdkgDealingEncPubKeysCountError {
    fn from(e: NodePublicKeyDataError) -> Self {
        match e {
            NodePublicKeyDataError::TransientInternalError(internal_error) => {
                IdkgDealingEncPubKeysCountError::TransientInternalError(internal_error)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DkgDealingEncryptionKeyIdRetrievalError {
    /// Missing DKG dealing encryption key
    KeyNotFound,
    /// The public key could not be parsed or was otherwise invalid
    MalformedPublicKey {
        /// Raw key data
        key_bytes: Vec<u8>,
        /// Auxiliary details
        details: String,
    },
    /// Transient internal error occurred
    TransientInternalError(String),
}

impl fmt::Display for DkgDealingEncryptionKeyIdRetrievalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DkgDealingEncryptionKeyIdRetrievalError::KeyNotFound => {
                write!(f, "missing DKG dealing encryption key")
            }
            DkgDealingEncryptionKeyIdRetrievalError::MalformedPublicKey { key_bytes, details } => {
                write!(
                    f,
                    "the public key could not be parsed or was otherwise invalid: \
                    key bytes='{key_bytes:?}', details='{details}'"
                )
            }
            DkgDealingEncryptionKeyIdRetrievalError::TransientInternalError(details) => {
                write!(
                    f,
                    "Transient internal error occurred while accessing the remote vault for retrieving the \
                    DKG deadling encryption key id: {details}"
                )
            }
        }
    }
}

impl From<DkgDealingEncryptionKeyIdRetrievalError> for CspDkgUpdateFsEpochError {
    fn from(e: DkgDealingEncryptionKeyIdRetrievalError) -> CspDkgUpdateFsEpochError {
        match e {
            DkgDealingEncryptionKeyIdRetrievalError::KeyNotFound => {
                CspDkgUpdateFsEpochError::KeyNotFoundError(KeyNotFoundError {
                    internal_error: String::from("Missing DKG dealing encryption key"),
                    key_id: String::from(
                        "Public key not found, therefore the key id could not be derived",
                    ),
                })
            }
            DkgDealingEncryptionKeyIdRetrievalError::MalformedPublicKey {
                key_bytes,
                details: description,
            } => CspDkgUpdateFsEpochError::MalformedPublicKeyError(MalformedDataError {
                algorithm: AlgorithmId::NiDkg_Groth20_Bls12_381,
                internal_error: description,
                data: Some(key_bytes),
            }),
            DkgDealingEncryptionKeyIdRetrievalError::TransientInternalError(details) => {
                CspDkgUpdateFsEpochError::TransientInternalError(InternalError {
                    internal_error: details,
                })
            }
        }
    }
}

impl From<DkgDealingEncryptionKeyIdRetrievalError> for CspDkgLoadPrivateKeyError {
    fn from(e: DkgDealingEncryptionKeyIdRetrievalError) -> CspDkgLoadPrivateKeyError {
        match e {
            DkgDealingEncryptionKeyIdRetrievalError::KeyNotFound => {
                CspDkgLoadPrivateKeyError::KeyNotFoundError(KeyNotFoundError {
                    internal_error: String::from("Missing DKG dealing encryption key"),
                    key_id: String::from(
                        "Public key not found, therefore the key id could not be derived",
                    ),
                })
            }
            DkgDealingEncryptionKeyIdRetrievalError::MalformedPublicKey {
                key_bytes,
                details: description,
            } => CspDkgLoadPrivateKeyError::MalformedPublicKeyError(MalformedDataError {
                algorithm: AlgorithmId::NiDkg_Groth20_Bls12_381,
                internal_error: description,
                data: Some(key_bytes),
            }),
            DkgDealingEncryptionKeyIdRetrievalError::TransientInternalError(details) => {
                CspDkgLoadPrivateKeyError::TransientInternalError(InternalError {
                    internal_error: details,
                })
            }
        }
    }
}
