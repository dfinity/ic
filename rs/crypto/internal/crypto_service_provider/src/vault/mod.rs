use crate::key_id::KeyIdInstantiationError;
use crate::secret_key_store::panic_due_to_duplicated_key_id;
use crate::vault::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError, CspSecretKeyStoreContainsError,
};
use ic_types::crypto::CryptoError;

pub mod api;
pub mod local_csp_vault;
pub mod remote_csp_vault;
#[cfg(test)]
pub mod test_utils;

impl From<CspBasicSignatureError> for CryptoError {
    fn from(e: CspBasicSignatureError) -> CryptoError {
        match e {
            CspBasicSignatureError::SecretKeyNotFound { algorithm, key_id } => {
                CryptoError::SecretKeyNotFound {
                    algorithm,
                    key_id: key_id.to_string(),
                }
            }
            CspBasicSignatureError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported algorithm".to_string(),
                }
            }
            CspBasicSignatureError::WrongSecretKeyType {
                algorithm,
                secret_key_variant,
            } => CryptoError::InvalidArgument {
                message: format!(
                    "Wrong secret key type: {secret_key_variant} incompatible with {algorithm:?}"
                ),
            },
            CspBasicSignatureError::MalformedSecretKey { algorithm } => {
                CryptoError::MalformedSecretKey {
                    algorithm,
                    internal_error: "Malformed secret key".to_string(),
                }
            }
            // TODO(CRP-1262): using InvalidArgument here is not ideal.
            CspBasicSignatureError::InternalError { internal_error } => {
                CryptoError::InvalidArgument {
                    message: format!("Internal error: {}", internal_error),
                }
            }
        }
    }
}

impl From<CspBasicSignatureKeygenError> for CryptoError {
    fn from(e: CspBasicSignatureKeygenError) -> CryptoError {
        match e {
            CspBasicSignatureKeygenError::InternalError { internal_error } => {
                CryptoError::InternalError { internal_error }
            }
            CspBasicSignatureKeygenError::DuplicateKeyId { key_id } => {
                panic_due_to_duplicated_key_id(key_id)
            }
            CspBasicSignatureKeygenError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
        }
    }
}

impl From<CspMultiSignatureError> for CryptoError {
    fn from(e: CspMultiSignatureError) -> CryptoError {
        match e {
            CspMultiSignatureError::SecretKeyNotFound { algorithm, key_id } => {
                CryptoError::SecretKeyNotFound {
                    algorithm,
                    key_id: key_id.to_string(),
                }
            }
            CspMultiSignatureError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported algorithm".to_string(),
                }
            }
            CspMultiSignatureError::WrongSecretKeyType {
                algorithm,
                secret_key_variant,
            } => CryptoError::InvalidArgument {
                message: format!(
                    "Wrong secret key type: expected {algorithm:?} but found {secret_key_variant}"
                ),
            },
            CspMultiSignatureError::InternalError { internal_error } => {
                CryptoError::InvalidArgument {
                    message: internal_error,
                }
            }
        }
    }
}

impl From<CspMultiSignatureKeygenError> for CryptoError {
    fn from(e: CspMultiSignatureKeygenError) -> CryptoError {
        match e {
            CspMultiSignatureKeygenError::MalformedPublicKey {
                algorithm,
                key_bytes,
                internal_error,
            } => CryptoError::MalformedPublicKey {
                algorithm,
                key_bytes,
                internal_error,
            },
            CspMultiSignatureKeygenError::InternalError { internal_error } => {
                CryptoError::InvalidArgument {
                    message: internal_error,
                }
            }
            CspMultiSignatureKeygenError::DuplicateKeyId { key_id } => {
                panic_due_to_duplicated_key_id(key_id)
            }
            CspMultiSignatureKeygenError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
        }
    }
}

impl From<CspSecretKeyStoreContainsError> for CryptoError {
    fn from(e: CspSecretKeyStoreContainsError) -> Self {
        match e {
            CspSecretKeyStoreContainsError::InternalError { internal_error } => {
                CryptoError::InternalError { internal_error }
            }
        }
    }
}

impl From<KeyIdInstantiationError> for CspBasicSignatureKeygenError {
    fn from(error: KeyIdInstantiationError) -> Self {
        CspBasicSignatureKeygenError::InternalError {
            internal_error: format!("Cannot instantiate KeyId: {:?}", error),
        }
    }
}

impl From<KeyIdInstantiationError> for CspMultiSignatureKeygenError {
    fn from(error: KeyIdInstantiationError) -> Self {
        CspMultiSignatureKeygenError::InternalError {
            internal_error: format!("Cannot instantiate KeyId: {:?}", error),
        }
    }
}
