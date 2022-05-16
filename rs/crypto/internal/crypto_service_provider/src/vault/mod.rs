use crate::api::CspThresholdSignError;
use crate::vault::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError, CspSecretKeyStoreContainsError, CspThresholdSignatureKeygenError,
    CspTlsKeygenError, CspTlsSignError,
};
use ic_types::crypto::CryptoError;

pub mod api;
pub mod local_csp_vault;
pub mod remote_csp_vault;
#[cfg(test)]
mod test_utils;

impl From<tarpc::client::RpcError> for CspThresholdSignError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspThresholdSignError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<tarpc::client::RpcError> for CspThresholdSignatureKeygenError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspThresholdSignatureKeygenError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<tarpc::client::RpcError> for CspMultiSignatureError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspMultiSignatureError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<tarpc::client::RpcError> for CspMultiSignatureKeygenError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspMultiSignatureKeygenError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<tarpc::client::RpcError> for CspBasicSignatureError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspBasicSignatureError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<tarpc::client::RpcError> for CspBasicSignatureKeygenError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspBasicSignatureKeygenError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<tarpc::client::RpcError> for CspTlsKeygenError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspTlsKeygenError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<tarpc::client::RpcError> for CspTlsSignError {
    fn from(e: tarpc::client::RpcError) -> Self {
        CspTlsSignError::InternalError {
            internal_error: e.to_string(),
        }
    }
}

impl From<CspBasicSignatureError> for CryptoError {
    fn from(e: CspBasicSignatureError) -> CryptoError {
        match e {
            CspBasicSignatureError::SecretKeyNotFound { algorithm, key_id } => {
                CryptoError::SecretKeyNotFound { algorithm, key_id }
            }
            CspBasicSignatureError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported algorithm".to_string(),
                }
            }
            CspBasicSignatureError::WrongSecretKeyType { algorithm } => {
                CryptoError::InvalidArgument {
                    message: format!("Wrong secret key type: {:?}", algorithm),
                }
            }
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
            CspBasicSignatureKeygenError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported algorithm".to_string(),
                }
            }
            CspBasicSignatureKeygenError::InternalError { internal_error } => {
                CryptoError::InvalidArgument {
                    message: format!("Internal error: {}", internal_error),
                }
            }
        }
    }
}

impl From<CspMultiSignatureError> for CryptoError {
    fn from(e: CspMultiSignatureError) -> CryptoError {
        match e {
            CspMultiSignatureError::SecretKeyNotFound { algorithm, key_id } => {
                CryptoError::SecretKeyNotFound { algorithm, key_id }
            }
            CspMultiSignatureError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported algorithm".to_string(),
                }
            }
            CspMultiSignatureError::WrongSecretKeyType { algorithm } => {
                CryptoError::InvalidArgument {
                    message: format!("Wrong secret key type: {:?}", algorithm),
                }
            }
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
            CspMultiSignatureKeygenError::UnsupportedAlgorithm { algorithm } => {
                CryptoError::AlgorithmNotSupported {
                    algorithm,
                    reason: "Unsupported algorithm".to_string(),
                }
            }
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
