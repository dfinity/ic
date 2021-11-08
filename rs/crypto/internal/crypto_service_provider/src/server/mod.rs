use crate::server::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError,
};
use ic_types::crypto::CryptoError;

pub mod api;
pub mod local_csp_server;

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
        }
    }
}
