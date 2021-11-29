//! Defines crypto error types.
pub mod conversions;
pub use super::CryptoError;
use crate::crypto::{AlgorithmId, KeyId};
use serde::{Deserialize, Serialize};
use std::fmt; // Probably move all the errors into this file

/// Occurs if an argument is invalid.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvalidArgumentError {
    pub message: String,
}

impl fmt::Display for InvalidArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Semantic error in argument: {}", &self.message)
    }
}

/// An internal error.  Occurs e.g. when an internal RPC communication fails.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InternalError {
    pub internal_error: String,
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Internal error: {}", &self.internal_error)
    }
}

/// Occurs if a public key is malformed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MalformedPublicKeyError {
    pub algorithm: AlgorithmId,
    pub key_bytes: Option<Vec<u8>>,
    pub internal_error: String,
}

impl fmt::Display for MalformedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Malformed {:?} public key: 0x{:?}. Internal error: {}",
            &self.algorithm,
            &self.key_bytes.as_ref().map(hex::encode),
            &self.internal_error
        )
    }
}

/// Malformed X for other types of X.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MalformedDataError {
    pub algorithm: AlgorithmId,
    pub internal_error: String,
    pub data: Option<Vec<u8>>,
}

impl fmt::Display for MalformedDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Malformed {:?} data: 0x{:?}. Internal error: {}",
            &self.algorithm,
            &self.data.as_ref().map(hex::encode),
            &self.internal_error
        )
    }
}

/// The secret key was not found in the secret key store.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyNotFoundError {
    pub internal_error: String,
    pub key_id: KeyId,
}

impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Secret key with id {} not found in secret key store. Internal error: {}",
            &self.key_id, &self.internal_error
        )
    }
}

impl From<MalformedPublicKeyError> for MalformedDataError {
    fn from(error: MalformedPublicKeyError) -> Self {
        let MalformedPublicKeyError {
            algorithm,
            key_bytes,
            internal_error,
        } = error;
        MalformedDataError {
            algorithm,
            internal_error,
            data: key_bytes,
        }
    }
}
