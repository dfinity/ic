//! Error types used in the public DKG API.
//!
//! This defines two types of errors:
//! * Individual error conditions;
//! * Enumerations of all the error conditions that a method can return.

pub use ic_types::crypto::error::{
    InvalidArgumentError, KeyNotFoundError, MalformedDataError, MalformedPublicKeyError,
};
use ic_types::crypto::AlgorithmId;
use serde::{Deserialize, Serialize};

mod conversions;
mod imported_conversions;

#[cfg(test)]
mod tests;

/// Cognate to CryptoError::MalformedSecretKey
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct MalformedSecretKeyError {
    pub algorithm: AlgorithmId,
    pub internal_error: String,
}

/// Proof of possession could not be parsed.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MalformedPopError {
    pub algorithm: AlgorithmId,
    pub internal_error: String,
    pub bytes: Option<Vec<u8>>,
}

/// A size is unsupported by this machine; this is not a protocol error as other
/// machines may be able to complete this instruction successfully.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct SizeError {
    pub message: String,
}

/// An internal error.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct InternalError {
    pub internal_error: String,
}
