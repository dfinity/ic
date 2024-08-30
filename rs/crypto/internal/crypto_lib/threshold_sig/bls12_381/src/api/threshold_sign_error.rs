//! Error encountered during threshold signing.
use ic_types::crypto::AlgorithmId;

/// Error encountered during threshold signing in the crypto library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClibThresholdSignError {
    /// The threshold signing secret key is malformed.
    MalformedSecretKey { algorithm: AlgorithmId },
}
