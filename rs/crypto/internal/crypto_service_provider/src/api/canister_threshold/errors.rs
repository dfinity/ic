//! Errors encountered during CSP canister threshold signature operations.
use ic_crypto_internal_threshold_sig_ecdsa::ThresholdEcdsaError;
use ic_types::crypto::AlgorithmId;
use serde::{Deserialize, Serialize};

/// Errors encountered during generation of a MEGa encryption key pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CspCreateMEGaKeyError {
    UnsupportedAlgorithm { algorithm_id: AlgorithmId },
    FailedKeyGeneration(ThresholdEcdsaError),
    SerializationError(ThresholdEcdsaError),
    CspServerError { internal_error: String },
}

impl std::fmt::Display for CspCreateMEGaKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm { algorithm_id } => write!(
                f,
                "Error creating MEGa keypair: Algorithm '{:?}' is not supported",
                algorithm_id
            ),
            Self::FailedKeyGeneration(tecdsa_err) => write!(
                f,
                "Error creating MEGa keypair: Underlying operation failed: {:?}",
                tecdsa_err
            ),
            Self::SerializationError(tecdsa_err) => write!(
                f,
                "Error (de)serializing MEGa keypair: Underlying operation failed: {:?}",
                tecdsa_err
            ),
            Self::CspServerError { internal_error } => write!(
                f,
                "Error creating MEGa keypair: CSP server operation failed: {:?}",
                internal_error
            ),
        }
    }
}
