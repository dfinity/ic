//! Errors encountered during CSP canister threshold signature operations.
use crate::secret_key_store::SecretKeyStoreError;
use crate::KeyId;
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
    DuplicateKeyId { key_id: KeyId },
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
            Self::DuplicateKeyId { key_id } => {
                write!(f, "A key with ID {} has already been inserted", key_id)
            }
        }
    }
}

impl From<SecretKeyStoreError> for CspCreateMEGaKeyError {
    fn from(err: SecretKeyStoreError) -> Self {
        match err {
            SecretKeyStoreError::DuplicateKeyId(key_id) => {
                CspCreateMEGaKeyError::DuplicateKeyId { key_id }
            }
        }
    }
}
