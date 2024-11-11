//! Errors encountered during CSP canister threshold signature operations.
use crate::KeyId;
use ic_crypto_internal_threshold_sig_ecdsa::CanisterThresholdSerializationError;
use ic_interfaces::crypto::IDkgDealingEncryptionKeyRotationError;
use serde::{Deserialize, Serialize};

/// Errors encountered during generation of a MEGa encryption key pair.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CspCreateMEGaKeyError {
    SerializationError(CanisterThresholdSerializationError),
    TransientInternalError { internal_error: String },
    DuplicateKeyId { key_id: KeyId },
    InternalError { internal_error: String },
}

impl std::fmt::Display for CspCreateMEGaKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::SerializationError(tecdsa_err) => write!(
                f,
                "Error (de)serializing MEGa keypair: Underlying operation failed: {:?}",
                tecdsa_err
            ),
            Self::TransientInternalError { internal_error } => write!(
                f,
                "Error creating MEGa keypair: Transient internal error: {}",
                internal_error
            ),
            Self::DuplicateKeyId { key_id } => {
                write!(f, "A key with ID {} has already been inserted", key_id)
            }
            Self::InternalError { internal_error } => {
                write!(
                    f,
                    "Error creating MEGa keypair: Internal error: {}",
                    internal_error
                )
            }
        }
    }
}

impl From<CspCreateMEGaKeyError> for IDkgDealingEncryptionKeyRotationError {
    fn from(error: CspCreateMEGaKeyError) -> Self {
        IDkgDealingEncryptionKeyRotationError::KeyGenerationError(format!("{:?}", error))
    }
}
