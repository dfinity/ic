//! An error that may occur when threshold signing.
use crate::crypto::threshold_sig::errors::threshold_sig_data_not_found_error::ThresholdSigDataNotFoundError;
use crate::crypto::threshold_sig::ni_dkg::NiDkgId;
use crate::crypto::{AlgorithmId, CryptoError};
use std::fmt;

/// A threshold signing error.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum ThresholdSignError {
    ThresholdSigDataNotFound(ThresholdSigDataNotFoundError),
    SecretKeyNotFound {
        dkg_id: NiDkgId,
        algorithm: AlgorithmId,
        key_id: String,
    },
    KeyIdInstantiationError(String),
    TransientInternalError(String),
    InternalError(String),
}

impl fmt::Display for ThresholdSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = "Error in threshold signing: ";
        match self {
            ThresholdSignError::ThresholdSigDataNotFound(error) => write!(f, "{prefix}{error}"),
            ThresholdSignError::SecretKeyNotFound {
                dkg_id,
                algorithm,
                key_id,
            } => write!(
                f,
                "{prefix}Cannot find threshold signing {algorithm:?} secret key for DKG ID {dkg_id} with key id {key_id} in the secret key store. \
                Reloading the transcript does not help since the transcript has been loaded already."
            ),
            ThresholdSignError::TransientInternalError(internal_error) => write!(
                f,
                "Transient internal error in threshold signing: {internal_error}"
            ),
            ThresholdSignError::KeyIdInstantiationError(internal_error) => write! {
                f,
                "Error instantiating KeyId from public coefficients: {internal_error}"
            },
            ThresholdSignError::InternalError(internal_error) => {
                write!(f, "{prefix}Internal error: {internal_error}")
            }
        }
    }
}

impl From<ThresholdSignError> for CryptoError {
    fn from(error: ThresholdSignError) -> Self {
        match error {
            ThresholdSignError::ThresholdSigDataNotFound(
                ThresholdSigDataNotFoundError::ThresholdSigDataNotFound { dkg_id },
            ) => CryptoError::ThresholdSigDataNotFound { dkg_id },
            ThresholdSignError::SecretKeyNotFound {
                dkg_id: _,
                algorithm,
                key_id,
            } => {
                // ThresholdSigDataNotFound must not be used here, see CRP-586.
                CryptoError::SecretKeyNotFound { algorithm, key_id }
            }
            ThresholdSignError::TransientInternalError(internal_error) => {
                CryptoError::TransientInternalError { internal_error }
            }
            ThresholdSignError::KeyIdInstantiationError(internal_error) => {
                CryptoError::InternalError { internal_error }
            }
            ThresholdSignError::InternalError(internal_error) => {
                CryptoError::InternalError { internal_error }
            }
        }
    }
}

impl From<ThresholdSigDataNotFoundError> for ThresholdSignError {
    fn from(error: ThresholdSigDataNotFoundError) -> Self {
        ThresholdSignError::ThresholdSigDataNotFound(error)
    }
}
