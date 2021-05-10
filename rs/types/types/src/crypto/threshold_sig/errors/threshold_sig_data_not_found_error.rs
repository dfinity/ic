//! An error that occurs if the threshold signature data has not been loaded
//! into the threshold signature data store.
use crate::crypto::threshold_sig::ni_dkg::DkgId;
use crate::crypto::CryptoError;
use std::fmt;

/// Occurs if the threshold signature data has not been loaded into the
/// threshold signature data store. Refer to the documentation of
/// `ThresholdSigner` and `ThresholdSigVerifier` for details on how to act upon
/// this error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ThresholdSigDataNotFoundError {
    ThresholdSigDataNotFound { dkg_id: DkgId },
}

impl fmt::Display for ThresholdSigDataNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThresholdSigDataNotFoundError::ThresholdSigDataNotFound { dkg_id } => write!(
                f,
                "Cannot find transcript data for DKG ID {:?} in data store",
                dkg_id
            ),
        }
    }
}

impl From<ThresholdSigDataNotFoundError> for CryptoError {
    fn from(error: ThresholdSigDataNotFoundError) -> Self {
        match error {
            ThresholdSigDataNotFoundError::ThresholdSigDataNotFound { dkg_id } => {
                CryptoError::ThresholdSigDataNotFound { dkg_id }
            }
        }
    }
}
