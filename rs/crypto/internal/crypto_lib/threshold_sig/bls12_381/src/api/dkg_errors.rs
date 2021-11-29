//! Error types used in the public DKG API.
//!
//! This defines two types of errors:
//! * Individual error conditions;
//! * Enumerations of all the error conditions that a method can return.

pub use ic_types::crypto::error::{
    InvalidArgumentError, KeyNotFoundError, MalformedDataError, MalformedPublicKeyError,
};
use ic_types::crypto::{AlgorithmId, CryptoError};
use serde::{Deserialize, Serialize};

mod conversions;
mod imported_conversions;

#[cfg(test)]
mod tests;

/// Cognate to CryptoError::MalformedSecretKey
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalformedSecretKeyError {
    pub algorithm: AlgorithmId,
    pub internal_error: String,
}

/// Proof of possession could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedPopError {
    pub algorithm: AlgorithmId,
    pub internal_error: String,
    pub bytes: Option<Vec<u8>>,
}

/// A size is unsupported by this machine; this is not a protocol error as other
/// machines may be able to complete this instruction successfully.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeError {
    pub message: String,
}

/// An internal error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalError {
    pub internal_error: String,
}

/// Creation of an ephemeral key failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgCreateEphemeralError {
    /// There is an incompatible preexisting key for this DKG.
    MalformedSecretKeyError(MalformedSecretKeyError),
}

/// Verification of an ephemeral key failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgVerifyEphemeralError {
    /// The public key could not be parsed.
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// The PoP could not be parsed.
    MalformedPopError(MalformedPopError),
    /// The proof in the "proof of possession" failed.
    InvalidPopError(MalformedPopError),
}

/// Dealing of shares during DKG failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgCreateDealingError {
    /// Precondition error: The ephemeral secret key was not in the secret key
    /// store.
    KeyNotFoundError(KeyNotFoundError),
    /// Precondition error: The ephemeral secret key is malformed.  Was the
    /// correct algorithm ID used?
    MalformedSecretKeyError(MalformedSecretKeyError),
    /// The threshold scheme does not support the supplied parameters.
    UnsupportedThresholdParameters(CryptoError),
    /// One of the receiver public keys is invalid.
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

/// Verification of a dealing during DKG failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgVerifyDealingError {
    /// Precondition error: One of the receiver public keys is malformed.  This
    /// should have been checked with verify_ephemeral().
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// The dealing could not be parsed.
    MalformedDealingError(MalformedDataError),
    /// The dealing is invalid.
    InvalidDealingError(InvalidArgumentError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

/// Creation of a DKG response failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgCreateResponseError {
    /// Precondition error: The ephemeral secret key was not in the secret key
    /// store.
    KeyNotFoundError(KeyNotFoundError),
    /// Precondition error: The ephemeral secret key is malformed.  Was the
    /// correct algorithm ID used?
    MalformedSecretKeyError(MalformedSecretKeyError),
    /// Precondition error: This node's public key is malformed.
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// Precondition error: error: This node's PoP is malformed.
    MalformedPopError(MalformedPopError),
    /// Precondition error: A dealing should not have passed verification.
    MalformedDealingError(MalformedDataError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

/// Verification of a DKG response failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgVerifyResponseError {
    /// Precondition error: One of the public keys is malformed.
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// Precondition error: One of the pops is malformed.
    MalformedPopError(MalformedDataError),
    /// Precondition error: The dealing should not have passed validation.
    MalformedDealingError(MalformedDataError),
    /// The receiver index for the response is out of bounds; the response may
    /// be discarded.
    InvalidReceiverIndexError(InvalidArgumentError),
    /// This response cannot be parsed and may be discarded.
    MalformedResponseError(MalformedDataError),
    /// This response is invalid and may be discarded.
    InvalidResponseError(InvalidArgumentError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

/// Creation of a DKG transcript failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgCreateTranscriptError {
    /// Precondition error: One of the public keys is malformed.
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// Precondition error: One of the dealings is invalid.  Only verified
    /// dealings should be used.
    MalformedDealingError(MalformedDataError),
    /// Precondition error: One of the responses is invalid.
    MalformedResponseError(MalformedDataError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
    /// The threshold is so large that it is impossible to have sufficient data.
    InvalidThresholdError(InvalidArgumentError),
    /// There were insufficient valid dealings or responses to proceed safely.
    InsufficientDataError(InvalidArgumentError),
}

/// Loading of a private key from a DKG transcript failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgLoadPrivateKeyError {
    /// Precondition error: The ephemeral key was not found.
    KeyNotFoundError(KeyNotFoundError),
    /// Precondition error: The ephemeral key could not be parsed.  Was the
    /// correct algorithm ID used?
    MalformedSecretKeyError(MalformedSecretKeyError),
    /// The transcript could not be parsed.
    MalformedTranscriptError(MalformedDataError),
    /// The transcript cannot be used to generate the desired private key.
    InvalidTranscriptError(InvalidArgumentError),
}

/// Creation of a DKG resharing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgCreateReshareDealingError {
    /// Precondition error: The ephemeral secret key was not in the secret key
    /// store.
    KeyNotFoundError(KeyNotFoundError),
    /// Precondition error: The ephemeral secret key is malformed.  Was the
    /// correct algorithm ID used?
    MalformedSecretKeyError(MalformedSecretKeyError),
    /// The threshold scheme does not support the supplied parameters.
    UnsupportedThresholdParameters(CryptoError),
    /// One of the receiver public keys is invalid.
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

impl From<DkgCreateDealingError> for DkgCreateReshareDealingError {
    fn from(error: DkgCreateDealingError) -> Self {
        match error {
            DkgCreateDealingError::KeyNotFoundError(error) => {
                DkgCreateReshareDealingError::KeyNotFoundError(error)
            }
            DkgCreateDealingError::MalformedSecretKeyError(error) => {
                DkgCreateReshareDealingError::MalformedSecretKeyError(error)
            }
            DkgCreateDealingError::UnsupportedThresholdParameters(error) => {
                DkgCreateReshareDealingError::UnsupportedThresholdParameters(error)
            }
            DkgCreateDealingError::MalformedPublicKeyError(error) => {
                DkgCreateReshareDealingError::MalformedPublicKeyError(error)
            }
            DkgCreateDealingError::SizeError(error) => {
                DkgCreateReshareDealingError::SizeError(error)
            }
        }
    }
}

/// Verification of a DKG resharing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgVerifyReshareDealingError {
    /// Precondition error: One of the receiver public keys is malformed.  This
    /// should have been checked with verify_ephemeral().
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// The dealing could not be parsed.
    MalformedDealingError(MalformedDataError),
    /// The dealing is invalid.
    InvalidDealingError(InvalidArgumentError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
    /// The public coefficients could not be parsed
    MalformedPublicCoefficientsError(MalformedDataError),
}

impl From<DkgVerifyDealingError> for DkgVerifyReshareDealingError {
    fn from(error: DkgVerifyDealingError) -> Self {
        match error {
            DkgVerifyDealingError::MalformedPublicKeyError(error) => {
                DkgVerifyReshareDealingError::MalformedPublicKeyError(error)
            }
            DkgVerifyDealingError::MalformedDealingError(error) => {
                DkgVerifyReshareDealingError::MalformedDealingError(error)
            }
            DkgVerifyDealingError::InvalidDealingError(error) => {
                DkgVerifyReshareDealingError::InvalidDealingError(error)
            }
            DkgVerifyDealingError::SizeError(error) => {
                DkgVerifyReshareDealingError::SizeError(error)
            }
        }
    }
}

/// Creation of a DKG transcript from a resharing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgCreateReshareTranscriptError {
    /// Precondition error: One of the public keys is malformed.
    MalformedPublicKeyError(MalformedPublicKeyError),
    /// Precondition error: One of the dealings is invalid.  Only verified
    /// dealings should be used.
    MalformedDealingError(MalformedDataError),
    /// Precondition error: One of the responses is invalid.
    MalformedResponseError(MalformedDataError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
    /// The threshold is so large that it is impossible to have sufficient data.
    InvalidThresholdError(InvalidArgumentError),
    /// There were insufficient valid dealings or responses to proceed safely.
    InsufficientDataError(InvalidArgumentError),
}

impl From<DkgCreateTranscriptError> for DkgCreateReshareTranscriptError {
    fn from(error: DkgCreateTranscriptError) -> Self {
        match error {
            DkgCreateTranscriptError::MalformedPublicKeyError(error) => {
                DkgCreateReshareTranscriptError::MalformedPublicKeyError(error)
            }
            DkgCreateTranscriptError::MalformedDealingError(error) => {
                DkgCreateReshareTranscriptError::MalformedDealingError(error)
            }
            DkgCreateTranscriptError::MalformedResponseError(error) => {
                DkgCreateReshareTranscriptError::MalformedResponseError(error)
            }
            DkgCreateTranscriptError::SizeError(error) => {
                DkgCreateReshareTranscriptError::SizeError(error)
            }
            DkgCreateTranscriptError::InvalidThresholdError(error) => {
                DkgCreateReshareTranscriptError::InvalidThresholdError(error)
            }
            DkgCreateTranscriptError::InsufficientDataError(error) => {
                DkgCreateReshareTranscriptError::InsufficientDataError(error)
            }
        }
    }
}

impl DkgCreateDealingError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        DkgCreateDealingError::SizeError(SizeError {
            message: "Something terrible".to_string(),
        })
    }
}

impl DkgCreateReshareDealingError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        DkgCreateReshareDealingError::SizeError(SizeError {
            message: "Voice of doom".to_string(),
        })
    }
}

impl DkgVerifyDealingError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        DkgVerifyDealingError::SizeError(SizeError {
            message: "Crocodile banquet".to_string(),
        })
    }
}

impl DkgVerifyReshareDealingError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        DkgVerifyReshareDealingError::SizeError(SizeError {
            message: "Squeaky voice".to_string(),
        })
    }
}

impl DkgCreateTranscriptError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        DkgCreateTranscriptError::SizeError(SizeError {
            message: "Chicxulub".to_string(),
        })
    }
}

impl DkgCreateReshareTranscriptError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        DkgCreateReshareTranscriptError::SizeError(SizeError {
            message: "AI Singularity".to_string(),
        })
    }
}

impl DkgLoadPrivateKeyError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        DkgLoadPrivateKeyError::InvalidTranscriptError(InvalidArgumentError {
            message: "Relativism".to_string(),
        })
    }
}
