//! Error types used by non-interactive DKG.

use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeIndex, NumberOfNodes};
use serde::{Deserialize, Serialize};

// These are the base error types used by ni_dkg
// TODO(CRP-574): Move these up, out of dkg.
pub use super::dkg_errors::{
    InternalError, InvalidArgumentError, KeyNotFoundError, MalformedDataError, MalformedPopError,
    MalformedPublicKeyError, MalformedSecretKeyError, SizeError,
};

/// The receiver set isn't properly indexed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MisnumberedReceiverError {
    pub receiver_index: NodeIndex,
    pub number_of_receivers: NumberOfNodes,
}
impl From<MisnumberedReceiverError> for CspDkgCreateReshareDealingError {
    fn from(error: MisnumberedReceiverError) -> Self {
        let MisnumberedReceiverError {
            receiver_index,
            number_of_receivers,
        } = error;
        CspDkgCreateReshareDealingError::MisnumberedReceiverError {
            receiver_index,
            number_of_receivers,
        }
    }
}
impl From<MisnumberedReceiverError> for CspDkgVerifyDealingError {
    fn from(error: MisnumberedReceiverError) -> Self {
        let MisnumberedReceiverError {
            receiver_index,
            number_of_receivers,
        } = error;
        CspDkgVerifyDealingError::MisnumberedReceiverError {
            receiver_index,
            number_of_receivers,
        }
    }
}

/// Creation of a forward-secure keypair during DKG failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CspDkgCreateFsKeyError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    InternalError(InternalError),
}

/// Verification of a DKG forward-secure key failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CspDkgVerifyFsKeyError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    MalformedPublicKeyError(MalformedPublicKeyError),
    MalformedPopError(MalformedPopError),
    InvalidPop(()),
}

/// Updating the forward-secure epoch for DKG failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CspDkgUpdateFsEpochError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    FsKeyNotInSecretKeyStoreError(KeyNotFoundError),
    InternalError(InternalError),
}

/// Encrypting or zero-knowledge proving during DKG failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptAndZKProveError {
    /// One of the receiver public keys is invalid.
    MalformedFsPublicKeyError {
        receiver_index: NodeIndex,
        error: MalformedPublicKeyError,
    },
    /// The public coefficients are invalid
    MalformedPublicCoefficients,
}

/// Forward-secure decryption during DKG failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// The ciphertext was malformed
    MalformedCiphertext(&'static str),

    /// Receiver index was too large
    InvalidReceiverIndex {
        num_receivers: NumberOfNodes,
        node_index: NodeIndex,
    },
    /// The message was encrypted under an epoch older than the secret key.
    EpochTooOld {
        ciphertext_epoch: Epoch,
        secret_key_epoch: Epoch,
    },
    /// One of the forward-secure-encryption chunks failed to decrypt.
    InvalidChunk,
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

/// Creation of a DKG dealing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CspDkgCreateDealingError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    /// The threshold scheme does not support the supplied parameters.
    InvalidThresholdError(InvalidArgumentError),
    /// Precondition error: The receiver indices are invalid.  The receiver
    /// indices SHOULD be 0..n-1.
    MisnumberedReceiverError {
        receiver_index: NodeIndex,
        number_of_receivers: NumberOfNodes,
    },
    /// One of the receiver public keys is invalid.
    MalformedFsPublicKeyError {
        receiver_index: NodeIndex,
        error: MalformedPublicKeyError,
    },
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
    // An internal error, e.g. an RPC error.
    InternalError(InternalError),
}

impl From<EncryptAndZKProveError> for CspDkgCreateDealingError {
    fn from(error: EncryptAndZKProveError) -> CspDkgCreateDealingError {
        match error {
            EncryptAndZKProveError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            } => CspDkgCreateDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            },
            EncryptAndZKProveError::MalformedPublicCoefficients => {
                panic!("The public coefficients we created are malformed")
            }
        }
    }
}

/// Creation of a DKG resharing dealing failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CspDkgCreateReshareDealingError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    /// The threshold scheme does not support the supplied parameters.
    InvalidThresholdError(InvalidArgumentError),
    /// Precondition error: The receiver indices are invalid.  The receiver
    /// indices SHOULD be 0..n-1.
    MisnumberedReceiverError {
        receiver_index: NodeIndex,
        number_of_receivers: NumberOfNodes,
    },
    /// One of the receiver public keys is invalid.
    MalformedFsPublicKeyError {
        receiver_index: NodeIndex,
        error: MalformedPublicKeyError,
    },
    /// Precondition error: The key encryption key was not in the secret key
    /// store.
    ReshareKeyNotInSecretKeyStoreError(KeyNotFoundError),
    /// Precondition error: The key encryption key key is malformed.  Was the
    /// correct algorithm ID used?
    MalformedReshareSecretKeyError(MalformedSecretKeyError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
    // An internal error, e.g. an RPC error.
    InternalError(InternalError),
}

impl From<EncryptAndZKProveError> for CspDkgCreateReshareDealingError {
    fn from(error: EncryptAndZKProveError) -> CspDkgCreateReshareDealingError {
        match error {
            EncryptAndZKProveError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            } => CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            },
            EncryptAndZKProveError::MalformedPublicCoefficients => {
                panic!("The public coefficients we created are malformed")
            }
        }
    }
}

impl From<CspDkgCreateDealingError> for CspDkgCreateReshareDealingError {
    fn from(error: CspDkgCreateDealingError) -> Self {
        match error {
            CspDkgCreateDealingError::UnsupportedAlgorithmId(error) => {
                CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(error)
            }
            CspDkgCreateDealingError::InvalidThresholdError(error) => {
                CspDkgCreateReshareDealingError::InvalidThresholdError(error)
            }
            CspDkgCreateDealingError::MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            } => CspDkgCreateReshareDealingError::MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            },
            CspDkgCreateDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            } => CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            },
            CspDkgCreateDealingError::SizeError(error) => {
                CspDkgCreateReshareDealingError::SizeError(error)
            }
            CspDkgCreateDealingError::InternalError(error) => {
                CspDkgCreateReshareDealingError::InternalError(error)
            }
        }
    }
}

impl From<CspDkgCreateReshareDealingError> for CspDkgCreateDealingError {
    fn from(error: CspDkgCreateReshareDealingError) -> Self {
        match error {
            CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(error) => {
                CspDkgCreateDealingError::UnsupportedAlgorithmId(error)
            }
            CspDkgCreateReshareDealingError::InvalidThresholdError(error) => {
                CspDkgCreateDealingError::InvalidThresholdError(error)
            }
            CspDkgCreateReshareDealingError::ReshareKeyNotInSecretKeyStoreError(_) => {
                panic!("This error cannot be converted")
            }
            CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError(_) => {
                panic!("This error cannot be converted")
            }
            CspDkgCreateReshareDealingError::MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            } => CspDkgCreateDealingError::MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            },
            CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            } => CspDkgCreateDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            },
            CspDkgCreateReshareDealingError::SizeError(error) => {
                CspDkgCreateDealingError::SizeError(error)
            }
            CspDkgCreateReshareDealingError::InternalError(error) => {
                CspDkgCreateDealingError::InternalError(error)
            }
        }
    }
}

/// Verification of a DKG dealing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CspDkgVerifyDealingError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    /// Precondition error: The threshold is less than 1 or greater than the
    /// number of receivers.  This SHOULD never happen as these values SHOULD
    /// come from a correct DKG config.  This error does not necessarily imply
    /// that the dealing is invalid or that the dealer has acted incorrectly.
    InvalidThresholdError(InvalidArgumentError),
    /// Precondition error: The receiver indices are invalid.  The receiver
    /// indices SHOULD be 0..n-1.
    MisnumberedReceiverError {
        receiver_index: NodeIndex,
        number_of_receivers: NumberOfNodes,
    },
    /// Precondition error: One of the receiver public keys is invalid.  This
    /// SHOULD never happen if the DKG config is valid.
    MalformedFsPublicKeyError {
        receiver_index: NodeIndex,
        error: MalformedPublicKeyError,
    },
    /// The dealing could not be parsed.
    MalformedDealingError(InvalidArgumentError),
    /// The dealing is invalid.
    InvalidDealingError(InvalidArgumentError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

/// Verification of a DKG resharing dealing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CspDkgVerifyReshareDealingError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    /// Precondition error: The threshold is less than 1 or greater than the
    /// number of receivers.  This SHOULD never happen as these values SHOULD
    /// come from a correct DKG config.  This error does not necessarily imply
    /// that the dealing is invalid or that the dealer has acted incorrectly.
    InvalidThresholdError(InvalidArgumentError),
    /// Precondition error: The receiver indices are invalid.  The receiver
    /// indices SHOULD be 0..n-1.
    MisnumberedReceiverError {
        receiver_index: NodeIndex,
        number_of_receivers: NumberOfNodes,
    },
    /// Precondition error: One of the receiver public keys is invalid.  This
    /// SHOULD never happen if the DKG config is valid.
    MalformedFsPublicKeyError {
        receiver_index: NodeIndex,
        error: MalformedPublicKeyError,
    },
    /// Precondition error: The resharing public coefficients are invalid.
    MalformedResharePublicCoefficientsError(MalformedPublicKeyError),
    /// The dealing could not be parsed.
    MalformedDealingError(InvalidArgumentError),
    /// The dealing is invalid.
    InvalidDealingError(InvalidArgumentError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

impl From<CspDkgVerifyDealingError> for CspDkgVerifyReshareDealingError {
    fn from(error: CspDkgVerifyDealingError) -> Self {
        match error {
            CspDkgVerifyDealingError::UnsupportedAlgorithmId(error) => {
                CspDkgVerifyReshareDealingError::UnsupportedAlgorithmId(error)
            }
            CspDkgVerifyDealingError::InvalidThresholdError(error) => {
                CspDkgVerifyReshareDealingError::InvalidThresholdError(error)
            }
            CspDkgVerifyDealingError::MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            } => CspDkgVerifyReshareDealingError::MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            },
            CspDkgVerifyDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            } => CspDkgVerifyReshareDealingError::MalformedFsPublicKeyError {
                receiver_index,
                error,
            },
            CspDkgVerifyDealingError::MalformedDealingError(error) => {
                CspDkgVerifyReshareDealingError::MalformedDealingError(error)
            }
            CspDkgVerifyDealingError::InvalidDealingError(error) => {
                CspDkgVerifyReshareDealingError::InvalidDealingError(error)
            }
            CspDkgVerifyDealingError::SizeError(error) => {
                CspDkgVerifyReshareDealingError::SizeError(error)
            }
        }
    }
}

/// Creation of a DKG transcript failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CspDkgCreateTranscriptError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    /// Precondition error: The threshold is so large that it is impossible to
    /// have sufficient data.
    InvalidThresholdError(InvalidArgumentError),
    /// Precondition error: One of the dealings is invalid.  Only verified
    /// dealings should be used.
    InvalidDealingError {
        dealer_index: NodeIndex,
        error: InvalidArgumentError,
    },
    /// There were insufficient valid dealings to proceed safely.
    InsufficientDealingsError(InvalidArgumentError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

/// Creation of a DKG transcript after resharing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CspDkgCreateReshareTranscriptError {
    /// Precondition error: The AlgorithmId does not correspond to a NiDkg
    /// variant.
    UnsupportedAlgorithmId(AlgorithmId),
    /// Precondition error: The threshold is so large that it is impossible to
    /// have sufficient data.
    InvalidThresholdError(InvalidArgumentError),
    /// Precondition error: The reshare public coefficients are malformed.
    MalformedResharePublicCoefficientsError(MalformedPublicKeyError),
    /// Precondition error: One of the dealings is invalid.  Only verified
    /// dealings should be used.
    InvalidDealingError {
        dealer_index: NodeIndex,
        error: InvalidArgumentError,
    },
    /// There were insufficient valid dealings to proceed safely.
    InsufficientDealingsError(InvalidArgumentError),
    /// Precondition error: Resharing failed.  This is impossible if dealings
    /// are verified properly.
    ResharingFailed(InvalidArgumentError),
    /// Hardware error: This machine cannot handle this request because some
    /// parameter was too large.
    SizeError(SizeError),
}

impl From<CspDkgCreateTranscriptError> for CspDkgCreateReshareTranscriptError {
    fn from(error: CspDkgCreateTranscriptError) -> Self {
        match error {
            CspDkgCreateTranscriptError::UnsupportedAlgorithmId(error) => {
                CspDkgCreateReshareTranscriptError::UnsupportedAlgorithmId(error)
            }
            CspDkgCreateTranscriptError::InvalidThresholdError(error) => {
                CspDkgCreateReshareTranscriptError::InvalidThresholdError(error)
            }
            CspDkgCreateTranscriptError::InvalidDealingError {
                dealer_index,
                error,
            } => CspDkgCreateReshareTranscriptError::InvalidDealingError {
                dealer_index,
                error,
            },
            CspDkgCreateTranscriptError::InsufficientDealingsError(error) => {
                CspDkgCreateReshareTranscriptError::InsufficientDealingsError(error)
            }
            CspDkgCreateTranscriptError::SizeError(error) => {
                CspDkgCreateReshareTranscriptError::SizeError(error)
            }
        }
    }
}

/// Loading a private key from a DKG transcript failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CspDkgLoadPrivateKeyError {
    /// The AlgorithmId does not correspond to a NiDkg variant
    UnsupportedAlgorithmId(AlgorithmId),
    /// Precondition error: The key encryption key was not found.
    KeyNotFoundError(KeyNotFoundError),
    /// Precondition error: The key encryption key could not be parsed.  Was the
    /// correct algorithm ID used?
    MalformedSecretKeyError(MalformedSecretKeyError),
    /// The transcript could not be parsed.
    MalformedTranscriptError(MalformedDataError),
    /// The transcript cannot be used to generate the desired private key.
    InvalidTranscriptError(InvalidArgumentError),
    /// The transcript's forward-secure epoch is too old and can no longer be
    /// decrypted
    EpochTooOldError {
        ciphertext_epoch: Epoch,
        secret_key_epoch: Epoch,
    },
    // An internal error, e.g. an RPC error.
    InternalError(InternalError),
}

impl CspDkgVerifyReshareDealingError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        CspDkgVerifyReshareDealingError::SizeError(SizeError {
            message: "Squeaky voice".to_string(),
        })
    }
}

impl CspDkgLoadPrivateKeyError {
    #[cfg(test)]
    pub fn test_value() -> Self {
        CspDkgLoadPrivateKeyError::InvalidTranscriptError(InvalidArgumentError {
            message: "Relativism".to_string(),
        })
    }
}

pub mod dealing {
    //! Errors encountered during the NI-DKG dealing phase.
    use super::*;

    /// A dealing is invalid
    #[derive(Debug)]
    pub enum InvalidDealingError {
        UnexpectedShare {
            receiver_index: NodeIndex,
            number_of_receivers: NumberOfNodes,
        },
        MissingShare {
            receiver_index: NodeIndex,
        },
        MalformedShare {
            receiver_index: NodeIndex,
        },
        ThresholdMismatch {
            threshold: NumberOfNodes,
            public_coefficients_len: usize,
        },
        ReshareMismatch {
            old: PublicKeyBytes,
            new: PublicKeyBytes,
        },
    }

    impl From<InvalidDealingError> for InvalidArgumentError {
        fn from(error: InvalidDealingError) -> InvalidArgumentError {
            match error {
          InvalidDealingError::UnexpectedShare { receiver_index, number_of_receivers } => InvalidArgumentError{ message: format!("Expected receiver indices 0..{} inclusive but found {}.", number_of_receivers.get()-1, receiver_index) },
          InvalidDealingError::MissingShare { receiver_index } => InvalidArgumentError{ message: format!("Missing share for receiver {}", receiver_index) },
          InvalidDealingError::MalformedShare { receiver_index } => InvalidArgumentError{ message: format!("Malformed share for receiver {}", receiver_index) },
          InvalidDealingError::ThresholdMismatch { threshold, public_coefficients_len } => InvalidArgumentError{ message: format!("The reshared public coefficients don't match the threshold\n  Threshold: {}\n  Public coefficients len: {}", threshold, public_coefficients_len) },
          InvalidDealingError::ReshareMismatch { old, new } => InvalidArgumentError{ message: format!("The reshared public key does not match the preexisting key.\n  Old: {:?}\n  New: {:?}", old, new) },
        }
        }
    }
}
