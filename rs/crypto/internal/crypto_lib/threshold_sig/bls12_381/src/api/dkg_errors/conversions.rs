//! Convert DKG error types to and from other error types.
use super::*;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;

use crate::api::ni_dkg_errors::{
    CspDkgCreateReshareTranscriptError, CspDkgCreateTranscriptError, CspDkgLoadPrivateKeyError,
    InvalidArgumentError,
};
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;

impl From<CspDkgCreateTranscriptError> for DkgCreateTranscriptError {
    fn from(error: CspDkgCreateTranscriptError) -> Self {
        // The errors are handled identically to the resharing variant:
        DkgCreateTranscriptError::from(CspDkgCreateReshareTranscriptError::from(error))
    }
}

impl From<DkgCreateEphemeralError> for CryptoError {
    // Placeholder implementation
    fn from(create_ephemeral_error: DkgCreateEphemeralError) -> CryptoError {
        match create_ephemeral_error {
            DkgCreateEphemeralError::MalformedSecretKeyError(error) => {
                panic!("Internal error from CSP: {:?}", error)
            }
        }
    }
}

impl From<CspDkgLoadPrivateKeyError> for DkgLoadTranscriptError {
    fn from(csp_load_private_key_error: CspDkgLoadPrivateKeyError) -> Self {
        let panic_prefix = "NI-DKG load_transcript error on loading private key - ";
        match csp_load_private_key_error {
            CspDkgLoadPrivateKeyError::MalformedTranscriptError(error) => {
                // Forward to the caller because the argument is malformed.
                DkgLoadTranscriptError::InvalidTranscript(InvalidArgumentError {
                    message: format!("{}", error),
                })
            }
            CspDkgLoadPrivateKeyError::InvalidTranscriptError(error) => {
                // Forward to the caller because the argument is invalid.
                DkgLoadTranscriptError::InvalidTranscript(error)
            }
            CspDkgLoadPrivateKeyError::KeyNotFoundError(error) => {
                // This would be an IDKM implementation error, since KeyNotFoundError is mapped
                // to `Ok(())` and ignored in load_transcript
                panic!("{}KeyNotFoundError: {:?}", panic_prefix, error);
            }
            CspDkgLoadPrivateKeyError::UnsupportedAlgorithmId(algorithm_id) => {
                // This would be an IDKM implementation error, so we panic:
                panic!(
                    "{}UnsupportedAlgorithmId: The algorithm id {:?} is unsupported.",
                    panic_prefix, algorithm_id
                );
            }
            CspDkgLoadPrivateKeyError::MalformedSecretKeyError(error) => {
                // This would be an implementation error, since we inserted a key that is
                // malformed:
                panic!("{}MalformedSecretKeyError: {:?}", panic_prefix, error);
            }
        }
    }
}

impl From<DkgCreateDealingError> for CryptoError {
    fn from(create_dealing_error: DkgCreateDealingError) -> Self {
        match create_dealing_error {
            DkgCreateDealingError::MalformedPublicKeyError(error) => CryptoError::InvalidArgument {
                message: format!("CSP error: {:?}", error),
            },
            DkgCreateDealingError::KeyNotFoundError(error) => CryptoError::InvalidArgument {
                message: format!("CSP error: {:?}", error),
            },
            DkgCreateDealingError::MalformedSecretKeyError(error) => {
                panic!("Internal error from CSP: {:?}", error)
            }
            DkgCreateDealingError::UnsupportedThresholdParameters(error) => {
                CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                }
            }
            DkgCreateDealingError::SizeError(error) => CryptoError::InvalidArgument {
                message: format!("CSP error: {:?}", error),
            },
        }
    }
}

impl From<DkgCreateReshareDealingError> for CryptoError {
    fn from(create_reshare_dealing_error: DkgCreateReshareDealingError) -> Self {
        match create_reshare_dealing_error {
            DkgCreateReshareDealingError::MalformedPublicKeyError(error) => {
                CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                }
            }
            DkgCreateReshareDealingError::KeyNotFoundError(error) => CryptoError::InvalidArgument {
                message: format!("CSP error: {:?}", error),
            },
            DkgCreateReshareDealingError::MalformedSecretKeyError(error) => {
                panic!("Internal error from CSP: {:?}", error)
            }
            DkgCreateReshareDealingError::UnsupportedThresholdParameters(error) => {
                CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                }
            }
            DkgCreateReshareDealingError::SizeError(error) => CryptoError::InvalidArgument {
                message: format!("CSP error: {:?}", error),
            },
        }
    }
}

impl From<CspDkgCreateReshareTranscriptError> for DkgCreateTranscriptError {
    fn from(error: CspDkgCreateReshareTranscriptError) -> Self {
        let panic_prefix = "NI-DKG create_transcript error - ";
        match error {
            CspDkgCreateReshareTranscriptError::MalformedResharePublicCoefficientsError(error) => {
                // Forwarded to the caller, this may happen due to an invalid config. This error
                // is currently not recoverable but may be in the future.
                DkgCreateTranscriptError::MalformedResharingTranscriptInConfig(error)
            }
            CspDkgCreateReshareTranscriptError::InvalidDealingError {
                dealer_index,
                error,
            } => {
                // This is a violation of the precondition that the dealings must be verified,
                // so we panic:
                panic!(
                        "{}Precondition violated: dealings have not been verified. InvalidDealingError for dealing with index {}: {:?}",
                        panic_prefix, dealer_index, error
                    );
            }
            CspDkgCreateReshareTranscriptError::UnsupportedAlgorithmId(algorithm_id) => {
                // This would be an IDKM implementation error, so we panic:
                panic!(
                    "{}UnsupportedAlgorithmId: The algorithm id {:?} is unsupported.",
                    panic_prefix, algorithm_id
                );
            }
            CspDkgCreateReshareTranscriptError::InvalidThresholdError(error) => {
                // This would be an IDKM implementation error, since the threshold invariants
                // are checked upon config creation.
                panic!("{}InvalidThresholdError: {:?}", panic_prefix, error);
            }
            CspDkgCreateReshareTranscriptError::InsufficientDealingsError(error) => {
                // This would be an IDKM implementation error, the required number of dealings
                // are checked there.
                panic!("{}InsufficientDealingsError: {:?}", panic_prefix, error);
            }
            CspDkgCreateReshareTranscriptError::ResharingFailed(_) => {
                // This is impossible if dealings are verified properly, thus we panic:
                panic!("{}Precondition violated: dealings have not been verified. ResharingFailed: {:?}", panic_prefix, error);
            }
            CspDkgCreateReshareTranscriptError::SizeError(error) => {
                // Will not happen in practice, so we panic:
                panic!("{}SizeError: {:?}", panic_prefix, error);
            }
        }
    }
}
