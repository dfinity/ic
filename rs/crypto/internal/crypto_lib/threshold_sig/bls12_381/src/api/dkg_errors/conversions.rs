//! Convert DKG error types to and from other error types.
use ic_types::crypto::threshold_sig::ni_dkg::errors::{
    MalformedFsEncryptionPublicKeyError, create_transcript_error::DkgCreateTranscriptError,
};

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

impl From<CspDkgLoadPrivateKeyError> for DkgLoadTranscriptError {
    fn from(csp_load_private_key_error: CspDkgLoadPrivateKeyError) -> Self {
        let panic_prefix = "NI-DKG load_transcript error on loading private key - ";
        match csp_load_private_key_error {
            CspDkgLoadPrivateKeyError::MalformedTranscriptError(error) => {
                // Forward to the caller because the argument is malformed.
                DkgLoadTranscriptError::InvalidTranscript(InvalidArgumentError {
                    message: format!("{error}"),
                })
            }
            CspDkgLoadPrivateKeyError::InvalidTranscriptError(error) => {
                // Forward to the caller because the argument is invalid.
                DkgLoadTranscriptError::InvalidTranscript(error)
            }
            CspDkgLoadPrivateKeyError::KeyNotFoundError(error) => {
                // This would be an IDKM implementation error, since KeyNotFoundError is mapped
                // to `Ok(())` and ignored in load_transcript
                panic!("{panic_prefix}KeyNotFoundError: {error:?}");
            }
            CspDkgLoadPrivateKeyError::UnsupportedAlgorithmId(algorithm_id) => {
                // This would be an IDKM implementation error, so we panic:
                panic!(
                    "{panic_prefix}UnsupportedAlgorithmId: The algorithm id {algorithm_id:?} is unsupported."
                );
            }
            CspDkgLoadPrivateKeyError::MalformedSecretKeyError(error) => {
                // This would be an implementation error, since we inserted a key that is
                // malformed:
                panic!("{panic_prefix}MalformedSecretKeyError: {error:?}");
            }
            CspDkgLoadPrivateKeyError::EpochTooOldError {
                ciphertext_epoch,
                secret_key_epoch,
            } => {
                // This would be an IDKM implementation error, since EpochTooOldError is mapped
                // to `Ok(())` and ignored in load_transcript
                panic!("{panic_prefix}EpochTooOldError: {ciphertext_epoch}/{secret_key_epoch}");
            }
            CspDkgLoadPrivateKeyError::TransientInternalError(e) => {
                DkgLoadTranscriptError::TransientInternalError(
                    ic_types::crypto::error::InternalError {
                        internal_error: e.internal_error,
                    },
                )
            }
            CspDkgLoadPrivateKeyError::MalformedPublicKeyError(error) => {
                // Forward to the caller because the argument is malformed.
                DkgLoadTranscriptError::MalformedFsEncryptionPublicKey(
                    MalformedFsEncryptionPublicKeyError {
                        internal_error: error.to_string(),
                    },
                )
            }
            CspDkgLoadPrivateKeyError::InternalError(e) => {
                DkgLoadTranscriptError::InternalError(ic_types::crypto::error::InternalError {
                    internal_error: e.internal_error,
                })
            }
            CspDkgLoadPrivateKeyError::KeyIdInstantiationError(message) => {
                // Forward to the caller because the argument is invalid.
                DkgLoadTranscriptError::InvalidTranscript(InvalidArgumentError { message })
            }
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
                    "{panic_prefix}Precondition violated: dealings have not been verified. InvalidDealingError for dealing with index {dealer_index}: {error:?}"
                );
            }
            CspDkgCreateReshareTranscriptError::UnsupportedAlgorithmId(algorithm_id) => {
                // This would be an IDKM implementation error, so we panic:
                panic!(
                    "{panic_prefix}UnsupportedAlgorithmId: The algorithm id {algorithm_id:?} is unsupported."
                );
            }
            CspDkgCreateReshareTranscriptError::InvalidThresholdError(error) => {
                // This would be an IDKM implementation error, since the threshold invariants
                // are checked upon config creation.
                panic!("{panic_prefix}InvalidThresholdError: {error:?}");
            }
            CspDkgCreateReshareTranscriptError::InsufficientDealingsError(error) => {
                // This would be an IDKM implementation error, the required number of dealings
                // are checked there.
                panic!("{panic_prefix}InsufficientDealingsError: {error:?}");
            }
            CspDkgCreateReshareTranscriptError::ResharingFailed(_) => {
                // This is impossible if dealings are verified properly, thus we panic:
                panic!(
                    "{panic_prefix}Precondition violated: dealings have not been verified. ResharingFailed: {error:?}"
                );
            }
            CspDkgCreateReshareTranscriptError::SizeError(error) => {
                // Will not happen in practice, so we panic:
                panic!("{panic_prefix}SizeError: {error:?}");
            }
        }
    }
}
