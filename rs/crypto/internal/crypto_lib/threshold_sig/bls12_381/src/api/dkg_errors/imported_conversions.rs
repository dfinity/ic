//! Error type conversions imported from other parts of the codebase

// TODO (CRP-817): Import tests for all the below.

// From: ../crypto/src/sign/threshold_sig/ni_dkg/dealing/error_conversions.rs
// TODO (CRP-817): Get the tests from there.
mod create_dealing_error_conversions_v2 {
    // TODO (CRP-818): Remove the v2 and merge.
    use crate::api::ni_dkg_errors::{CspDkgCreateDealingError, CspDkgCreateReshareDealingError};
    use ic_types::crypto::error::{InternalError, InvalidArgumentError};
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;

    impl From<CspDkgCreateDealingError> for DkgCreateDealingError {
        fn from(csp_create_dealing_error: CspDkgCreateDealingError) -> Self {
            // The errors are handled identically to the resharing variant:
            DkgCreateDealingError::from(CspDkgCreateReshareDealingError::from(
                csp_create_dealing_error,
            ))
        }
    }

    impl From<CspDkgCreateReshareDealingError> for DkgCreateDealingError {
        fn from(csp_create_dealing_error: CspDkgCreateReshareDealingError) -> Self {
            let panic_prefix = "NI-DKG create_dealing error - ";
            match csp_create_dealing_error {
                CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
                    receiver_index,
                    error,
                } => {
                    // Forward to the caller, since this is e.g. malformed data in the registry:
                    DkgCreateDealingError::MalformedFsEncryptionPublicKey(
                        MalformedFsEncryptionPublicKeyError {
                            // TODO (CRP-576): implement `Display`?
                            internal_error: format!(
                                "error for receiver index {receiver_index}: {error:?}"
                            ),
                        },
                    )
                }
                CspDkgCreateReshareDealingError::ReshareKeyNotInSecretKeyStoreError(error) => {
                    // Forward to the caller, since they haven't loaded the transcript yet
                    DkgCreateDealingError::ThresholdSigningKeyNotInSecretKeyStore(error)
                }
                CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(algorithm_id) => {
                    // This would be an IDKM implementation error, so we panic:
                    panic!(
                        "{panic_prefix}UnsupportedAlgorithmId: The algorithm id {algorithm_id:?} is unsupported."
                    );
                }
                CspDkgCreateReshareDealingError::InvalidThresholdError(error) => {
                    // This would be an IDKM implementation error, since the threshold invariants
                    // are checked upon config creation.
                    // TODO (CRP-576): implement `Display`?
                    panic!("{panic_prefix}InvalidThresholdError: {error:?}");
                }
                CspDkgCreateReshareDealingError::MisnumberedReceiverError {
                    receiver_index,
                    number_of_receivers,
                } => {
                    // This would be an IDKM implementation error, since the IDKM code should number
                    // the receivers correctly.
                    panic!(
                        "{panic_prefix}MisnumberedReceiverError: receiver index {receiver_index}, number of receivers: {number_of_receivers}"
                    );
                }
                CspDkgCreateReshareDealingError::SizeError(error) => {
                    // Will not happen in practice, so we panic:
                    // TODO (CRP-576): implement `Display`?
                    panic!("{panic_prefix}SizeError: {error:?}");
                }
                CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError(error) => {
                    // This would be an implementation error, since we inserted a key that is
                    // malformed:
                    // TODO (CRP-576): implement `Display`?
                    panic!("{panic_prefix}MalformedReshareSecretKeyError: {error:?}");
                }
                CspDkgCreateReshareDealingError::TransientInternalError(error) => {
                    DkgCreateDealingError::TransientInternalError(InternalError {
                        internal_error: error.internal_error,
                    })
                }
                CspDkgCreateReshareDealingError::ReshareKeyIdComputationError(
                    crate::api::dkg_errors::InternalError { internal_error },
                ) => DkgCreateDealingError::ReshareKeyIdComputationError(InvalidArgumentError {
                    message: internal_error,
                }),
            }
        }
    }
}

// From: crypto/src/sign/threshold_sig/ni_dkg/dealing/error_conversions.rs
mod verify_dealing_error_conversions {

    use crate::api::ni_dkg_errors::{CspDkgVerifyDealingError, CspDkgVerifyReshareDealingError};
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;

    impl From<CspDkgVerifyDealingError> for DkgVerifyDealingError {
        fn from(csp_verify_dealing_error: CspDkgVerifyDealingError) -> Self {
            // The errors are handled identically to the resharing variant:
            DkgVerifyDealingError::from(CspDkgVerifyReshareDealingError::from(
                csp_verify_dealing_error,
            ))
        }
    }

    impl From<CspDkgVerifyReshareDealingError> for DkgVerifyDealingError {
        fn from(csp_verify_dealing_error: CspDkgVerifyReshareDealingError) -> Self {
            let panic_prefix = "NI-DKG verify_dealing error - ";
            match csp_verify_dealing_error {
                CspDkgVerifyReshareDealingError::MalformedFsPublicKeyError {
                    receiver_index,
                    error,
                } => {
                    // Forward to the caller, since this is e.g. malformed data in the registry:
                    DkgVerifyDealingError::MalformedFsEncryptionPublicKey(
                        MalformedFsEncryptionPublicKeyError {
                            // TODO (CRP-576): implement `Display`?
                            internal_error: format!(
                                "error for receiver index {receiver_index}: {error:?}"
                            ),
                        },
                    )
                }
                CspDkgVerifyReshareDealingError::MalformedResharePublicCoefficientsError(error) => {
                    // Forwarded to the caller, this may happen due to an invalid config. This error
                    // is currently not recoverable but may be in the future.
                    DkgVerifyDealingError::MalformedResharingTranscriptInConfig(error)
                }
                CspDkgVerifyReshareDealingError::MalformedDealingError(error) => {
                    // Forward to the caller, since an invalid dealing was passed
                    DkgVerifyDealingError::InvalidDealingError(error)
                }
                CspDkgVerifyReshareDealingError::InvalidDealingError(error) => {
                    // Forward to the caller, since an invalid dealing was passed
                    DkgVerifyDealingError::InvalidDealingError(error)
                }
                CspDkgVerifyReshareDealingError::UnsupportedAlgorithmId(algorithm_id) => {
                    // This would be an IDKM implementation error, so we panic:
                    panic!(
                        "{panic_prefix}UnsupportedAlgorithmId: The algorithm id {algorithm_id:?} is unsupported."
                    );
                }
                CspDkgVerifyReshareDealingError::InvalidThresholdError(error) => {
                    // This would be an IDKM implementation error, since the threshold invariants
                    // are checked upon config creation.
                    // TODO (CRP-576): implement `Display`?
                    panic!("{panic_prefix}InvalidThresholdError: {error:?}");
                }
                CspDkgVerifyReshareDealingError::MisnumberedReceiverError {
                    receiver_index,
                    number_of_receivers,
                } => {
                    // This would be an IDKM implementation error, since the IDKM code should number
                    // the receivers correctly.
                    panic!(
                        "{panic_prefix}MisnumberedReceiverError: receiver index {receiver_index}, number of receivers: {number_of_receivers}"
                    );
                }
                CspDkgVerifyReshareDealingError::SizeError(error) => {
                    // Will not happen in practice, so we panic:
                    // TODO (CRP-576): implement `Display`?
                    panic!("{panic_prefix}SizeError: {error:?}");
                }
            }
        }
    }
}

mod retain_active_keys_error_conversions {
    use crate::api::ni_dkg_errors::{CspDkgRetainThresholdKeysError, CspDkgUpdateFsEpochError};
    use ic_types::crypto::error::InternalError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;

    impl From<CspDkgUpdateFsEpochError> for DkgKeyRemovalError {
        fn from(update_fs_epoch_error: CspDkgUpdateFsEpochError) -> Self {
            match update_fs_epoch_error {
                // This would be an implementation error in IDKM since the algorithm ID is hard
                // coded:
                CspDkgUpdateFsEpochError::UnsupportedAlgorithmId(id) => {
                    panic!("Implementation error - unknown algorithm ID: {id:?}")
                }
                CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(e) => {
                    DkgKeyRemovalError::FsKeyNotInSecretKeyStoreError(e)
                }
                CspDkgUpdateFsEpochError::TransientInternalError(e) => {
                    DkgKeyRemovalError::TransientInternalError(InternalError {
                        internal_error: e.internal_error,
                    })
                }
                CspDkgUpdateFsEpochError::KeyNotFoundError(e) => {
                    DkgKeyRemovalError::KeyNotFoundError(e)
                }
                CspDkgUpdateFsEpochError::MalformedPublicKeyError(e) => {
                    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;

                    DkgKeyRemovalError::MalformedFsEncryptionPublicKey(
                        MalformedFsEncryptionPublicKeyError {
                            internal_error: e.internal_error,
                        },
                    )
                }
            }
        }
    }

    impl From<CspDkgRetainThresholdKeysError> for DkgKeyRemovalError {
        fn from(dkg_retain_threshold_keys_error: CspDkgRetainThresholdKeysError) -> Self {
            match dkg_retain_threshold_keys_error {
                CspDkgRetainThresholdKeysError::TransientInternalError(e) => {
                    DkgKeyRemovalError::TransientInternalError(InternalError {
                        internal_error: e.internal_error,
                    })
                }
                CspDkgRetainThresholdKeysError::KeyIdInstantiationError(internal_error) => {
                    DkgKeyRemovalError::KeyIdInstantiationError(InternalError { internal_error })
                }
            }
        }
    }
}
