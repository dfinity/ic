//! Error type conversions imported from other parts of the codebase

// TODO (CRP-817): Import tests for all the below.

// From: crypto/src/sign/threshold_sig/dkg/dealing.rs
mod dkg_dealing {
    use crate::api::dkg_errors::{DkgVerifyDealingError, DkgVerifyReshareDealingError};
    use ic_types::crypto::CryptoError;

    // TODO (CRP-416): Map the CSP errors to IDKM errors.
    impl From<DkgVerifyReshareDealingError> for CryptoError {
        fn from(verify_dealing_error: DkgVerifyReshareDealingError) -> Self {
            match verify_dealing_error {
                DkgVerifyReshareDealingError::MalformedPublicKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyReshareDealingError::MalformedDealingError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyReshareDealingError::InvalidDealingError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyReshareDealingError::SizeError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgVerifyReshareDealingError::MalformedPublicCoefficientsError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
            }
        }
    }

    // TODO (CRP-346): Map the CSP errors to IDKM errors.
    impl From<DkgVerifyDealingError> for CryptoError {
        fn from(verify_dealing_error: DkgVerifyDealingError) -> Self {
            match verify_dealing_error {
                DkgVerifyDealingError::MalformedPublicKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyDealingError::MalformedDealingError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyDealingError::InvalidDealingError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgVerifyDealingError::SizeError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
            }
        }
    }
}

// From: crypto/src/sign/threshold_sig/dkg/encryption_keys.rs
mod dkg_encryption_keys_verify {
    use crate::api::dkg_errors::DkgVerifyEphemeralError;
    use ic_types::crypto::CryptoError;

    // TODO (CRP-342): Map the CSP errors to IDKM errors, this is only temporary.
    impl From<DkgVerifyEphemeralError> for CryptoError {
        fn from(verify_eph_err: DkgVerifyEphemeralError) -> Self {
            match verify_eph_err {
                DkgVerifyEphemeralError::MalformedPublicKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyEphemeralError::MalformedPopError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgVerifyEphemeralError::InvalidPopError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
            }
        }
    }
}

// From: crypto/src/sign/threshold_sig/dkg/response.rs
// TODO (CRP-817): Import tests
mod dkg_response_verify {
    use crate::api::dkg_errors::DkgCreateResponseError;
    use crate::api::dkg_errors::DkgVerifyResponseError;
    use ic_types::crypto::CryptoError;

    // TODO (CRP-327): Map the CSP errors to IDKM errors.
    impl From<DkgCreateResponseError> for CryptoError {
        fn from(create_response_error: DkgCreateResponseError) -> Self {
            match create_response_error {
                DkgCreateResponseError::MalformedPublicKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateResponseError::MalformedPopError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgCreateResponseError::MalformedSecretKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateResponseError::MalformedDealingError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateResponseError::KeyNotFoundError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgCreateResponseError::SizeError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
            }
        }
    }

    // TODO (CRP-361): Map the CSP errors to IDKM errors.
    impl From<DkgVerifyResponseError> for CryptoError {
        fn from(verify_response_error: DkgVerifyResponseError) -> Self {
            match verify_response_error {
                DkgVerifyResponseError::MalformedPublicKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyResponseError::MalformedPopError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgVerifyResponseError::MalformedDealingError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyResponseError::InvalidReceiverIndexError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyResponseError::MalformedResponseError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyResponseError::InvalidResponseError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgVerifyResponseError::SizeError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
            }
        }
    }
}

// From: crypto/src/sign/threshold_sig/dkg/transcript.rs
// TODO (CRP-817): import tests
mod create_transcript {
    use crate::api::dkg_errors::{DkgCreateReshareTranscriptError, DkgCreateTranscriptError};
    use ic_types::crypto::CryptoError;

    // TODO (CRP-371): Map the CSP errors to IDKM errors.
    impl From<DkgCreateReshareTranscriptError> for CryptoError {
        fn from(create_transcript_error: DkgCreateReshareTranscriptError) -> Self {
            match create_transcript_error {
                DkgCreateReshareTranscriptError::MalformedPublicKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateReshareTranscriptError::MalformedDealingError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateReshareTranscriptError::MalformedResponseError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateReshareTranscriptError::SizeError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgCreateReshareTranscriptError::InvalidThresholdError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateReshareTranscriptError::InsufficientDataError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
            }
        }
    }

    // TODO (CRP-371): Map the CSP errors to IDKM errors.
    impl From<DkgCreateTranscriptError> for CryptoError {
        fn from(create_transcript_error: DkgCreateTranscriptError) -> Self {
            match create_transcript_error {
                DkgCreateTranscriptError::MalformedPublicKeyError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateTranscriptError::MalformedDealingError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateTranscriptError::MalformedResponseError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateTranscriptError::SizeError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgCreateTranscriptError::InvalidThresholdError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgCreateTranscriptError::InsufficientDataError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
            }
        }
    }
}

// From: crypto/src/sign/threshold_sig/dkg/transcript.rs
// TODO (CRP-817): Import tests
mod load_transcript {
    use crate::api::dkg_errors::DkgLoadPrivateKeyError;
    use ic_types::crypto::CryptoError;

    // TODO (CRP-362): Map the CSP errors to IDKM errors, this is only temporary.
    impl From<DkgLoadPrivateKeyError> for CryptoError {
        fn from(load_private_key_error: DkgLoadPrivateKeyError) -> Self {
            match load_private_key_error {
                DkgLoadPrivateKeyError::KeyNotFoundError(error) => CryptoError::InvalidArgument {
                    message: format!("CSP error: {:?}", error),
                },
                DkgLoadPrivateKeyError::MalformedSecretKeyError(error) => {
                    panic!("Internal error from CSP: {:?}", error)
                }
                DkgLoadPrivateKeyError::MalformedTranscriptError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
                DkgLoadPrivateKeyError::InvalidTranscriptError(error) => {
                    CryptoError::InvalidArgument {
                        message: format!("CSP error: {:?}", error),
                    }
                }
            }
        }
    }
}

// From: ../crypto/src/sign/threshold_sig/ni_dkg/dealing/error_conversions.rs
// TODO (CRP-817): Get the tests from there.
mod create_dealing_error_conversions_v2 {
    // TODO (CRP-818): Remove the v2 and merge.
    use crate::api::ni_dkg_errors::{CspDkgCreateDealingError, CspDkgCreateReshareDealingError};
    use ic_types::crypto::error::InternalError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;

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
                                "error for receiver index {}: {:?}",
                                receiver_index, error
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
                        "{}UnsupportedAlgorithmId: The algorithm id {:?} is unsupported.",
                        panic_prefix, algorithm_id
                    );
                }
                CspDkgCreateReshareDealingError::InvalidThresholdError(error) => {
                    // This would be an IDKM implementation error, since the threshold invariants
                    // are checked upon config creation.
                    // TODO (CRP-576): implement `Display`?
                    panic!("{}InvalidThresholdError: {:?}", panic_prefix, error);
                }
                CspDkgCreateReshareDealingError::MisnumberedReceiverError {
                    receiver_index,
                    number_of_receivers,
                } => {
                    // This would be an IDKM implementation error, since the IDKM code should number
                    // the receivers correctly.
                    panic!(
                        "{}MisnumberedReceiverError: receiver index {}, number of receivers: {}",
                        panic_prefix, receiver_index, number_of_receivers
                    );
                }
                CspDkgCreateReshareDealingError::SizeError(error) => {
                    // Will not happen in practice, so we panic:
                    // TODO (CRP-576): implement `Display`?
                    panic!("{}SizeError: {:?}", panic_prefix, error);
                }
                CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError(error) => {
                    // This would be an implementation error, since we inserted a key that is
                    // malformed:
                    // TODO (CRP-576): implement `Display`?
                    panic!(
                        "{}MalformedReshareSecretKeyError: {:?}",
                        panic_prefix, error
                    );
                }
                CspDkgCreateReshareDealingError::InternalError(error) => {
                    DkgCreateDealingError::InternalError(InternalError {
                        internal_error: error.internal_error,
                    })
                }
            }
        }
    }
}

// From: crypto/src/sign/threshold_sig/ni_dkg/dealing/error_conversions.rs
mod verify_dealing_error_conversions {

    use crate::api::ni_dkg_errors::{CspDkgVerifyDealingError, CspDkgVerifyReshareDealingError};
    use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;

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
                                "error for receiver index {}: {:?}",
                                receiver_index, error
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
                        "{}UnsupportedAlgorithmId: The algorithm id {:?} is unsupported.",
                        panic_prefix, algorithm_id
                    );
                }
                CspDkgVerifyReshareDealingError::InvalidThresholdError(error) => {
                    // This would be an IDKM implementation error, since the threshold invariants
                    // are checked upon config creation.
                    // TODO (CRP-576): implement `Display`?
                    panic!("{}InvalidThresholdError: {:?}", panic_prefix, error);
                }
                CspDkgVerifyReshareDealingError::MisnumberedReceiverError {
                    receiver_index,
                    number_of_receivers,
                } => {
                    // This would be an IDKM implementation error, since the IDKM code should number
                    // the receivers correctly.
                    panic!(
                        "{}MisnumberedReceiverError: receiver index {}, number of receivers: {}",
                        panic_prefix, receiver_index, number_of_receivers
                    );
                }
                CspDkgVerifyReshareDealingError::SizeError(error) => {
                    // Will not happen in practice, so we panic:
                    // TODO (CRP-576): implement `Display`?
                    panic!("{}SizeError: {:?}", panic_prefix, error);
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
                    panic!("Implementation error - unknown algorithm ID: {:?}", id)
                }
                CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(e) => {
                    DkgKeyRemovalError::FsKeyNotInSecretKeyStoreError(e)
                }
                CspDkgUpdateFsEpochError::InternalError(e) => {
                    DkgKeyRemovalError::InternalError(InternalError {
                        internal_error: e.internal_error,
                    })
                }
            }
        }
    }

    impl From<CspDkgRetainThresholdKeysError> for DkgKeyRemovalError {
        fn from(dkg_retain_threshold_keys_error: CspDkgRetainThresholdKeysError) -> Self {
            match dkg_retain_threshold_keys_error {
                CspDkgRetainThresholdKeysError::InternalError(e) => {
                    DkgKeyRemovalError::InternalError(InternalError {
                        internal_error: e.internal_error,
                    })
                }
            }
        }
    }
}
