use crate::crypto::ErrorReplication;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgParamsValidationError, IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError,
    PresignatureQuadrupleCreationError, ThresholdEcdsaSigInputsCreationError,
};
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::CryptoError;
use ic_types::registry::RegistryClientError;

// An implementation for the consensus component.
impl ErrorReplication for CryptoError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            // true, as validity checks of arguments are stable across replicas
            CryptoError::InvalidArgument { .. } => true,
            // true, as the registry is guaranteed to be consistent across replicas
            CryptoError::PublicKeyNotFound { .. } | CryptoError::TlsCertNotFound { .. } => true,
            // panic, as during signature verification no secret keys are involved
            CryptoError::SecretKeyNotFound { .. } | CryptoError::TlsSecretKeyNotFound { .. } => {
                panic!("Unexpected error {}, no secret keys involved", &self)
            }
            // true tentatively, but may change to panic! in the future:
            // this error indicates either globally corrupted registry, or a local
            // data corruption, and in either case we should not use the key anymore
            CryptoError::MalformedPublicKey { .. } => true,
            // panic, as during signature verification no secret keys are involved
            CryptoError::MalformedSecretKey { .. } => {
                panic!("Unexpected error {}, no secret keys involved", &self)
            }
            // true, but this error may be removed TODO(CRP-224)
            CryptoError::MalformedSignature { .. } => true,
            // true, but this error may be removed TODO(CRP-224)
            CryptoError::MalformedPop { .. } => true,
            // true, as signature verification is stable across replicas
            CryptoError::SignatureVerification { .. } => true,
            // true, as PoP verification is stable across replicas
            CryptoError::PopVerification { .. } => true,
            // true, as it indicates inconsistent data in multi-sigs
            // (individual signatures of a multi sig belong to differing algorithms)
            CryptoError::InconsistentAlgorithms { .. } => true,
            // true, as the set of supported algorithms is stable (bound to code version)
            CryptoError::AlgorithmNotSupported { .. } => true,
            // false, as the result may change if the DKG transcript is reloaded.
            CryptoError::ThresholdSigDataNotFound { .. } => false,
            CryptoError::RegistryClient(registry_client_error) => match registry_client_error {
                // false, as depends on the data available to the registry
                RegistryClientError::VersionNotAvailable { .. } => false,
                // false in both cases, these may be transient errors
                RegistryClientError::DataProviderQueryFailed { source } => match source {
                    ic_types::registry::RegistryDataProviderError::Timeout => false,
                    ic_types::registry::RegistryDataProviderError::Transfer { .. } => false,
                },
                // may be a transient error
                RegistryClientError::PollLockFailed { .. } => false,
                // may be transient errors
                RegistryClientError::PollingLatestVersionFailed { .. } => false,
            },
            // true, as the registry is guaranteed to be consistent across replicas
            CryptoError::DkgTranscriptNotFound { .. } => true,
            // true, as the registry is guaranteed to be consistent across replicas
            CryptoError::RootSubnetPublicKeyNotFound { .. } => true,
        }
    }
}

impl ErrorReplication for DkgVerifyDealingError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            DkgVerifyDealingError::NotADealer(_) => {
                // true, as the node cannot become a dealer through retrying
                true
            }
            DkgVerifyDealingError::FsEncryptionPublicKeyNotInRegistry(_) => {
                // true, as the registry is guaranteed to be consistent across replicas
                true
            }
            DkgVerifyDealingError::Registry(registry_client_error) => {
                match registry_client_error {
                    // false, as depends on the data available to the registry
                    RegistryClientError::VersionNotAvailable { .. } => false,
                    // false in both cases, these may be transient errors
                    RegistryClientError::DataProviderQueryFailed { source } => match source {
                        ic_types::registry::RegistryDataProviderError::Timeout => false,
                        ic_types::registry::RegistryDataProviderError::Transfer { .. } => false,
                    },
                    // may be a transient error
                    RegistryClientError::PollLockFailed { .. } => false,
                    // may be transient errors
                    RegistryClientError::PollingLatestVersionFailed { .. } => false,
                }
            }
            DkgVerifyDealingError::MalformedFsEncryptionPublicKey(_) => {
                // true, as the encryption public key is fetched from the registry and the
                // registry is guaranteed to be consistent across replicas
                true
            }
            DkgVerifyDealingError::MalformedResharingTranscriptInConfig(_) => {
                // true, coefficients remain malformed when retrying
                true
            }
            DkgVerifyDealingError::InvalidDealingError(_) => {
                // true, the dealing does not become valid through retrying
                true
            }
        }
    }
}

impl ErrorReplication for DkgCreateTranscriptError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            DkgCreateTranscriptError::InsufficientDealings(_) => {
                // true, the number of dealings remains insufficient when retrying
                true
            }
            DkgCreateTranscriptError::MalformedResharingTranscriptInConfig(_) => {
                // true, coefficients remain malformed when retrying
                true
            }
        }
    }
}

impl ErrorReplication for PresignatureQuadrupleCreationError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            PresignatureQuadrupleCreationError::WrongTypes => {
                // Logic error. Everyone is using the wrong types.
                true
            }
        }
    }
}

impl ErrorReplication for ThresholdEcdsaSigInputsCreationError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            ThresholdEcdsaSigInputsCreationError::NonmatchingTranscriptIds => {
                // Logic error. Everyone is using the wrong transcripts.
                true
            }
        }
    }
}

impl ErrorReplication for IDkgParamsValidationError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            IDkgParamsValidationError::TooManyReceivers { .. } => {
                // Everyone's using bad inputs
                true
            }
            IDkgParamsValidationError::TooManyDealers { .. } => {
                // Everyone's using bad inputs
                true
            }
            IDkgParamsValidationError::UnsatisfiedVerificationThreshold { .. } => {
                // Everyone agreed on an insufficient batch
                true
            }
            IDkgParamsValidationError::UnsatisfiedCollectionThreshold { .. } => {
                // Everyone agreed on an insufficient batch
                true
            }
            IDkgParamsValidationError::ReceiversEmpty => {
                // Everyone's using bad inputs
                true
            }
            IDkgParamsValidationError::DealersEmpty => {
                // Everyone's using bad inputs
                true
            }
            IDkgParamsValidationError::UnsupportedAlgorithmId { .. } => {
                // Everyone's using bad inputs
                true
            }
            IDkgParamsValidationError::WrongTypeForOriginalTranscript => {
                // Everyone's using bad inputs
                true
            }
            IDkgParamsValidationError::DealersNotContainedInPreviousReceivers => {
                // Everyone agreed on an incorrect batch
                true
            }
        }
    }
}

impl ErrorReplication for IDkgVerifyDealingPublicError {
    fn is_replicated(&self) -> bool {
        // TODO correctly implement this function
        false
    }
}

impl ErrorReplication for IDkgVerifyDealingPrivateError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            IDkgVerifyDealingPrivateError::NotAReceiver => {
                // Logic error. Everyone thinks a non-receiver is a receiver.
                true
            }
        }
    }
}
