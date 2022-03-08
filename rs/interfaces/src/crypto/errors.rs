use crate::crypto::ErrorReplication;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgVerifyComplaintError, IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError, ThresholdEcdsaVerifyCombinedSignatureError,
    ThresholdEcdsaVerifySigShareError,
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
            CryptoError::RegistryClient(registry_client_error) => {
                error_replication_of_registry_client_error(registry_client_error)
            }
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
                error_replication_of_registry_client_error(registry_client_error)
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

impl ErrorReplication for IDkgVerifyTranscriptError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            // rue, as validity checks of arguments are stable across replicas
            IDkgVerifyTranscriptError::InvalidArgument(_) => true,
            // Whether this is a replicated error depends on the underlying crypto error
            IDkgVerifyTranscriptError::InvalidDealingMultiSignature { crypto_error, .. } => {
                crypto_error.is_replicated()
            }
            // true, as (de)serialization is stable across replicas
            IDkgVerifyTranscriptError::SerializationError(_) => true,
            // true, as the transcript does not become valid through retrying
            IDkgVerifyTranscriptError::InvalidTranscript => true,
        }
    }
}

impl ErrorReplication for IDkgVerifyDealingPublicError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        // Public dealing verification does not depend on any local or private
        // state and so is inherently replicated.
        match self {
            // The dealer wasn't even in the transcript
            Self::TranscriptIdMismatch => true,
            // The dealing was publically invalid
            Self::InvalidDealing { .. } => true,
        }
    }
}

impl ErrorReplication for IDkgVerifyComplaintError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            // true, as the complaint does not become valid through retrying
            IDkgVerifyComplaintError::InvalidComplaint => true,
            // true, as validity checks of arguments are stable across replicas
            IDkgVerifyComplaintError::InvalidArgument { .. } => true,
            // true, as validity checks of arguments are stable across replicas
            IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs => true,
            // true, as validity checks of arguments are stable across replicas
            IDkgVerifyComplaintError::InvalidArgumentMissingDealingInTranscript { .. } => true,
            // true, as validity checks of arguments are stable across replicas
            IDkgVerifyComplaintError::InvalidArgumentMissingComplainerInTranscript { .. } => true,
            // true, as the registry is guaranteed to be consistent across replicas
            IDkgVerifyComplaintError::ComplainerPublicKeyNotInRegistry { .. } => true,
            // true, as the public key is fetched from the registry and the
            // registry is guaranteed to be consistent across replicas
            IDkgVerifyComplaintError::MalformedComplainerPublicKey { .. } => true,

            // true, as the set of supported algorithms is stable (bound to code version)
            IDkgVerifyComplaintError::UnsupportedComplainerPublicKeyAlgorithm { .. } => true,
            // true, as (de)serialization is stable across replicas
            IDkgVerifyComplaintError::SerializationError { .. } => true,
            IDkgVerifyComplaintError::Registry(registry_client_error) => {
                error_replication_of_registry_client_error(registry_client_error)
            }
            // true, as the types of internal errors that may occur during complaint
            // verification are stable
            IDkgVerifyComplaintError::InternalError { .. } => true,
        }
    }
}

impl ErrorReplication for IDkgVerifyDealingPrivateError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            IDkgVerifyDealingPrivateError::RegistryError(registry_client_error) => {
                error_replication_of_registry_client_error(registry_client_error)
            }
            // false, as an RPC error may be transient
            IDkgVerifyDealingPrivateError::CspVaultRpcError(_) => false,
            // true, as the dealing does not become valid through retrying
            IDkgVerifyDealingPrivateError::InvalidDealing(_) => true,
            // true, as validity checks of arguments are stable across replicas
            IDkgVerifyDealingPrivateError::InvalidArgument(_) => true,
            // true, as the internal errors that may occur are stable
            IDkgVerifyDealingPrivateError::InternalError(_) => true,
            // true, as the private key remains missing despite retrying
            IDkgVerifyDealingPrivateError::PrivateKeyNotFound => true,
            // true, as the registry is guaranteed to be consistent across replicas
            IDkgVerifyDealingPrivateError::PublicKeyNotInRegistry { .. } => true,
            // true, as the public key is fetched from the registry and the
            // registry is guaranteed to be consistent across replicas
            IDkgVerifyDealingPrivateError::MalformedPublicKey { .. } => true,
            // true, as the set of supported algorithms is stable (bound to code version)
            IDkgVerifyDealingPrivateError::UnsupportedAlgorithm { .. } => true,
            // true, as the node won't become a receiver through retrying
            IDkgVerifyDealingPrivateError::NotAReceiver => true,
        }
    }
}

impl ErrorReplication for ThresholdEcdsaVerifySigShareError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        // Signature share verification does not depend on any local or private
        // state and so is inherently replicated.
        match self {
            // The error returned if signature share commitments are invalid
            Self::InvalidSignatureShare => true,
            // The purported signer does exist in the transcript
            Self::InvalidArgumentMissingSignerInTranscript { .. } => true,
            // The signature share could not even be deserialized correctly
            Self::SerializationError { .. } => true,
            // The share included an invalid commitment type
            Self::InternalError { .. } => true,
        }
    }
}

impl ErrorReplication for ThresholdEcdsaVerifyCombinedSignatureError {
    fn is_replicated(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        // Signature verification does not depend on any local or
        // private state and so is inherently replicated.
        match self {
            // The ECDSA signature was invalid or did not match the
            // presignature transcript
            Self::InvalidSignature => true,
            // The signature could not even be deserialized correctly
            Self::SerializationError { .. } => true,
            // Invalid commitment type or wrong algorithm ID
            Self::InternalError { .. } => true,
        }
    }
}

impl ErrorReplication for IDkgVerifyOpeningError {
    fn is_replicated(&self) -> bool {
        // TODO correctly implement this function
        false
    }
}

fn error_replication_of_registry_client_error(registry_client_error: &RegistryClientError) -> bool {
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
