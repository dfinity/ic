use crate::crypto::ErrorReproducibility;
use ic_types::crypto::CryptoError;
use ic_types::crypto::canister_threshold_sig::error::{
    EcdsaPresignatureQuadrupleCreationError, IDkgParamsValidationError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError, ThresholdEcdsaSigInputsCreationError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
    ThresholdSchnorrPresignatureTranscriptCreationError, ThresholdSchnorrSigInputsCreationError,
    ThresholdSchnorrVerifyCombinedSigError, ThresholdSchnorrVerifySigShareError,
};
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::vetkd::{VetKdKeyShareVerificationError, VetKdKeyVerificationError};
use ic_types::registry::RegistryClientError;

#[cfg(test)]
mod tests;

// An implementation for the consensus component.
impl ErrorReproducibility for CryptoError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            // true, as validity checks of arguments are stable across replicas
            CryptoError::InvalidArgument { .. } => true,
            // true, as the registry is guaranteed to be consistent across replicas
            CryptoError::PublicKeyNotFound { .. } | CryptoError::TlsCertNotFound { .. } => true,
            // true, as secret material is specific to a replica (other replicas may not encounter the same error)
            // but retrying the same operation on this replica will not change the outcome
            CryptoError::SecretKeyNotFound { .. } | CryptoError::TlsSecretKeyNotFound { .. } => {
                true
            }
            // true tentatively, but may change to panic! in the future:
            // this error indicates either globally corrupted registry, or a local
            // data corruption, and in either case we should not use the key anymore
            CryptoError::MalformedPublicKey { .. } => true,
            // true, as secret material is specific to a replica (other replicas may not encounter the same error)
            // but retrying the same operation on this replica will not change the outcome
            CryptoError::MalformedSecretKey { .. } => true,
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
                registry_client_error.is_reproducible()
            }
            // true, as the registry is guaranteed to be consistent across replicas
            CryptoError::DkgTranscriptNotFound { .. } => true,
            // true, as the registry is guaranteed to be consistent across replicas
            CryptoError::RootSubnetPublicKeyNotFound { .. } => true,
            // true, as non-reproducible internal errors use the other variant TransientInternalError
            CryptoError::InternalError { .. } => true,
            // false, as by definition the transient internal error is non-reproducible
            // (catch-all for lower-level transient errors)
            CryptoError::TransientInternalError { .. } => false,
        }
    }
}

impl ErrorReproducibility for DkgVerifyDealingError {
    fn is_reproducible(&self) -> bool {
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
                registry_client_error.is_reproducible()
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

impl ErrorReproducibility for DkgCreateTranscriptError {
    fn is_reproducible(&self) -> bool {
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

impl ErrorReproducibility for DkgLoadTranscriptError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            // true, as the registry is guaranteed to be consistent across replicas
            DkgLoadTranscriptError::FsEncryptionPublicKeyNotInRegistry(_) => true,
            DkgLoadTranscriptError::Registry(registry_client_error) => {
                registry_client_error.is_reproducible()
            }
            // true, as validity checks of arguments are stable across replicas
            DkgLoadTranscriptError::InvalidTranscript(_) => true,
            // true, as the encryption public key is fetched from the registry and the
            // registry is guaranteed to be consistent across replicas
            DkgLoadTranscriptError::MalformedFsEncryptionPublicKey(_) => true,
            // false, as a transient error is not replicated by definition
            DkgLoadTranscriptError::TransientInternalError(_) => false,
            // true, as internal errors are not expected to resolve through retrying
            DkgLoadTranscriptError::InternalError(_) => true,
        }
    }
}

impl ErrorReproducibility for DkgKeyRemovalError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            // true, as validity checks of arguments are stable across replicas
            DkgKeyRemovalError::InputValidationError(_) => true,
            // true, as the registry is guaranteed to be consistent across replicas
            DkgKeyRemovalError::FsEncryptionPublicKeyNotInRegistry(_) => true,
            // true, as the encryption public key is fetched from the registry and the
            // registry is guaranteed to be consistent across replicas
            DkgKeyRemovalError::MalformedFsEncryptionPublicKey(_) => true,
            DkgKeyRemovalError::Registry(registry_client_error) => {
                registry_client_error.is_reproducible()
            }
            // true, as the private key remains missing despite retrying
            DkgKeyRemovalError::FsKeyNotInSecretKeyStoreError(_) => true,
            // false, as a transient error is not replicated by definition
            DkgKeyRemovalError::TransientInternalError(_) => false,
            // true, as the encryption public key is fetched from the registry
            DkgKeyRemovalError::KeyNotFoundError(_) => true,
            // true, as the key ID is computed from the transcripts provided as input
            DkgKeyRemovalError::KeyIdInstantiationError(_) => true,
        }
    }
}

impl ErrorReproducibility for IDkgVerifyTranscriptError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            // true, as validity checks of arguments are stable across replicas
            IDkgVerifyTranscriptError::InvalidArgument(_) => true,
            // Whether this is a replicated error depends on the underlying crypto error
            IDkgVerifyTranscriptError::InvalidDealingSignatureBatch { crypto_error, .. } => {
                crypto_error.is_reproducible()
            }
            // true, as (de)serialization is stable across replicas
            IDkgVerifyTranscriptError::SerializationError(_) => true,
            // true, as the transcript does not become valid through retrying
            IDkgVerifyTranscriptError::InvalidTranscript => true,
        }
    }
}

impl ErrorReproducibility for IDkgVerifyDealingPublicError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        // Public dealing verification does not depend on any local or private
        // state and so is inherently replicated.
        match self {
            // The dealer wasn't even in the transcript
            Self::TranscriptIdMismatch => true,
            // The dealing was publicly invalid
            Self::InvalidDealing { .. } => true,
            Self::InvalidSignature { crypto_error, .. } => crypto_error.is_reproducible(),
        }
    }
}

impl ErrorReproducibility for IDkgVerifyInitialDealingsError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        // Public dealing verification does not depend on any local or private
        // state and so is inherently replicated.
        match self {
            // The params do not become matching through retrying
            Self::MismatchingTranscriptParams => true,
            Self::PublicVerificationFailure {
                verify_dealing_public_error,
                ..
            } => verify_dealing_public_error.is_reproducible(),
        }
    }
}

impl ErrorReproducibility for IDkgVerifyComplaintError {
    fn is_reproducible(&self) -> bool {
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
                registry_client_error.is_reproducible()
            }
            // true, as the types of internal errors that may occur during complaint
            // verification are stable
            IDkgVerifyComplaintError::InternalError { .. } => true,
        }
    }
}

impl ErrorReproducibility for IDkgVerifyDealingPrivateError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.
        match self {
            IDkgVerifyDealingPrivateError::RegistryError(registry_client_error) => {
                registry_client_error.is_reproducible()
            }
            // false, as a transient error is not reproducible by definition
            IDkgVerifyDealingPrivateError::TransientInternalError { .. } => false,
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

impl ErrorReproducibility for ThresholdEcdsaVerifySigShareError {
    fn is_reproducible(&self) -> bool {
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
            // true, as validity checks of arguments are stable across replicas
            Self::InvalidArguments(_) => true,
        }
    }
}

impl ErrorReproducibility for ThresholdEcdsaVerifyCombinedSignatureError {
    fn is_reproducible(&self) -> bool {
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
            // true, as validity checks of arguments are stable across replicas
            Self::InvalidArguments(_) => true,
        }
    }
}

impl ErrorReproducibility for ThresholdEcdsaSigInputsCreationError {
    fn is_reproducible(&self) -> bool {
        match self {
            ThresholdEcdsaSigInputsCreationError::InconsistentAlgorithmIds => true,
            ThresholdEcdsaSigInputsCreationError::InconsistentReceivers => true,
            ThresholdEcdsaSigInputsCreationError::InvalidHashLength => true,
            ThresholdEcdsaSigInputsCreationError::InvalidQuadrupleOrigin(_) => true,
            ThresholdEcdsaSigInputsCreationError::UnsupportedAlgorithm => true,
        }
    }
}

impl ErrorReproducibility for EcdsaPresignatureQuadrupleCreationError {
    fn is_reproducible(&self) -> bool {
        match self {
            EcdsaPresignatureQuadrupleCreationError::InconsistentAlgorithmIds => true,
            EcdsaPresignatureQuadrupleCreationError::InconsistentReceivers => true,
            EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(_) => true,
        }
    }
}

impl ErrorReproducibility for ThresholdSchnorrVerifySigShareError {
    fn is_reproducible(&self) -> bool {
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
            Self::SerializationError(_) => true,
            // The share included an invalid commitment type
            Self::InternalError(_) => true,
            // true, as validity checks of arguments are stable across replicas
            Self::InvalidArguments(_) => true,
        }
    }
}

impl ErrorReproducibility for ThresholdSchnorrVerifyCombinedSigError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        // Signature verification does not depend on any local or
        // private state and so is inherently replicated.
        match self {
            // The Schnorr signature was invalid or did not match the
            // presignature transcript
            Self::InvalidSignature => true,
            // The signature could not even be deserialized correctly
            Self::SerializationError(_) => true,
            // Invalid commitment type or wrong algorithm ID
            Self::InternalError(_) => true,
            // true, as validity checks of arguments are stable across replicas
            Self::InvalidArguments(_) => true,
        }
    }
}

impl ErrorReproducibility for ThresholdSchnorrSigInputsCreationError {
    fn is_reproducible(&self) -> bool {
        match self {
            ThresholdSchnorrSigInputsCreationError::InconsistentAlgorithmIds(_, _) => true,
            ThresholdSchnorrSigInputsCreationError::InconsistentReceivers => true,
            ThresholdSchnorrSigInputsCreationError::InvalidPreSignatureOrigin(_) => true,
            ThresholdSchnorrSigInputsCreationError::InvalidUseOfTaprootHash => true,
            ThresholdSchnorrSigInputsCreationError::UnsupportedAlgorithm(_) => true,
        }
    }
}

impl ErrorReproducibility for ThresholdSchnorrPresignatureTranscriptCreationError {
    fn is_reproducible(&self) -> bool {
        match self {
            ThresholdSchnorrPresignatureTranscriptCreationError::InvalidTranscriptOrigin(_) => true,
            ThresholdSchnorrPresignatureTranscriptCreationError::UnsupportedAlgorithm(_) => true,
        }
    }
}

impl ErrorReproducibility for IDkgParamsValidationError {
    fn is_reproducible(&self) -> bool {
        match self {
            IDkgParamsValidationError::TooManyReceivers { .. } => true,
            IDkgParamsValidationError::TooManyDealers { .. } => true,
            IDkgParamsValidationError::UnsatisfiedVerificationThreshold { .. } => true,
            IDkgParamsValidationError::UnsatisfiedCollectionThreshold { .. } => true,
            IDkgParamsValidationError::ReceiversEmpty => true,
            IDkgParamsValidationError::DealersEmpty => true,
            IDkgParamsValidationError::UnsupportedAlgorithmId { .. } => true,
            IDkgParamsValidationError::WrongTypeForOriginalTranscript => true,
            IDkgParamsValidationError::DealersNotContainedInPreviousReceivers => true,
        }
    }
}

impl ErrorReproducibility for IDkgVerifyOpeningError {
    fn is_reproducible(&self) -> bool {
        match self {
            // true, as this is a stable property of the arguments.
            IDkgVerifyOpeningError::TranscriptIdMismatch => true,
            // true, as this is a stable property of the arguments.
            IDkgVerifyOpeningError::DealerIdMismatch => true,
            // true, as this is a stable property of the arguments.
            IDkgVerifyOpeningError::MissingDealingInTranscript { .. } => true,
            // true, as this is a stable property of the arguments.
            IDkgVerifyOpeningError::MissingOpenerInReceivers { .. } => true,
            // true, as this is a stable property of the arguments.
            IDkgVerifyOpeningError::InternalError { .. } => true,
        }
    }
}

impl ErrorReproducibility for RegistryClientError {
    fn is_reproducible(&self) -> bool {
        match &self {
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
            // true, as the registry is guaranteed to be consistent across replicas
            RegistryClientError::DecodeError { .. } => true,
            // false, as depends on the data available to the registry
            RegistryClientError::NoVersionsBefore { .. } => false,
        }
    }
}

impl ErrorReproducibility for VetKdKeyShareVerificationError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        match self {
            Self::VerificationError(crypto_error) => crypto_error.is_reproducible(),
            // false, as the result may change if the DKG transcript is reloaded.
            Self::ThresholdSigDataNotFound(_) => false,
        }
    }
}

impl ErrorReproducibility for VetKdKeyVerificationError {
    fn is_reproducible(&self) -> bool {
        // The match below is intentionally explicit on all possible values,
        // to avoid defaults, which might be error-prone.
        // Upon addition of any new error this match has to be updated.

        match self {
            Self::InvalidArgumentEncryptedKey => true,
            Self::InternalError(_) => true,
            Self::InvalidArgumentMasterPublicKey => true,
            Self::InvalidArgumentEncryptionPublicKey => true,
            Self::VerificationError => true,
            // false, as the result may change if the DKG transcript is reloaded.
            Self::ThresholdSigDataNotFound(_) => false,
        }
    }
}
