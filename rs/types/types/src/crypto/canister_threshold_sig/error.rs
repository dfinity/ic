//! Defines errors that may occur in the context of canister threshold
//! signatures.
use crate::crypto::{AlgorithmId, CryptoError};
use crate::registry::RegistryClientError;
use crate::{Height, NodeId, RegistryVersion};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use serde::{Deserialize, Serialize};

macro_rules! impl_display_using_debug {
    ($t:ty) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };
}

pub(crate) use impl_display_using_debug;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgTranscriptIdError {
    DecreasedBlockHeight {
        existing_height: Height,
        updated_height: Height,
    },
}
impl_display_using_debug!(IDkgTranscriptIdError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum EcdsaPresignatureQuadrupleCreationError {
    InconsistentAlgorithmIds,
    InconsistentReceivers,
    InvalidTranscriptOrigin(String),
}
impl_display_using_debug!(EcdsaPresignatureQuadrupleCreationError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdEcdsaSigInputsCreationError {
    InconsistentAlgorithmIds,
    InconsistentReceivers,
    InvalidHashLength,
    InvalidQuadrupleOrigin(String),
    UnsupportedAlgorithm,
}
impl_display_using_debug!(ThresholdEcdsaSigInputsCreationError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgParamsValidationError {
    TooManyReceivers { receivers_count: usize },
    TooManyDealers { dealers_count: usize },
    UnsatisfiedVerificationThreshold { threshold: u32, receiver_count: u32 },
    UnsatisfiedCollectionThreshold { threshold: u32, dealer_count: u32 },
    ReceiversEmpty,
    DealersEmpty,
    UnsupportedAlgorithmId { algorithm_id: AlgorithmId },
    WrongTypeForOriginalTranscript,
    DealersNotContainedInPreviousReceivers,
}
impl_display_using_debug!(IDkgParamsValidationError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum InitialIDkgDealingsValidationError {
    DealerNotAllowed { node_id: NodeId },
    DealersAndReceiversNotDisjoint,
    DeserializationError { error: String },
    InvalidTranscriptOperation,
    MismatchingDealing,
    MultipleDealingsFromSameDealer { node_id: NodeId },
    MultipleSupportSharesFromSameReceiver { node_id: NodeId },
    UnsatisfiedCollectionThreshold { threshold: u32, dealings_count: u32 },
}
impl_display_using_debug!(InitialIDkgDealingsValidationError);

impl From<InitialIDkgDealingsValidationError> for ProxyDecodeError {
    fn from(init: InitialIDkgDealingsValidationError) -> Self {
        ProxyDecodeError::Other(init.to_string())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum CanisterThresholdGetPublicKeyError {
    InvalidArgument(String),
    InternalError(String),
}
impl_display_using_debug!(CanisterThresholdGetPublicKeyError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgCreateTranscriptError {
    SerializationError {
        internal_error: String,
    },
    InternalError {
        internal_error: String,
    },
    DealerNotAllowed {
        node_id: NodeId,
    },
    SignerNotAllowed {
        node_id: NodeId,
    },
    UnsatisfiedCollectionThreshold {
        threshold: u32,
        dealing_count: usize,
    },
    UnsatisfiedVerificationThreshold {
        threshold: u32,
        signature_count: usize,
        dealer_id: NodeId,
    },
    InvalidSignatureBatch {
        crypto_error: CryptoError,
    },
}
impl_display_using_debug!(IDkgCreateTranscriptError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgVerifyTranscriptError {
    InvalidArgument(String),
    InvalidDealingSignatureBatch {
        error: String,
        crypto_error: CryptoError,
    },
    SerializationError(String),
    InvalidTranscript,
}
impl_display_using_debug!(IDkgVerifyTranscriptError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgOpenTranscriptError {
    PrivateKeyNotFound {
        key_id: String,
    },
    PublicKeyNotFound {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    MissingDealingInTranscript {
        dealer_id: NodeId,
    },
    RegistryError(RegistryClientError),
    InternalError {
        internal_error: String,
    },
    TransientInternalError {
        internal_error: String,
    },
}
impl_display_using_debug!(IDkgOpenTranscriptError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgRetainKeysError {
    InternalError { internal_error: String },
    SerializationError { internal_error: String },
    TransientInternalError { internal_error: String },
}
impl_display_using_debug!(IDkgRetainKeysError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgLoadTranscriptError {
    InsufficientOpenings {
        internal_error: String,
    },
    InvalidArguments {
        internal_error: String,
    },
    PublicKeyNotFound {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    SerializationError {
        internal_error: String,
    },
    PrivateKeyNotFound,
    InternalError {
        internal_error: String,
    },
    MalformedPublicKey {
        node_id: NodeId,
        #[serde(with = "serde_bytes")]
        key_bytes: Vec<u8>,
    },
    UnsupportedAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    RegistryError(RegistryClientError),
    TransientInternalError {
        internal_error: String,
    },
}
impl_display_using_debug!(IDkgLoadTranscriptError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgCreateDealingError {
    NotADealer {
        node_id: NodeId,
    },
    MalformedPublicKey {
        node_id: NodeId,
        #[serde(with = "serde_bytes")]
        key_bytes: Vec<u8>,
    },
    PublicKeyNotFound {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    UnsupportedAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    RegistryError(RegistryClientError),
    SerializationError {
        internal_error: String,
    },
    SignatureError {
        internal_error: String,
    },
    InternalError {
        internal_error: String,
    },
    SecretSharesNotFound {
        commitment_string: String,
    },
    TransientInternalError {
        internal_error: String,
    },
}
impl_display_using_debug!(IDkgCreateDealingError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgVerifyDealingPublicError {
    TranscriptIdMismatch,
    InvalidDealing {
        reason: String,
    },
    InvalidSignature {
        error: String,
        crypto_error: CryptoError,
    },
}
impl_display_using_debug!(IDkgVerifyDealingPublicError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgVerifyDealingPrivateError {
    InvalidDealing(String),
    NotAReceiver,
    InvalidArgument(String),
    PrivateKeyNotFound,
    RegistryError(RegistryClientError),
    PublicKeyNotInRegistry {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    MalformedPublicKey {
        node_id: NodeId,
        #[serde(with = "serde_bytes")]
        key_bytes: Vec<u8>,
    },
    UnsupportedAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    InternalError(String),
    TransientInternalError {
        internal_error: String,
    },
}
impl_display_using_debug!(IDkgVerifyDealingPrivateError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgVerifyInitialDealingsError {
    MismatchingTranscriptParams,
    PublicVerificationFailure {
        error: String,
        verify_dealing_public_error: IDkgVerifyDealingPublicError,
    },
}
impl_display_using_debug!(IDkgVerifyInitialDealingsError);

/// Occurs if verifying a complaint using `IDkgProtocol::verify_complaint` fails.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgVerifyComplaintError {
    InvalidComplaint,
    InvalidArgument {
        internal_error: String,
    },
    InvalidArgumentMismatchingTranscriptIDs,
    InvalidArgumentMissingDealingInTranscript {
        dealer_id: NodeId,
    },
    InvalidArgumentMissingComplainerInTranscript {
        complainer_id: NodeId,
    },
    ComplainerPublicKeyNotInRegistry {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    MalformedComplainerPublicKey {
        node_id: NodeId,
        #[serde(with = "serde_bytes")]
        key_bytes: Vec<u8>,
    },
    UnsupportedComplainerPublicKeyAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    SerializationError {
        internal_error: String,
    },
    Registry(RegistryClientError),
    InternalError {
        internal_error: String,
    },
}
impl_display_using_debug!(IDkgVerifyComplaintError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum IDkgVerifyOpeningError {
    TranscriptIdMismatch,
    DealerIdMismatch,
    MissingDealingInTranscript { dealer_id: NodeId },
    MissingOpenerInReceivers { opener_id: NodeId },
    InternalError { internal_error: String },
}
impl_display_using_debug!(IDkgVerifyOpeningError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdEcdsaVerifySigShareError {
    InternalError { internal_error: String },
    SerializationError { internal_error: String },
    InvalidSignatureShare,
    InvalidArgumentMissingSignerInTranscript { signer_id: NodeId },
    InvalidArguments(String),
}
impl_display_using_debug!(ThresholdEcdsaVerifySigShareError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdEcdsaCreateSigShareError {
    InternalError { internal_error: String },
    NotAReceiver,
    SerializationError { internal_error: String },
    SecretSharesNotFound { commitment_string: String },
    TransientInternalError { internal_error: String },
}
impl_display_using_debug!(ThresholdEcdsaCreateSigShareError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdEcdsaVerifyCombinedSignatureError {
    InternalError { internal_error: String },
    InvalidSignature,
    SerializationError { internal_error: String },
    InvalidArguments(String),
}
impl_display_using_debug!(ThresholdEcdsaVerifyCombinedSignatureError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdEcdsaCombineSigSharesError {
    InternalError { internal_error: String },
    UnsatisfiedReconstructionThreshold { threshold: u32, share_count: usize },
    SerializationError { internal_error: String },
    SignerNotAllowed { node_id: NodeId },
}
impl_display_using_debug!(ThresholdEcdsaCombineSigSharesError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdSchnorrVerifySigShareError {
    InternalError(String),
    SerializationError(String),
    InvalidSignatureShare,
    InvalidArgumentMissingSignerInTranscript { signer_id: NodeId },
    InvalidArguments(String),
}
impl_display_using_debug!(ThresholdSchnorrVerifySigShareError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdSchnorrCreateSigShareError {
    InternalError(String),
    NotAReceiver,
    SerializationError(String),
    SecretSharesNotFound { commitment_string: String },
    TransientInternalError(String),
    InvalidArguments(String),
}
impl_display_using_debug!(ThresholdSchnorrCreateSigShareError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdSchnorrVerifyCombinedSigError {
    InternalError(String),
    InvalidSignature,
    SerializationError(String),
    InvalidArguments(String),
}
impl_display_using_debug!(ThresholdSchnorrVerifyCombinedSigError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdSchnorrCombineSigSharesError {
    InternalError(String),
    UnsatisfiedReconstructionThreshold { threshold: u32, share_count: usize },
    SerializationError(String),
    SignerNotAllowed { node_id: NodeId },
    InvalidArguments(String),
}
impl_display_using_debug!(ThresholdSchnorrCombineSigSharesError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdSchnorrSigInputsCreationError {
    InconsistentAlgorithmIds(String, String),
    InconsistentReceivers,
    InvalidPreSignatureOrigin(String),
    UnsupportedAlgorithm(String),
}
impl_display_using_debug!(ThresholdSchnorrSigInputsCreationError);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ThresholdSchnorrPresignatureTranscriptCreationError {
    InvalidTranscriptOrigin(String),
    UnsupportedAlgorithm(String),
}
impl_display_using_debug!(ThresholdSchnorrPresignatureTranscriptCreationError);
