//! Defines errors that may occur in the context of canister threshold
//! signatures.
use crate::crypto::{AlgorithmId, CryptoError};
use crate::registry::RegistryClientError;
use crate::{NodeId, RegistryVersion};
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;

macro_rules! impl_display_using_debug {
    ($t:ty) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PresignatureQuadrupleCreationError {
    WrongTypes,
}
impl_display_using_debug!(PresignatureQuadrupleCreationError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThresholdEcdsaSigInputsCreationError {
    NonmatchingTranscriptIds,
}
impl_display_using_debug!(ThresholdEcdsaSigInputsCreationError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThresholdEcdsaGetPublicKeyError {}
impl_display_using_debug!(ThresholdEcdsaGetPublicKeyError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgTranscriptParsingError {}
impl_display_using_debug!(IDkgTranscriptParsingError);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IDkgCreateTranscriptError {
    SerializationError { internal_error: String },
    InternalError { internal_error: String },
    DealerNotAllowed { node_id: NodeId },
    SignerNotAllowed { node_id: NodeId },
    UnsatisfiedCollectionThreshold { threshold: u32, dealer_count: u32 },
    InvalidMultisignature { crypto_error: CryptoError },
}
impl_display_using_debug!(IDkgCreateTranscriptError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgVerifyTranscriptError {}
impl_display_using_debug!(IDkgVerifyTranscriptError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgOpenTranscriptError {}
impl_display_using_debug!(IDkgOpenTranscriptError);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IDkgLoadTranscriptError {
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
        key_bytes: Vec<u8>,
    },
    UnsupportedAlgorithm {
        algorithm_id: Option<AlgorithmIdProto>,
    },
    RegistryError(RegistryClientError),
}
impl_display_using_debug!(IDkgLoadTranscriptError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgLoadTranscriptWithOpeningsError {}
impl_display_using_debug!(IDkgLoadTranscriptWithOpeningsError);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IDkgCreateDealingError {
    NotADealer {
        node_id: NodeId,
    },
    MalformedPublicKey {
        node_id: NodeId,
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
    InternalError {
        internal_error: String,
    },
    SecretSharesNotFound {
        commitment_string: String,
    },
    AlgorithmMismatchWithSKS {
        algorithm_id: AlgorithmId,
    },
}
impl_display_using_debug!(IDkgCreateDealingError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgVerifyDealingPublicError {}
impl_display_using_debug!(IDkgVerifyDealingPublicError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgVerifyDealingPrivateError {
    NotAReceiver,
}
impl_display_using_debug!(IDkgVerifyDealingPrivateError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgComplaintParsingError {}
impl_display_using_debug!(IDkgComplaintParsingError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgVerifyComplaintError {}
impl_display_using_debug!(IDkgVerifyComplaintError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgOpeningParsingError {}
impl_display_using_debug!(IDkgOpeningParsingError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IDkgVerifyOpeningError {}
impl_display_using_debug!(IDkgVerifyOpeningError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThresholdEcdsaVerifySigShareError {}
impl_display_using_debug!(ThresholdEcdsaVerifySigShareError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThresholdEcdsaSignShareError {}
impl_display_using_debug!(ThresholdEcdsaSignShareError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThresholdEcdsaVerifyCombinedSignatureError {}
impl_display_using_debug!(ThresholdEcdsaVerifyCombinedSignatureError);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThresholdEcdsaCombineSigSharesError {}
impl_display_using_debug!(ThresholdEcdsaCombineSigSharesError);
