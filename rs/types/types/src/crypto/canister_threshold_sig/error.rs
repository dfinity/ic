//! Defines errors that may occur in the context of canister threshold
//! signatures.
use crate::crypto::{AlgorithmId, CryptoError};
use crate::registry::RegistryClientError;
use crate::{NodeId, RegistryVersion};
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresignatureQuadrupleCreationError {
    WrongTypes,
}
impl_display_using_debug!(PresignatureQuadrupleCreationError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdEcdsaSigInputsCreationError {
    NonmatchingTranscriptIds,
}
impl_display_using_debug!(ThresholdEcdsaSigInputsCreationError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdEcdsaGetPublicKeyError {}
impl_display_using_debug!(ThresholdEcdsaGetPublicKeyError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgTranscriptParsingError {}
impl_display_using_debug!(IDkgTranscriptParsingError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgCreateTranscriptError {
    SerializationError { internal_error: String },
    InternalError { internal_error: String },
    DealerNotAllowed { node_id: NodeId },
    SignerNotAllowed { node_id: NodeId },
    UnsatisfiedCollectionThreshold { threshold: u32, dealer_count: u32 },
    InvalidMultisignature { crypto_error: CryptoError },
}
impl_display_using_debug!(IDkgCreateTranscriptError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgVerifyTranscriptError {}
impl_display_using_debug!(IDkgVerifyTranscriptError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgOpenTranscriptError {}
impl_display_using_debug!(IDkgOpenTranscriptError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgLoadTranscriptWithOpeningsError {}
impl_display_using_debug!(IDkgLoadTranscriptWithOpeningsError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgVerifyDealingPublicError {}
impl_display_using_debug!(IDkgVerifyDealingPublicError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgVerifyDealingPrivateError {
    NotAReceiver,
}
impl_display_using_debug!(IDkgVerifyDealingPrivateError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgComplaintParsingError {}
impl_display_using_debug!(IDkgComplaintParsingError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgVerifyComplaintError {}
impl_display_using_debug!(IDkgVerifyComplaintError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgOpeningParsingError {}
impl_display_using_debug!(IDkgOpeningParsingError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IDkgVerifyOpeningError {}
impl_display_using_debug!(IDkgVerifyOpeningError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdEcdsaVerifySigShareError {}
impl_display_using_debug!(ThresholdEcdsaVerifySigShareError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdEcdsaSignShareError {}
impl_display_using_debug!(ThresholdEcdsaSignShareError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdEcdsaVerifyCombinedSignatureError {}
impl_display_using_debug!(ThresholdEcdsaVerifyCombinedSignatureError);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdEcdsaCombineSigSharesError {}
impl_display_using_debug!(ThresholdEcdsaCombineSigSharesError);
