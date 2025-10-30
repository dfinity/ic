//! Canister Http related public interfaces.
use crate::validation::ValidationError;
use ic_base_types::RegistryVersion;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{
    NodeId, Time,
    artifact::CanisterHttpResponseId,
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseArtifact, CanisterHttpResponseShare,
    },
    consensus::Threshold,
    crypto::{CryptoError, CryptoHashOf},
    messages::CallbackId,
};

#[derive(Debug)]
pub enum InvalidCanisterHttpPayloadReason {
    /// The [`CanisterHttpPayload`] is too large
    PayloadTooBig {
        expected: usize,
        received: usize,
    },
    /// There are too many responses in the payload
    TooManyResponses {
        expected: usize,
        received: usize,
    },
    /// The signed metadata does not match the metadata of the content
    InvalidMetadata {
        metadata_id: CallbackId,
        content_id: CallbackId,
        metadata_timeout: Time,
        content_timeout: Time,
    },
    /// The content hash of the signed metadata does not match the actual hash of the content
    ContentHashMismatch {
        metadata_hash: CryptoHashOf<CanisterHttpResponse>,
        calculated_hash: CryptoHashOf<CanisterHttpResponse>,
    },
    /// The response has already timed out
    Timeout {
        timed_out_at: Time,
        validation_time: Time,
    },
    /// A timeout refers to a CallbackId that is unknown by the StateManager
    UnknownCallbackId(CallbackId),
    /// A CallbackId was included as a timeout, however the Request has not timed out at all
    NotTimedOut(CallbackId),
    /// The registry version of a response does not match the validation context
    RegistryVersionMismatch {
        expected: RegistryVersion,
        received: RegistryVersion,
    },
    /// There was an error with a signature calculation
    SignatureError(Box<CryptoError>),
    /// Some of the signatures in the canister http proof were not members of
    /// the canister http committee.
    SignersNotMembers {
        committee: Vec<NodeId>,
        invalid_signers: Vec<NodeId>,
        valid_signers: Vec<NodeId>,
    },
    /// There were not enough signers in the canister http response proof
    NotEnoughSigners {
        committee: Vec<NodeId>,
        signers: Vec<NodeId>,
        expected_threshold: Threshold,
    },
    /// The payload contains a duplicate response
    DuplicateResponse(CallbackId),
    DivergenceProofContainsMultipleCallbackIds,
    DivergenceProofDoesNotMeetDivergenceCriteria,
    /// The payload could not be deserialized
    DecodeError(ProxyDecodeError),
}

/// A transient failure that can occur during validation of a [`CanisterHttpPayload`]
#[derive(Debug)]
pub enum CanisterHttpPayloadValidationFailure {
    /// The state was not available at the time of validation
    StateUnavailable,
    /// The consensus registry version could not be retrieved from the summary
    ConsensusRegistryVersionUnavailable,
    /// The feature is not enabled
    Disabled,
    /// Membership Issue
    Membership,
}

pub type CanisterHttpPayloadValidationError =
    ValidationError<InvalidCanisterHttpPayloadReason, CanisterHttpPayloadValidationFailure>;

#[derive(Debug)]
pub enum CanisterHttpChangeAction {
    AddToValidated(CanisterHttpResponseShare, CanisterHttpResponse),
    AddToValidatedAndGossipResponse(CanisterHttpResponseShare, CanisterHttpResponse),
    MoveToValidated(CanisterHttpResponseShare),
    RemoveValidated(CanisterHttpResponseId),
    RemoveUnvalidated(CanisterHttpResponseId),
    RemoveContent(CryptoHashOf<CanisterHttpResponse>),
    HandleInvalid(CanisterHttpResponseId, String),
}

pub type CanisterHttpChangeSet = Vec<CanisterHttpChangeAction>;

/// Artifact pool for the Canister HTTP messages (query interface)
pub trait CanisterHttpPool: Send + Sync {
    fn get_validated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_>;
    fn get_unvalidated_artifacts(
        &self,
    ) -> Box<dyn Iterator<Item = &CanisterHttpResponseArtifact> + '_>;
    fn get_unvalidated_artifact(
        &self,
        share: &CanisterHttpResponseShare,
    ) -> Option<&CanisterHttpResponseArtifact>;
    // TODO: Likely not needed
    fn get_response_content_items(
        &self,
    ) -> Box<dyn Iterator<Item = (&CryptoHashOf<CanisterHttpResponse>, &CanisterHttpResponse)> + '_>;

    fn get_response_content_by_hash(
        &self,
        hash: &CryptoHashOf<CanisterHttpResponse>,
    ) -> Option<CanisterHttpResponse>;

    fn lookup_validated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare>;
}
