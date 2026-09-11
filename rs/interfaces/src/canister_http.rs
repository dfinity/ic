//! Canister Http related public interfaces.
use crate::validation::ValidationError;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{
    NodeId,
    artifact::CanisterHttpResponseId,
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseArtifact, CanisterHttpResponseShare,
    },
    consensus::Threshold,
    crypto::{CryptoError, CryptoHashOf},
    messages::CallbackId,
};
use ic_types_cycles::Cycles;

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
    },
    /// The content hash of the signed metadata does not match the actual hash of the content
    ContentHashMismatch {
        metadata_hash: CryptoHashOf<CanisterHttpResponse>,
        calculated_hash: CryptoHashOf<CanisterHttpResponse>,
    },
    /// The content size of the signed metadata does not match the actual size of the content
    ContentSizeMismatch {
        metadata_size: u32,
        calculated_size: u32,
    },
    /// The is_reject flag of the signed metadata does not match the actual response content type
    IsRejectMismatch {
        metadata_is_reject: bool,
        calculated_is_reject: bool,
    },
    /// A timeout refers to a CallbackId that is unknown by the StateManager
    UnknownCallbackId(CallbackId),
    /// An asynchronous receipt refers to a CallbackId that the StateManager does not
    /// know as an already responded to request, i.e. one that is not among the
    /// `delivered_canister_http_request_contexts`.
    UnknownDeliveredCallbackId(CallbackId),
    /// An asynchronous receipt refers to an already responded to request whose
    /// delivered context has timed out, i.e. one that message routing settles and
    /// drops in this very block, leaving nothing left to refund.
    DeliveredCallbackTimedOut(CallbackId),
    /// An asynchronous receipt reports a replica whose spend has already been
    /// accounted for, either in the certified state or in a past payload.
    AlreadyRefunded {
        callback_id: CallbackId,
        signer: NodeId,
    },
    /// A CallbackId was included as a timeout, however the Request has not timed out at all
    NotTimedOut(CallbackId),
    /// There was an error with a signature calculation
    SignatureError(Box<CryptoError>),
    /// A payment receipt claims the replica spent more than it was allowed to:
    /// the per-replica allowance derived from the request's payment on a
    /// charging subnet, or the free-subnet maximum on a free subnet.
    SpentExceedsLimit {
        spent: Cycles,
        limit: Cycles,
    },
    /// A share claims a `content_size` larger than the largest response the replica
    /// could have produced, i.e. [`CanisterHttpRequestContext::max_http_outcall_content_size`].
    ///
    /// [`CanisterHttpRequestContext::max_http_outcall_content_size`]: ic_types::canister_http::CanisterHttpRequestContext::max_http_outcall_content_size
    ContentSizeExceedsLimit {
        callback_id: CallbackId,
        content_size: u32,
        limit: u64,
    },
    /// The collective initial spent cycles included in the payload do not match
    /// the value recomputed from the request context's subnet size and the
    /// signed per-replica receipts.
    InitialSpentMismatch {
        callback_id: CallbackId,
        /// The initial spend received in the payload.
        received: Cycles,
        /// The initial spend the validator recomputed and expected.
        expected: Cycles,
    },
    /// The collective initial spent cycles of a response exceed the collective
    /// allowance of the replicas that contributed to it, i.e. the sum of their
    /// per-replica allowances.
    InitialSpentExceedsLimit {
        callback_id: CallbackId,
        initial_spent: Cycles,
        per_replica_allowance: Cycles,
        num_replicas: usize,
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
    /// The callback_id a share or response is signed for does not match the one of
    /// the payload section it appears in.
    ShareCallbackIdMismatch {
        callback_id: CallbackId,
        mismatched_id: CallbackId,
    },
    /// The number of responses in a flexible group is outside the [min, max] range.
    FlexibleResponseCountOutOfRange {
        callback_id: CallbackId,
        count: usize,
        min_responses: u32,
        max_responses: u32,
    },
    /// A payload section carrying individual shares has more than one from the same
    /// signer.
    DuplicateShareSigner {
        callback_id: CallbackId,
        signer: NodeId,
    },
    /// A share is signed by a node that is not part of the request's committee.
    ShareSignerNotInCommittee {
        callback_id: CallbackId,
        signer: NodeId,
    },
    /// A flexible ok-response group contains a Reject response.
    FlexibleRejectNotAllowedInOkResponses {
        callback_id: CallbackId,
    },
    /// The payload is not in its designated section.
    /// For example, a non-flexible response is not in the responses section
    /// or a flexible response is not in the flexible_responses section.
    InvalidPayloadSection(CallbackId),
    /// A TooManyRejects error does not carry enough rejects.
    FlexibleInsufficientRejectCount {
        callback_id: CallbackId,
        reject_count: usize,
        min_needed: usize,
    },
    /// A TooManyRejects entry contains a non-Reject response.
    FlexibleRejectExpectedInErrorResponse(CallbackId),
    /// A ResponsesTooLarge error has incorrect total_requests or min_responses.
    FlexibleResponsesTooLargeParamMismatch {
        callback_id: CallbackId,
        field: &'static str,
        expected: u32,
        actual: u32,
    },
    /// A ResponsesTooLarge error does not include enough OK shares to prove impossibility.
    FlexibleResponsesTooLargeInsufficientEvidence {
        callback_id: CallbackId,
        ok_count: usize,
        min_known_ok_needed: usize,
    },
    /// A ResponsesTooLarge error is invalid: the smallest responses actually fit.
    FlexibleResponsesNotTooLarge(CallbackId),
    /// A figure an OutOfCycles error reports to the caller does not match the value
    /// recomputed from the request context and the signed receipts.
    OutOfCyclesFigureMismatch {
        callback_id: CallbackId,
        field: &'static str,
        /// The figure received in the payload.
        received: Cycles,
        /// The figure the validator recomputed and expected.
        expected: Cycles,
    },
    /// An OutOfCycles error is invalid: what is left of the committee's
    /// per-replica allowances can still cover the cost of delivering a response.
    NotOutOfCycles {
        callback_id: CallbackId,
        /// The committee's collective allowance that is still unspent, assuming
        /// that every committee member that has not reported a spend yet has
        /// spent nothing; or `None` if the outcall has no per-replica allowance to
        /// spend in the first place, and so none to run out of.
        unspent_allowance: Option<Cycles>,
        /// The least it can cost to deliver a response, or `None` if no response
        /// can be delivered any more, in which case there is no cost to cover.
        min_cost: Option<Cycles>,
    },
    /// The payload could not be deserialized
    DecodeError(ProxyDecodeError),
}

/// A transient failure that can occur during validation of a [`CanisterHttpPayload`]
#[derive(Debug)]
pub enum CanisterHttpPayloadValidationFailure {
    /// The state was not available at the time of validation
    StateUnavailable,
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
