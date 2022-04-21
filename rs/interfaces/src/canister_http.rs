//! Canister Http related public interfaces.
use crate::{
    artifact_pool::UnvalidatedArtifact, consensus_pool::ConsensusPoolCache,
    payload::BatchPayloadSectionType, validation::ValidationError,
};
use ic_base_types::NumBytes;
use ic_types::{
    artifact::{CanisterHttpResponseId, PriorityFn},
    batch::{CanisterHttpPayload, ValidationContext},
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseAttribute, CanisterHttpResponseShare,
    },
    consensus::Payload,
    crypto::CryptoHashOf,
    Height, Time,
};

#[derive(Debug)]
pub enum CanisterHttpPermananentValidationError {
    PayloadTooBig { expected: usize, received: usize },
}

#[derive(Debug)]
pub enum CanisterHttpTransientValidationError {}

pub type CanisterHttpPayloadValidationError =
    ValidationError<CanisterHttpPermananentValidationError, CanisterHttpTransientValidationError>;

impl BatchPayloadSectionType for CanisterHttpPayload {
    type PermanentValidationError = CanisterHttpPermananentValidationError;
    type TransientValidationError = CanisterHttpTransientValidationError;
}

pub enum CanisterHttpChangeAction {
    AddToValidated(CanisterHttpResponseShare, CanisterHttpResponse),
    MoveToValidated(CanisterHttpResponseId),
    RemoveValidated(CanisterHttpResponseId),
    RemoveUnvalidated(CanisterHttpResponseId),
    HandleInvalid(CanisterHttpResponseId, String),
}

pub type CanisterHttpChangeSet = Vec<CanisterHttpChangeAction>;

/// Artifact pool for the ECDSA messages (query interface)
pub trait CanisterHttpPool: Send + Sync {
    fn get_validated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_>;
    fn get_unvalidated_shares(&self) -> Box<dyn Iterator<Item = &CanisterHttpResponseShare> + '_>;
    fn get_response_content_items(
        &self,
    ) -> Box<dyn Iterator<Item = (&CryptoHashOf<CanisterHttpResponse>, &CanisterHttpResponse)> + '_>;

    fn lookup_validated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare>;

    fn lookup_unvalidated(
        &self,
        msg_id: &CanisterHttpResponseId,
    ) -> Option<CanisterHttpResponseShare>;
}

pub trait MutableCanisterHttpPool: CanisterHttpPool {
    /// Adds the entry to the unvalidated section of the artifact pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<CanisterHttpResponseShare>);

    /// Mutates the artifact pool by applying the change set.
    fn apply_changes(&mut self, change_set: CanisterHttpChangeSet);
}

pub trait CanisterHttpGossip: Send + Sync {
    fn get_priority_function(
        &self,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> PriorityFn<CanisterHttpResponseId, CanisterHttpResponseAttribute>;
}

pub trait CanisterHttpPoolManager: Send {
    /// A function to be invoked every time the canister http pool is changed.
    fn on_state_change(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet;
}

pub trait CanisterHttpPayloadBuilder: Send + Sync {
    fn get_canister_http_payload(
        &self,
        validation_context: &ValidationContext,
        past_payloads: &[&CanisterHttpPayload],
        byte_limit: NumBytes,
    ) -> CanisterHttpPayload;

    fn validate_canister_http_payload(
        &self,
        payload: &CanisterHttpPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&CanisterHttpPayload],
    ) -> Result<NumBytes, CanisterHttpPayloadValidationError>;

    fn filter_past_payloads<'a>(
        &self,
        past_payloads: &'a [(Height, Time, Payload)],
    ) -> Vec<&'a CanisterHttpPayload> {
        past_payloads
            .iter()
            .filter_map(|(_, _, payload)| {
                if payload.is_summary() {
                    None
                } else {
                    Some(&payload.as_ref().as_data().batch.canister_http)
                }
            })
            .collect()
    }
}
