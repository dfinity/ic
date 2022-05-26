//! This module encapsulates all components required for canister http requests.
use crate::consensus::utils::registry_version_at_height;
use ic_interfaces::{
    canister_http::{
        CanisterHttpGossip, CanisterHttpPayloadBuilder, CanisterHttpPayloadValidationError,
        CanisterHttpPermananentValidationError, CanisterHttpPool,
    },
    consensus_pool::ConsensusPoolCache,
};
use ic_interfaces_state_manager::StateManager;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::{CanisterHttpResponseId, Priority, PriorityFn},
    batch::{CanisterHttpPayload, ValidationContext},
    canister_http::CanisterHttpResponseAttribute,
    CountBytes, NumBytes,
};
use std::{collections::BTreeSet, sync::Arc};

pub mod pool_manager;

/// The canonical implementation of CanisterHttpGossip
struct CanisterHttpGossipImpl {
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
}

impl CanisterHttpGossip for CanisterHttpGossipImpl {
    fn get_priority_function(
        &self,
        _canister_http_pool: &dyn CanisterHttpPool,
    ) -> PriorityFn<CanisterHttpResponseId, CanisterHttpResponseAttribute> {
        let finalized_height = self.consensus_cache.finalized_block().height;
        let registry_version =
            registry_version_at_height(self.consensus_cache.as_ref(), finalized_height).unwrap();
        let known_request_ids: BTreeSet<_> = self
            .state_manager
            .get_latest_state()
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .iter()
            .map(|item| *item.0)
            .collect();
        Box::new(
            move |_, attr: &'_ CanisterHttpResponseAttribute| match attr {
                CanisterHttpResponseAttribute::Share(
                    msg_registry_version,
                    callback_id,
                    _content_hash,
                ) => {
                    if *msg_registry_version != registry_version {
                        return Priority::Drop;
                    }
                    if known_request_ids.contains(callback_id) {
                        Priority::Fetch
                    } else {
                        Priority::Stash
                    }
                }
            },
        )
    }
}

/// Implementation of the [`CanisterHttpPayloadBuilder`].
#[derive(Debug, Clone, Default)]
pub struct CanisterHttpPayloadBuilderImpl {}

impl CanisterHttpPayloadBuilderImpl {
    /// Create and initialize an instance of [`CanisterHttpPayloadBuilderImpl`].
    pub fn new() -> Self {
        Self {}
    }
}

impl CanisterHttpPayloadBuilder for CanisterHttpPayloadBuilderImpl {
    fn get_canister_http_payload(
        &self,
        _validation_context: &ValidationContext,
        _past_payloads: &[&CanisterHttpPayload],
        _byte_limit: NumBytes,
    ) -> CanisterHttpPayload {
        // For now, we always return the empty payload
        CanisterHttpPayload::default()
    }

    fn validate_canister_http_payload(
        &self,
        payload: &CanisterHttpPayload,
        _validation_context: &ValidationContext,
        _past_payloads: &[&CanisterHttpPayload],
    ) -> Result<NumBytes, CanisterHttpPayloadValidationError> {
        // For now, we reject any canister http payload that is not empty
        let payload_size = payload.count_bytes();
        if payload_size != 0 {
            Err(CanisterHttpPayloadValidationError::Permanent(
                CanisterHttpPermananentValidationError::PayloadTooBig {
                    expected: 0,
                    received: payload_size,
                },
            ))
        } else {
            Ok(NumBytes::new(0))
        }
    }
}
