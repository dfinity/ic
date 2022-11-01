//! This module contains the gossip implementation of the canister http feature.

pub use crate::canister_http::pool_manager::CanisterHttpPoolManagerImpl;
use crate::consensus::utils::registry_version_at_height;
use ic_interfaces::{
    canister_http::{CanisterHttpGossip, CanisterHttpPool},
    consensus_pool::ConsensusPoolCache,
};
use ic_interfaces_state_manager::StateManager;
use ic_logger::{warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::{CanisterHttpResponseId, Priority, PriorityFn},
    canister_http::CanisterHttpResponseAttribute,
};
use std::{collections::BTreeSet, sync::Arc};

/// The canonical implementation of [`CanisterHttpGossip`]
pub struct CanisterHttpGossipImpl {
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    log: ReplicaLogger,
}

impl CanisterHttpGossipImpl {
    /// Construcet a new CanisterHttpGossipImpl instance
    pub fn new(
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        log: ReplicaLogger,
    ) -> Self {
        CanisterHttpGossipImpl {
            consensus_cache,
            state_manager,
            log,
        }
    }
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
        let log = self.log.clone();
        Box::new(
            move |_, attr: &'_ CanisterHttpResponseAttribute| match attr {
                CanisterHttpResponseAttribute::Share(
                    msg_registry_version,
                    callback_id,
                    _content_hash,
                ) => {
                    if *msg_registry_version != registry_version {
                        warn!(log, "Dropping canister http response share with callback id: {}, because registry version {} does not match expected version {}", callback_id, msg_registry_version, registry_version);
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
