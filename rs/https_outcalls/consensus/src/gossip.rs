//! This module contains the gossip implementation of the canister http feature.

pub use crate::pool_manager::CanisterHttpPoolManagerImpl;
use ic_consensus_utils::registry_version_at_height;
use ic_interfaces::{
    artifact_pool::PriorityFnAndFilterProducer, canister_http::CanisterHttpPool,
    consensus_pool::ConsensusPoolCache,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::{CanisterHttpResponseId, Priority, PriorityFn},
    artifact_kind::CanisterHttpArtifact,
    canister_http::CanisterHttpResponseAttribute,
};
use std::{collections::BTreeSet, sync::Arc};

/// The canonical implementation of [`PriorityFnAndFilterProducer`]
pub struct CanisterHttpGossipImpl {
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    log: ReplicaLogger,
}

impl CanisterHttpGossipImpl {
    /// Construcet a new CanisterHttpGossipImpl instance
    pub fn new(
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        log: ReplicaLogger,
    ) -> Self {
        CanisterHttpGossipImpl {
            consensus_cache,
            state_reader,
            log,
        }
    }
}

impl<Pool: CanisterHttpPool> PriorityFnAndFilterProducer<CanisterHttpArtifact, Pool>
    for CanisterHttpGossipImpl
{
    fn get_priority_function(
        &self,
        _canister_http_pool: &Pool,
    ) -> PriorityFn<CanisterHttpResponseId, CanisterHttpResponseAttribute> {
        let finalized_height = self.consensus_cache.finalized_block().height;
        let registry_version =
            registry_version_at_height(self.consensus_cache.as_ref(), finalized_height).unwrap();
        let known_request_ids: BTreeSet<_> = self
            .state_reader
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
