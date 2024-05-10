//! This module contains the gossip implementation of the canister http feature.

pub use crate::pool_manager::CanisterHttpPoolManagerImpl;
use ic_consensus_utils::registry_version_at_height;
use ic_interfaces::{
    canister_http::CanisterHttpPool, consensus_pool::ConsensusPoolCache,
    p2p::consensus::PriorityFnAndFilterProducer,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::{CanisterHttpResponseId, Priority, PriorityFn},
    artifact_kind::CanisterHttpArtifact,
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
    ) -> PriorityFn<CanisterHttpResponseId, ()> {
        let finalized_height = self.consensus_cache.finalized_block().height;
        let registry_version =
            registry_version_at_height(self.consensus_cache.as_ref(), finalized_height).unwrap();
        let (known_request_ids, next_callback_id) = {
            let latest_state = self.state_reader.get_latest_state();
            let subnet_call_context_manger =
                &latest_state.get_ref().metadata.subnet_call_context_manager;
            let known_request_ids: BTreeSet<_> = subnet_call_context_manger
                .canister_http_request_contexts
                .iter()
                .map(|item| *item.0)
                .collect();
            let next_callback_id = subnet_call_context_manger.next_callback_id();
            (known_request_ids, next_callback_id)
        };
        let log = self.log.clone();
        Box::new(move |id: &'_ CanisterHttpResponseId, _| {
            if id.content.registry_version != registry_version {
                warn!(log, "Dropping canister http response share with callback id: {}, because registry version {} does not match expected version {}", id.content.id, id.content.registry_version, registry_version);
                return Priority::Drop;
            }
            // The https outcalls share should be fetched in two cases:
            //  - The Id of the share is part of the state which means it is active.
            //  - The callback Id is higher than the next callback Id (the next callback Id is the Id used next in execution round).
            //    Receiving an callback Id higher is possible because the priority fn is updated periodically (every 3s) with the latest state
            //    and can therefore store stale `known_request_ids` and stale `next_callback_id`.
            if known_request_ids.contains(&id.content.id) || id.content.id >= next_callback_id {
                Priority::FetchNow
            } else {
                Priority::Drop
            }
        })
    }
}
