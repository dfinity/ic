//! This module contains the gossip implementation of the canister http feature.

pub use crate::pool_manager::CanisterHttpPoolManagerImpl;
use ic_consensus_utils::registry_version_at_height;
use ic_interfaces::{
    canister_http::CanisterHttpPool,
    consensus_pool::ConsensusPoolCache,
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue},
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::CanisterHttpResponseId, canister_http::CanisterHttpResponseShare,
    messages::CallbackId,
};
use std::{collections::BTreeSet, sync::Arc};

// We are aiming for about 100 req/s for http outcalls. Assuming that the priority function gets
// called about once every 3 seconds, we do not expect the number of requests to grow from one call
// to another by about 100 http outcalls + 15 other management canister calls per second.
const MAX_NUMBER_OF_REQUESTS_AHEAD: u64 = 3 * (100 + 15);

/// The canonical implementation of [`BouncerFactory`]
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

impl<Pool: CanisterHttpPool> BouncerFactory<CanisterHttpResponseId, Pool>
    for CanisterHttpGossipImpl
{
    fn new_bouncer(&self, _canister_http_pool: &Pool) -> Bouncer<CanisterHttpResponseId> {
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
        Box::new(move |id: &'_ CanisterHttpResponseId| {
            if id.content.registry_version != registry_version {
                warn!(log, "Dropping canister http response share with callback id: {}, because registry version {} does not match expected version {}", id.content.id, id.content.registry_version, registry_version);
                return BouncerValue::Unwanted;
            }

            // We derive the highest accepted request id from the next expected request id, plus the
            // number of maximal number of new requests we can get between the function calls.
            let highest_accepted_request_id =
                CallbackId::from(next_callback_id.get() + MAX_NUMBER_OF_REQUESTS_AHEAD);

            // The https outcalls share should be fetched in two cases:
            //  - The Id of the share is part of the state which means it is active.
            //  - The callback Id is higher than the next callback Id (the next callback Id is the Id used next in execution round), but
            //    not higher that `MAX_NUMBER_OF_REQUESTS_AHEAD`.
            //    Receiving an callback Id higher is possible because the priority fn is updated periodically (every 3s) with the latest state
            //    and can therefore store stale `known_request_ids` and stale `next_callback_id`.
            if known_request_ids.contains(&id.content.id)
                || (id.content.id >= next_callback_id
                    && id.content.id <= highest_accepted_request_id)
            {
                BouncerValue::Wants
            } else if id.content.id > highest_accepted_request_id {
                BouncerValue::MaybeWantsLater
            } else {
                BouncerValue::Unwanted
            }
        })
    }
}
