//! This module contains the gossip implementation of the canister http feature.

pub use crate::pool_manager::CanisterHttpPoolManagerImpl;
use ic_interfaces::{
    canister_http::CanisterHttpPool,
    p2p::consensus::{Bouncer, BouncerFactory, BouncerValue},
};
use ic_interfaces_state_manager::StateReader;
use ic_replicated_state::ReplicatedState;
use ic_types::{artifact::CanisterHttpResponseId, messages::CallbackId};
use std::{collections::BTreeSet, sync::Arc};

// We are aiming for about 100 req/s for http outcalls. Assuming that the priority function gets
// called about once every 3 seconds, we do not expect the number of requests to grow from one call
// to another by about 100 http outcalls + 15 other management canister calls per second.
const MAX_NUMBER_OF_REQUESTS_AHEAD: u64 = 3 * (100 + 15);

/// The canonical implementation of [`BouncerFactory`]
pub struct CanisterHttpGossipImpl {
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl CanisterHttpGossipImpl {
    /// Construcet a new CanisterHttpGossipImpl instance
    pub fn new(state_reader: Arc<dyn StateReader<State = ReplicatedState>>) -> Self {
        CanisterHttpGossipImpl { state_reader }
    }
}

impl<Pool: CanisterHttpPool> BouncerFactory<CanisterHttpResponseId, Pool>
    for CanisterHttpGossipImpl
{
    fn new_bouncer(&self, _canister_http_pool: &Pool) -> Bouncer<CanisterHttpResponseId> {
        let (known_request_ids, next_callback_id) = {
            let latest_state = self.state_reader.get_latest_state();
            let subnet_call_context_manger =
                &latest_state.get_ref().metadata.subnet_call_context_manager;
            let known_request_ids: BTreeSet<_> = subnet_call_context_manger
                .canister_http_request_contexts
                .keys()
                .chain(
                    subnet_call_context_manger
                        .delivered_canister_http_request_contexts
                        .keys(),
                )
                .copied()
                .collect();
            let next_callback_id = subnet_call_context_manger.next_callback_id();
            (known_request_ids, next_callback_id)
        };
        Box::new(move |id: &'_ CanisterHttpResponseId| {
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
            if known_request_ids.contains(&id.content.id())
                || (id.content.id() >= next_callback_id
                    && id.content.id() <= highest_accepted_request_id)
            {
                BouncerValue::Wants
            } else if id.content.id() > highest_accepted_request_id {
                BouncerValue::MaybeWantsLater
            } else {
                BouncerValue::Unwanted
            }
        })
    }

    fn refresh_period(&self) -> std::time::Duration {
        std::time::Duration::from_secs(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
    use ic_interfaces_state_manager::Labeled;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::SubnetCallContext;
    use ic_test_utilities::state_manager::RefMockStateManager;
    use ic_test_utilities_types::{
        ids::{node_test_id, subnet_test_id, test_replica_version},
        messages::RequestBuilder,
    };
    use ic_types::{
        Height, NumberOfNodes, RegistryVersion,
        canister_http::{
            CanisterHttpMethod, CanisterHttpPaymentReceipt, CanisterHttpRequestContext,
            CanisterHttpResponseMetadata, CanisterHttpResponseReceipt, PricingVersion,
            RefundStatus, Replication,
        },
        crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed},
        signature::BasicSignature,
        time::UNIX_EPOCH,
    };
    use ic_types_cycles::CanisterCyclesCostSchedule;
    use std::sync::Arc;

    fn request_context() -> CanisterHttpRequestContext {
        CanisterHttpRequestContext {
            request: RequestBuilder::new().build(),
            url: String::new(),
            max_response_bytes: None,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: UNIX_EPOCH,
            replication: Replication::FullyReplicated,
            pricing_version: PricingVersion::PayAsYouGo,
            refund_status: RefundStatus::default(),
            registry_version: RegistryVersion::from(1),
            subnet_size: NumberOfNodes::from(13),
            cost_schedule: CanisterCyclesCostSchedule::Normal,
        }
    }

    fn share_id(callback_id: CallbackId) -> CanisterHttpResponseId {
        Signed {
            content: CanisterHttpResponseReceipt {
                metadata: CanisterHttpResponseMetadata {
                    id: callback_id,
                    content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                    content_size: 0,
                    is_reject: false,
                    replica_version: test_replica_version(),
                },
                payment_receipt: CanisterHttpPaymentReceipt::default(),
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: node_test_id(0),
            },
        }
    }

    /// The `next_callback_id` of the state [`test_bouncer`] builds.
    const NEXT_CALLBACK_ID: u64 = 3;

    /// A bouncer over a state that has handed out callback ids 0, 1 and 2 — so
    /// `next_callback_id` is [`NEXT_CALLBACK_ID`] — of which 0 is still awaiting a
    /// response, 1 has been responded to, and 2 is gone for good.
    fn test_bouncer() -> Bouncer<CanisterHttpResponseId> {
        let mut state = ReplicatedState::new(subnet_test_id(0), SubnetType::Application);
        let contexts = &mut state.metadata.subnet_call_context_manager;
        // Advance `next_callback_id` to NEXT_CALLBACK_ID
        for _ in 0..NEXT_CALLBACK_ID {
            contexts.push_context(SubnetCallContext::CanisterHttpRequest(request_context()));
        }
        contexts.canister_http_request_contexts.clear();
        contexts
            .canister_http_request_contexts
            .insert(CallbackId::new(0), request_context());
        contexts
            .delivered_canister_http_request_contexts
            .insert(CallbackId::new(1), request_context());

        let state_manager = Arc::new(RefMockStateManager::default());
        state_manager
            .get_mut()
            .expect_get_latest_state()
            .return_const(Labeled::new(Height::new(1), Arc::new(state)));

        let gossip = CanisterHttpGossipImpl::new(state_manager);
        let pool = CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
        gossip.new_bouncer(&pool)
    }

    #[test]
    fn shares_of_delivered_contexts_are_wanted() {
        let bouncer = test_bouncer();

        assert_eq!(bouncer(&share_id(CallbackId::new(0))), BouncerValue::Wants);
        assert_eq!(bouncer(&share_id(CallbackId::new(1))), BouncerValue::Wants);
        // A request that is neither pending nor delivered is settled for good.
        assert_eq!(
            bouncer(&share_id(CallbackId::new(2))),
            BouncerValue::Unwanted
        );
    }

    #[test]
    fn shares_of_upcoming_requests_are_wanted() {
        let bouncer = test_bouncer();

        // The very next id execution will hand out, ...
        assert_eq!(
            bouncer(&share_id(CallbackId::new(NEXT_CALLBACK_ID))),
            BouncerValue::Wants
        );
        // ... and everything up to the far edge of the look-ahead window.
        assert_eq!(
            bouncer(&share_id(CallbackId::new(
                NEXT_CALLBACK_ID + MAX_NUMBER_OF_REQUESTS_AHEAD
            ))),
            BouncerValue::Wants
        );
    }

    #[test]
    fn shares_beyond_the_look_ahead_window_are_stashed() {
        let bouncer = test_bouncer();

        assert_eq!(
            bouncer(&share_id(CallbackId::new(
                NEXT_CALLBACK_ID + MAX_NUMBER_OF_REQUESTS_AHEAD + 1
            ))),
            BouncerValue::MaybeWantsLater
        );
    }
}
