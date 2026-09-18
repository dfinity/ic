//! This module defines the [`CanisterHttpPoolManagerImpl`], which is an object
//! responsible for managing the flow of requests from execution to the
//! networking component, and ensuring that the resulting responses are signed
//! and eventually make it into consensus.
use crate::metrics::CanisterHttpPoolManagerMetrics;
use crate::payload_builder::utils::{check_content_size_within_limit, check_spent_within_limit};
use ic_consensus_utils::{
    crypto::ConsensusCrypto,
    membership::{Membership, MembershipError},
};
use ic_https_outcalls_socks_proxy::SocksProxyCache;
use ic_interfaces::{
    canister_http::*, consensus_pool::ConsensusPoolCache, p2p::consensus::PoolMutationsProducer,
};
use ic_interfaces_adapter_client::*;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::*;
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    CountBytes, NodeId, canister_http::*, crypto::Signed, messages::CallbackId,
    replica_config::ReplicaConfig,
};
use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
    convert::TryInto,
    sync::{Arc, Mutex},
};

pub type CanisterHttpAdapterClient = Box<
    dyn NonBlockingChannel<
            CanisterHttpRequest,
            Response = (CanisterHttpResponse, CanisterHttpPaymentReceipt),
        > + Send,
>;

/// [`CanisterHttpPoolManagerImpl`] implements the pool and state monitoring
/// functionality that is necessary to ensure that http requests are made and
/// responses can be inserted into consensus. Concretely, it has the following responsibilities:
/// - It must decide when to trigger purging by noticing when consensus time changes
/// - Inform the HttpAdapterShim to make a request when new requests appear in the replicated state
/// - Sign response shares once a request is made
/// - Validate shares in the unvalidated pool that were received from gossip
pub struct CanisterHttpPoolManagerImpl {
    registry_client: Arc<dyn RegistryClient>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    http_adapter_shim: Arc<Mutex<CanisterHttpAdapterClient>>,
    crypto: Arc<dyn ConsensusCrypto>,
    membership: Arc<Membership>,
    replica_config: ReplicaConfig,
    socks_proxy: SocksProxyCache,
    requested_id_cache: RefCell<BTreeSet<CallbackId>>,
    metrics: CanisterHttpPoolManagerMetrics,
    log: ReplicaLogger,
}

impl CanisterHttpPoolManagerImpl {
    /// Create a new [`CanisterHttpPoolManagerImpl`]
    pub fn new(
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        http_adapter_shim: Arc<Mutex<CanisterHttpAdapterClient>>,
        crypto: Arc<dyn ConsensusCrypto>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        replica_config: ReplicaConfig,
        subnet_type: SubnetType,
        registry_client: Arc<dyn RegistryClient>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let membership = Arc::new(Membership::new(
            consensus_pool_cache.clone(),
            registry_client.clone(),
            replica_config.subnet_id,
        ));
        let metrics = CanisterHttpPoolManagerMetrics::new(&metrics_registry);
        let socks_proxy = SocksProxyCache::new(registry_client.clone(), subnet_type, log.clone())
            .with_error_observer({
                let metrics = metrics.clone();
                Arc::new(move |label: &str| metrics.observe_pool_manager_error(label))
            });

        Self {
            state_reader,
            http_adapter_shim,
            crypto,
            replica_config,
            socks_proxy,
            membership,
            registry_client,
            metrics,
            log,
            requested_id_cache: RefCell::new(BTreeSet::new()),
        }
    }

    /// Purge shares of responses for requests that have already been processed,
    /// i.e. whose contexts are no longer part of the replicated state.
    ///
    /// Response *content* is purged earlier than that, as soon as its request leaves
    /// the active contexts: an answered outcall's response can never be put into a
    /// block again, nor be of use to a peer, while its shares are kept for as long as
    /// the delivered context is around, to be published as asynchronous receipts.
    fn purge_shares_of_processed_requests(
        &self,
        state: &ReplicatedState,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["purge_shares"])
            .start_timer();

        let known_callback_ids = Self::known_callback_ids(state);
        let active_contexts = &state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts;
        let next_callback_id = state
            .metadata
            .subnet_call_context_manager
            .next_callback_id();

        let ids_to_remove_from_cache: Vec<_> = self
            .requested_id_cache
            .borrow()
            .difference(&known_callback_ids)
            .cloned()
            .collect();

        for callback_id in ids_to_remove_from_cache.iter() {
            self.requested_id_cache.borrow_mut().remove(callback_id);
        }

        canister_http_pool
            .get_validated_shares()
            .filter_map(|share| {
                if known_callback_ids.contains(&share.content.id()) {
                    None
                } else {
                    Some(CanisterHttpChangeAction::RemoveValidated(share.clone()))
                }
            })
            .chain(
                canister_http_pool
                    .get_unvalidated_artifacts()
                    // Only check the unvalidated shares belonging to the requests that we can validate.
                    .filter(|artifact| artifact.share.content.id() < next_callback_id)
                    .filter_map(|artifact| {
                        let share = &artifact.share;
                        if known_callback_ids.contains(&share.content.id()) {
                            None
                        } else {
                            Some(CanisterHttpChangeAction::RemoveUnvalidated(share.clone()))
                        }
                    }),
            )
            .chain(
                canister_http_pool
                    .get_response_content_items()
                    .filter_map(|content| {
                        // Note that this keys on the active contexts, not on
                        // `known_callback_ids`: the response of an answered outcall is
                        // dropped while its share lives on as a receipt.
                        if active_contexts.contains_key(&content.1.id) {
                            None
                        } else {
                            Some(CanisterHttpChangeAction::RemoveContent(content.0.clone()))
                        }
                    }),
            )
            .collect()
    }

    /// Returns whether `node_id` belongs to the committee responsible for the
    /// given request, evaluated at the registry version pinned in the request
    /// context.
    ///
    /// For [`Replication::FullyReplicated`] the committee is the full set of
    /// subnet nodes at `context.registry_version`. For
    /// [`Replication::NonReplicated`]/[`Replication::Flexible`] the authorized
    /// signers are pinned in the context, so [`Replication::is_authorized_signer`]
    /// suffices.
    ///
    /// Returns `Err` only when the committee lookup fails.
    fn node_belongs_to_request_committee(
        &self,
        context: &CanisterHttpRequestContext,
        node_id: &NodeId,
    ) -> Result<bool, MembershipError> {
        match &context.replication {
            Replication::FullyReplicated => self
                .membership
                .node_belongs_to_canister_http_committee(context.registry_version, node_id)
                .inspect_err(|e| {
                    warn!(
                        every_n_seconds => 10,
                        self.log,
                        "Unable to check HTTP committee membership at registry version {}, {:?}",
                        context.registry_version,
                        e
                    );
                    self.metrics
                        .observe_pool_manager_error("committee_membership_lookup_failed");
                }),
            Replication::NonReplicated(delegated_node_id) => Ok(node_id == delegated_node_id),
            Replication::Flexible { committee, .. } => Ok(committee.contains(node_id)),
        }
    }

    /// Inform the HttpAdapterShim of any new requests that must be made.
    fn make_new_requests(
        &self,
        state: &ReplicatedState,
        canister_http_pool: &dyn CanisterHttpPool,
    ) {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["make_new_requests"])
            .start_timer();

        let http_requests = &state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts;

        self.metrics
            .in_flight_requests
            .set(http_requests.len().try_into().unwrap());

        let request_ids_in_pool: BTreeSet<_> = canister_http_pool
            .get_validated_shares()
            .filter_map(|share| {
                if share.signature.signer == self.replica_config.node_id {
                    Some(share.content.id())
                } else {
                    None
                }
            })
            .collect();

        let request_ids_already_made: BTreeSet<_> = request_ids_in_pool
            .union(&self.requested_id_cache.borrow())
            .cloned()
            .collect();

        let socks_proxy_addrs = self.socks_proxy.addrs();

        for (id, context) in http_requests {
            // Only make a request if this node belongs to the request's committee
            if !self
                .node_belongs_to_request_committee(context, &self.replica_config.node_id)
                .unwrap_or(false)
            {
                continue;
            }

            if !request_ids_already_made.contains(id) {
                if let Err(err) = self
                    .http_adapter_shim
                    .lock()
                    .unwrap()
                    .send(CanisterHttpRequest {
                        id: *id,
                        context: context.clone(),
                        socks_proxy_addrs: socks_proxy_addrs.clone(),
                    })
                {
                    warn!(
                        self.log,
                        "Failed to add canister http request to queue {:?}", err
                    );
                    // The id is not cached, so the request is retried next round.
                    self.metrics.observe_pool_manager_error(match err {
                        SendError::Full(_) => "adapter_queue_full",
                        SendError::BrokenConnection => "adapter_connection_broken",
                    });
                } else {
                    self.requested_id_cache.borrow_mut().insert(*id);
                    self.metrics
                        .observe_pool_manager_event("request_sent_to_adapter");
                }
            }
        }
    }

    /// Whether the response of a share is of use to our peers: only if they cannot
    /// produce it themselves, and only until the outcall has been answered.
    fn response_visibility(replication: &Replication, is_delivered: bool) -> ResponseVisibility {
        match (replication, is_delivered) {
            (Replication::NonReplicated(_) | Replication::Flexible { .. }, false) => {
                ResponseVisibility::Publish
            }
            (Replication::FullyReplicated, _) | (_, true) => ResponseVisibility::Withhold,
        }
    }

    /// Create any shares that should be made from responses provided by the
    /// HttpAdapterShim.
    fn create_shares_from_responses(&self, state: &ReplicatedState) -> CanisterHttpChangeSet {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["create_shares_from_responses"])
            .start_timer();
        let mut change_set = Vec::new();

        let subnet_call_context_manager = &state.metadata.subnet_call_context_manager;
        let active_contexts = &subnet_call_context_manager.canister_http_request_contexts;
        let delivered_contexts =
            &subnet_call_context_manager.delivered_canister_http_request_contexts;

        loop {
            match self.http_adapter_shim.lock().unwrap().try_receive() {
                Err(TryReceiveError::Empty) => break,
                Ok((response, payment_receipt)) => {
                    self.metrics
                        .observe_pool_manager_event("adapter_response_received");
                    // Drop the response if its context is no longer present in the replicated state.
                    // We continue gossiping a share (though not the response itself) even if a
                    // response to the context has already been delivered, in order to report the
                    // amount of cycles spent.
                    let (context, is_delivered) = match active_contexts.get(&response.id) {
                        Some(context) => (context, false),
                        None => match delivered_contexts.get(&response.id) {
                            Some(context) => {
                                // Consensus already answered this request; we only sign a
                                // share to report the cycles we spent on it.
                                self.metrics
                                    .observe_pool_manager_event("response_for_delivered_context");
                                (context, true)
                            }
                            None => {
                                warn!(
                                    self.log,
                                    "Dropping http response for request ID {}: \
                                     corresponding context is no longer in the replicated state.",
                                    response.id,
                                );
                                self.metrics.observe_pool_manager_event(
                                    "response_dropped_context_timed_out",
                                );
                                self.requested_id_cache.borrow_mut().remove(&response.id);
                                continue;
                            }
                        },
                    };

                    let receipt_share = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: response.id,
                            content_hash: ic_types::crypto::crypto_hash(&response),
                            content_size: response.content.count_bytes() as u32,
                            is_reject: response.content.is_reject(),
                            replica_version: self.replica_config.replica_version().clone(),
                        },
                        payment_receipt,
                    };

                    if let Err(err) = check_content_size_within_limit(
                        &receipt_share.metadata,
                        response.id,
                        context,
                    ) {
                        warn!(
                            self.log,
                            "Refusing to sign our own oversized response: {err:?}"
                        );
                        // Our own adapter produced a response no honest replica could
                        // have produced, so no peer would accept a share for it.
                        self.metrics
                            .observe_pool_manager_error("own_response_too_large");
                        continue;
                    }

                    let signature = if let Ok(signature) = self
                        .crypto
                        .sign(
                            &receipt_share,
                            self.replica_config.node_id,
                            context.registry_version,
                        )
                        .map_err(|err| {
                            error!(self.log, "Failed to sign http response {}", err);
                            self.metrics.observe_pool_manager_error("sign_share_failed");
                        }) {
                        signature
                    } else {
                        continue;
                    };
                    let share = Signed {
                        content: receipt_share,
                        signature,
                    };
                    self.requested_id_cache.borrow_mut().remove(&response.id);
                    self.metrics.shares_signed.inc();

                    change_set.push(CanisterHttpChangeAction::AddToValidated(
                        share,
                        response,
                        Self::response_visibility(&context.replication, is_delivered),
                    ));
                }
            }
        }
        change_set
    }

    /// Validate any shares found in the unvalidated section of the canister http pool.
    fn validate_shares(
        &self,
        state: &ReplicatedState,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["validate_shares"])
            .start_timer();

        let subnet_call_context_manager = &state.metadata.subnet_call_context_manager;
        let active_contexts = &subnet_call_context_manager.canister_http_request_contexts;
        let delivered_contexts =
            &subnet_call_context_manager.delivered_canister_http_request_contexts;
        let next_callback_id = subnet_call_context_manager.next_callback_id();

        let key_from_share =
            |share: &CanisterHttpResponseShare| (share.signature.signer, share.content.id());

        let mut existing_signed_requests: HashSet<_> = canister_http_pool
            .get_validated_shares()
            .map(key_from_share)
            .collect();

        canister_http_pool
            .get_unvalidated_artifacts()
            .filter(|artifact| artifact.share.content.id() < next_callback_id)
            .filter_map(|artifact| {
                let share = &artifact.share;

                // Reject shares from different replica versions
                if share.content.replica_version() != self.replica_config.replica_version() {
                    self.metrics
                        .observe_pool_manager_event("share_dropped_unknown_version");
                    return Some(CanisterHttpChangeAction::RemoveUnvalidated(share.clone()));
                }

                if existing_signed_requests.contains(&key_from_share(share)) {
                    return Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        "Redundant share".into(),
                    ));
                }

                // Whether the request has already been responded to decides whether the
                // share may come without a response (see below), so remember which of the
                // two collections the context was found in.
                let (context, is_delivered) = match active_contexts.get(&share.content.id()) {
                    Some(context) => (context, false),
                    None => match delivered_contexts.get(&share.content.id()) {
                        Some(context) => (context, true),
                        None => {
                            self.metrics
                                .observe_pool_manager_event("share_dropped_unknown_context");
                            return Some(CanisterHttpChangeAction::RemoveUnvalidated(
                                share.clone(),
                            ));
                        }
                    },
                };

                // Invalidate shares whose claimed spent cycles exceed what a
                // single replica is allowed to consume.
                if let Err(err) = check_spent_within_limit(&share.content.payment_receipt, context)
                {
                    return Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        format!("{err:?}"),
                    ));
                }

                // Invalidate shares claiming a larger response than an honest replica could have
                // produced: a success exceeding `max_response_bytes`, or a reject exceeding the
                // 1KB an error message is truncated to.
                if let Err(err) = check_content_size_within_limit(
                    &share.content.metadata,
                    share.content.id(),
                    context,
                ) {
                    return Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        format!("{err:?}"),
                    ));
                }

                match &context.replication {
                    Replication::FullyReplicated => {
                        if artifact.response.is_some() {
                            return Some(CanisterHttpChangeAction::HandleInvalid(
                                share.clone(),
                                "Artifact should not contain response".to_string(),
                            ));
                        }
                    }
                    Replication::NonReplicated(_) | Replication::Flexible { .. } => {
                        match &artifact.response {
                            Some(response) => {
                                if response.id != share.content.id() {
                                    return Some(CanisterHttpChangeAction::HandleInvalid(
                                        share.clone(),
                                        format!(
                                            "Response is for request ID {} rather than the share's {}",
                                            response.id,
                                            share.content.id(),
                                        ),
                                    ));
                                }

                                if share.content.content_hash()
                                    != &ic_types::crypto::crypto_hash(response)
                                {
                                    return Some(CanisterHttpChangeAction::HandleInvalid(
                                        share.clone(),
                                        "Content hash does not match the response".to_string(),
                                    ));
                                }

                                if share.content.content_size()
                                    != response.content.count_bytes() as u32
                                {
                                    return Some(CanisterHttpChangeAction::HandleInvalid(
                                        share.clone(),
                                        "Content size does not match the response".to_string(),
                                    ));
                                }

                                if share.content.is_reject() != response.content.is_reject() {
                                    return Some(CanisterHttpChangeAction::HandleInvalid(
                                        share.clone(),
                                        "is_reject does not match the response content".to_string(),
                                    ));
                                }
                            }
                            // The request has already been answered, so the response is of no
                            // use to anyone and is not gossiped along with the share.
                            None if is_delivered => {}
                            // The peer signed this share when it already saw the request as
                            // answered, while our own latest state still shows it as awaiting a
                            // response. Defer until our own state catches up.
                            None => {
                                self.metrics
                                    .observe_pool_manager_event("share_deferred_pending_delivery");
                                return None;
                            }
                        }
                    }
                }

                let node_is_in_committee = self
                    .node_belongs_to_request_committee(context, &share.signature.signer)
                    .ok()?;
                if !node_is_in_committee {
                    return Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        "Share signed by node not in the request's committee".to_string(),
                    ));
                }
                // TODO: more precise error handling
                if let Err(err) = self.crypto.verify(share, context.registry_version) {
                    error!(self.log, "Unable to verify signature of share, {}", err);

                    self.metrics.shares_marked_invalid.inc();
                    Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        format!("Unable to verify signature of share, {err}"),
                    ))
                } else {
                    // Update the set of existing signed requests.
                    existing_signed_requests.insert(key_from_share(share));
                    self.metrics.shares_validated.inc();
                    // The response of an already answered request is dropped rather than
                    // passed on to peers that pull the artifact.
                    Some(CanisterHttpChangeAction::MoveToValidated(
                        share.clone(),
                        Self::response_visibility(&context.replication, is_delivered),
                    ))
                }
            })
            .collect()
    }

    fn generate_change_set(
        &self,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["generate_change_set"])
            .start_timer();
        let mut change_set = Vec::new();
        let state = self.latest_state();

        // Whenever we have artifacts to purge, we insert the purge change actions before everything
        // else, to avoid having in the validated pool artifacts belonging to different epochs and
        // hence preserving the expected maximal number of artifacts in the pool.
        change_set.extend(self.purge_shares_of_processed_requests(&state, canister_http_pool));

        // Make any requests that need to be made and create shares from responses
        // that are now available.
        self.make_new_requests(&state, canister_http_pool);
        change_set.extend(self.create_shares_from_responses(&state));

        // Attempt to validate unvalidated shares
        change_set.extend(self.validate_shares(&state, canister_http_pool));

        self.metrics
            .in_client_requests
            .set(self.requested_id_cache.borrow().len().try_into().unwrap());

        change_set
    }

    /// The callback ids of all requests whose artifacts are still of use: those
    /// still awaiting a response, plus those already responded to but still awaiting
    /// the [asynchronous receipts](ic_types::batch::CanisterHttpPayload::async_receipts)
    /// of the replicas that did not contribute to the response.
    fn known_callback_ids(state: &ReplicatedState) -> BTreeSet<CallbackId> {
        let subnet_call_context_manager = &state.metadata.subnet_call_context_manager;
        subnet_call_context_manager
            .canister_http_request_contexts
            .keys()
            .chain(
                subnet_call_context_manager
                    .delivered_canister_http_request_contexts
                    .keys(),
            )
            .copied()
            .collect()
    }

    fn latest_state(&self) -> Arc<ReplicatedState> {
        self.state_reader.get_latest_state().get_ref().clone()
    }
}

impl<T: CanisterHttpPool> PoolMutationsProducer<T> for CanisterHttpPoolManagerImpl {
    type Mutations = CanisterHttpChangeSet;

    fn on_state_change(&self, canister_http_pool: &T) -> CanisterHttpChangeSet {
        if let Ok(subnet_features) = self.registry_client.get_features(
            self.replica_config.subnet_id,
            self.registry_client.get_latest_version(),
        ) && subnet_features.unwrap_or_default().http_requests
        {
            return self.generate_change_set(canister_http_pool);
        }
        vec![]
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use assert_matches::assert_matches;
    use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
    use ic_consensus_mocks::{Dependencies, DependenciesBuilder};
    use ic_consensus_utils::crypto::SignVerify;
    use ic_error_types::RejectCode;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_interfaces_state_manager::Labeled;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::SubnetCallContext;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_metrics::{fetch_int_counter_vec, metric_vec};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id, test_replica_version};
    use ic_types::CountBytes;
    use ic_types::ReplicaVersion;
    use ic_types::crypto::crypto_hash;
    use ic_types::{
        Height, NumBytes, NumberOfNodes, RegistryVersion,
        crypto::{CryptoHash, CryptoHashOf},
        messages::CallbackId,
        time::UNIX_EPOCH,
    };
    use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
    use mockall::predicate::*;
    use mockall::*;
    use std::{collections::BTreeMap, str::FromStr};

    mock! {
        pub NonBlockingChannel<Request: 'static> {
        }

        impl<Request> NonBlockingChannel<Request> for NonBlockingChannel<Request> {
            type Response = (CanisterHttpResponse, CanisterHttpPaymentReceipt);

            fn send(&self, request: Request) -> Result<(), SendError<Request>>;
            fn try_receive(
                &mut self,
            ) -> Result<(CanisterHttpResponse, CanisterHttpPaymentReceipt), TryReceiveError>;
        }
    }

    fn state_with_pending_http_calls(
        http_calls: BTreeMap<CallbackId, CanisterHttpRequestContext>,
    ) -> ReplicatedState {
        // Add some pending http calls
        let mut replicated_state = ReplicatedState::new(subnet_test_id(0), SubnetType::System);
        // This will increase the next_call_id to 1
        if let Some(val) = http_calls.values().next() {
            replicated_state
                .metadata
                .subnet_call_context_manager
                .push_context(SubnetCallContext::CanisterHttpRequest(val.clone()));
        }
        replicated_state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts = http_calls;
        replicated_state
    }

    /// A state whose HTTP outcall contexts have all been responded to already, i.e.
    /// that only keeps them around for their asynchronous receipts.
    fn state_with_delivered_http_calls(
        delivered: BTreeMap<CallbackId, CanisterHttpRequestContext>,
    ) -> ReplicatedState {
        let mut replicated_state = ReplicatedState::new(subnet_test_id(0), SubnetType::System);
        let contexts = &mut replicated_state.metadata.subnet_call_context_manager;
        // Hand out callback ids up to the largest delivered one, so that shares for
        // them are not mistaken for shares belonging to a future state. Pushing a
        // context is the only way to advance the private `next_callback_id`, so the
        // contexts it parks in the active collection are cleared out again below.
        if let Some((max_id, context)) = delivered.iter().next_back() {
            for _ in 0..=max_id.get() {
                contexts.push_context(SubnetCallContext::CanisterHttpRequest(context.clone()));
            }
        }
        contexts.canister_http_request_contexts.clear();
        contexts.delivered_canister_http_request_contexts = delivered;
        replicated_state
    }

    /// The canister that makes the outcalls in these tests.
    fn requester() -> ic_types::CanisterId {
        ic_types::CanisterId::from(0)
    }

    fn empty_canister_http_response(id: u64) -> CanisterHttpResponse {
        CanisterHttpResponse {
            id: CallbackId::from(id),
            content: CanisterHttpResponseContent::Success(Vec::new()),
        }
    }

    fn test_request_context(
        replication: Replication,
        pricing_version: PricingVersion,
        max_response_bytes: Option<NumBytes>,
    ) -> CanisterHttpRequestContext {
        CanisterHttpRequestContext {
            request: ic_test_utilities_types::messages::RequestBuilder::new()
                .sender(requester())
                .build(),
            url: "".to_string(),
            max_response_bytes,
            headers: vec![],
            body: None,
            http_method: CanisterHttpMethod::GET,
            transform: None,
            time: ic_types::Time::from_nanos_since_unix_epoch(10),
            replication,
            pricing_version,
            refund_status: RefundStatus::default(),
            registry_version: RegistryVersion::from(1),
            subnet_size: NumberOfNodes::from(13),
            cost_schedule: CanisterCyclesCostSchedule::Normal,
        }
    }

    #[test]
    pub fn test_validation_of_shares_above_known_requests() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::Legacy,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request,
                        )]))),
                    ));

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                // Try to insert a share for request id 1 (while the next expected one is the
                // default value 0).
                {
                    let response_metadata = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: CallbackId::from(1),
                            content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                            content_size: 0,
                            is_reject: false,
                            replica_version: replica_config.replica_version().clone(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };

                    let signature = crypto
                        .sign(
                            &response_metadata,
                            replica_config.node_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap();

                    let share = Signed {
                        content: response_metadata.clone(),
                        signature,
                    };

                    let artifact = CanisterHttpResponseArtifact {
                        share,
                        response: None,
                    };

                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: artifact,
                        peer_id: replica_config.node_id,
                        timestamp: UNIX_EPOCH,
                    });
                }

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // Make sure the changes are empty (share was filtered out)
                assert!(changes.is_empty());
            })
        });
    }

    #[test]
    fn test_invalidation_of_invalid_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::Legacy,
                    None,
                );

                // NOTE: We need at least some context in the state, otherwise next_callback_id will be 0 and no
                // artifacts can have a smaller callback_id and be valid
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request,
                        )]))),
                    ));

                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                        content_size: 0,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                let signature = crypto
                    .sign(
                        &response_metadata,
                        replica_config.node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();

                let mut share = Signed {
                    content: response_metadata.clone(),
                    signature,
                };

                // add a share (plus content) to the validated pool
                canister_http_pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
                    share.clone(),
                    empty_canister_http_response(7),
                    ResponseVisibility::Withhold,
                )]);

                // add an unvalidated copy of the share, that has an outdated version instead
                share.content.metadata.replica_version =
                    ReplicaVersion::from_str("outdated_version").unwrap();

                let artifact = CanisterHttpResponseArtifact {
                    share,
                    response: None,
                };

                canister_http_pool.insert(UnvalidatedArtifact {
                    message: artifact,
                    peer_id: replica_config.node_id,
                    timestamp: UNIX_EPOCH,
                });

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                assert_matches!(&changes[0], CanisterHttpChangeAction::RemoveUnvalidated(_));
            })
        });
    }

    #[test]
    fn test_removal_of_wrong_version_share_without_existing_validated_share() {
        // A share signed under a different replica version must be removed from
        // the unvalidated pool even when no share for the same (signer,
        // callback) is present in the validated pool yet.
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::Legacy,
                    None,
                );

                // A context must be present so that `next_callback_id` is 1 and
                // the share for callback 0 is considered (id < next_callback_id).
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request,
                        )]))),
                    ));

                // A share from a committee member with a valid signature that
                // would otherwise be validated, but which carries an outdated
                // replica version.
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                        content_size: 0,
                        is_reject: false,
                        replica_version: ReplicaVersion::from_str("outdated_version").unwrap(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let signature = crypto
                    .sign(
                        &response_metadata,
                        replica_config.node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();

                let share = Signed {
                    content: response_metadata,
                    signature,
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                // Note: the validated pool is intentionally left empty, so the
                // (signer, callback) slot is free.
                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: None,
                    },
                    peer_id: replica_config.node_id,
                    timestamp: UNIX_EPOCH,
                });

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let metrics_registry = MetricsRegistry::new();
                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    metrics_registry.clone(),
                    log,
                );

                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // The share is dropped silently (removed, not marked invalid).
                assert_eq!(changes.len(), 1);
                assert_matches!(&changes[0], CanisterHttpChangeAction::RemoveUnvalidated(_));
                // Dropping it is expected during an upgrade, so it is not an error.
                assert_eq!(
                    metric_vec(&[(&[("type", "share_dropped_unknown_version")], 1)]),
                    fetch_int_counter_vec(&metrics_registry, "canister_http_pool_manager_events")
                );
                assert!(
                    fetch_int_counter_vec(&metrics_registry, "canister_http_pool_manager_errors")
                        .is_empty()
                );
            })
        });
    }

    #[test]
    pub fn test_invalidation_of_redundant_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::Legacy,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request,
                        )]))),
                    ));

                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                        content_size: 0,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                // Insert the first share as validated.
                {
                    let signature = crypto
                        .sign(
                            &response_metadata,
                            replica_config.node_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap();

                    let share = Signed {
                        content: response_metadata.clone(),
                        signature,
                    };

                    let content = empty_canister_http_response(7);
                    canister_http_pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
                        share,
                        content,
                        ResponseVisibility::Withhold,
                    )]);
                }

                // Insert the second share as unvalidated.
                {
                    let signature = crypto
                        .sign(
                            &response_metadata,
                            replica_config.node_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap();

                    let share = Signed {
                        content: response_metadata.clone(),
                        signature,
                    };

                    let artifact = CanisterHttpResponseArtifact {
                        share,
                        response: None,
                    };

                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: artifact,
                        peer_id: replica_config.node_id,
                        timestamp: UNIX_EPOCH,
                    });
                }

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let metrics_registry = MetricsRegistry::new();
                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    metrics_registry.clone(),
                    log,
                );

                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // Make sure the second share is sorted out as invalid, for the right reason.
                if let CanisterHttpChangeAction::HandleInvalid(_, err) = &changes[0] {
                    assert_eq!(err, "Redundant share");
                } else {
                    panic!("unexpected change action");
                }
            })
        });
    }

    #[test]
    fn test_non_replicated_share_validation_logic() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let delegated_node_id = ic_test_utilities_types::ids::node_test_id(1);

                let request = test_request_context(
                    Replication::NonReplicated(delegated_node_id),
                    PricingVersion::Legacy,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request,
                        )]))),
                    ));

                let response = empty_canister_http_response(0);
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: ic_types::crypto::crypto_hash(&response),
                        content_size: response.content.count_bytes() as u32,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let signature = crypto
                    .sign(
                        &response_metadata,
                        delegated_node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();

                let share = Signed {
                    content: response_metadata.clone(),
                    signature,
                };

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager.clone(),
                    shim.clone(),
                    crypto.clone(),
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log.clone(),
                );

                // TEST 1: Non-replicated request artifact has a mismatched content hash.
                // It should be marked as invalid.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let mut bad_share = share.clone();
                    bad_share.content.metadata.content_hash =
                        CryptoHashOf::new(CryptoHash(vec![1, 2, 3]));

                    let artifact_with_mismatched_hash = CanisterHttpResponseArtifact {
                        share: bad_share,
                        response: Some(response),
                    };
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: artifact_with_mismatched_hash,
                        peer_id: delegated_node_id,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason) if reason == "Content hash does not match the response"
                    );
                }

                // TEST 2: Non-replicated request artifact has a mismatched content size.
                // It should be marked as invalid.
                {
                    let response = empty_canister_http_response(0);
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let mut bad_share = share.clone();
                    bad_share.content.metadata.content_size =
                        bad_share.content.metadata.content_size.wrapping_add(1);

                    let artifact_with_mismatched_size = CanisterHttpResponseArtifact {
                        share: bad_share,
                        response: Some(response),
                    };
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: artifact_with_mismatched_size,
                        peer_id: delegated_node_id,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason) if reason == "Content size does not match the response"
                    );
                }

                // TEST 3: Non-replicated request artifact has a mismatched is_reject flag.
                // It should be marked as invalid.
                {
                    let response = empty_canister_http_response(0);
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let mut bad_share = share.clone();
                    bad_share.content.metadata.is_reject = !bad_share.content.metadata.is_reject;

                    let artifact_with_mismatched_is_reject = CanisterHttpResponseArtifact {
                        share: bad_share,
                        response: Some(response),
                    };
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: artifact_with_mismatched_is_reject,
                        peer_id: delegated_node_id,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason) if reason == "is_reject does not match the response content"
                    );
                }
            })
        });
    }

    #[test]
    fn test_non_replicated_share_from_wrong_signer_is_invalid() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                // 1. SETUP: Create dependencies for a subnet with at least 3 nodes.
                let Dependencies {
                    pool,
                    replica_config, // Our node, ID 0
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                // Define the delegated node and a different, incorrect signer.
                let delegated_node_id = ic_test_utilities_types::ids::node_test_id(1);
                let wrong_signer_id = ic_test_utilities_types::ids::node_test_id(2);
                let callback_id = CallbackId::from(0);

                // 2. CONTEXT: The request is explicitly delegated to `delegated_node_id`.
                let request_context = test_request_context(
                    Replication::NonReplicated(delegated_node_id),
                    PricingVersion::Legacy,
                    None,
                );
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            request_context,
                        )]))),
                    ));

                // 3. MALICIOUS ARTIFACT: Create a share that is signed by the `wrong_signer_id`.
                let response = empty_canister_http_response(callback_id.get());
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: callback_id,
                        content_hash: ic_types::crypto::crypto_hash(&response),
                        content_size: response.content.count_bytes() as u32,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };
                let share = Signed {
                    content: response_metadata.clone(),
                    // The signature is created by the WRONG node.
                    signature: crypto
                        .sign(
                            &response_metadata,
                            wrong_signer_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap(),
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: Some(response),
                    },
                    peer_id: wrong_signer_id, // The artifact comes from the wrong signer.
                    timestamp: UNIX_EPOCH,
                });

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // 4. ACTION: Our replica attempts to validate the artifact.
                let change_set =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // 5. ASSERTION: The artifact must be invalidated with the specific reason.
                assert_eq!(change_set.len(), 1, "Expected exactly one change action");
                assert_matches!(
                    &change_set[0],
                    CanisterHttpChangeAction::HandleInvalid(_, reason) => {
                        assert_eq!(reason, "Share signed by node not in the request's committee");
                    }
                );
            })
        });
    }

    #[test]
    fn test_fully_replicated_share_with_response_is_invalid() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                // This request is fully replicated across the committee.
                let request = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::Legacy,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request,
                        )]))),
                    ));

                let response = empty_canister_http_response(0);
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: ic_types::crypto::crypto_hash(&response),
                        content_size: response.content.count_bytes() as u32,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let signature = crypto
                    .sign(
                        &response_metadata,
                        replica_config.node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();

                let share = Signed {
                    content: response_metadata.clone(),
                    signature,
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                // Create an artifact that incorrectly includes a response for a fully replicated request.
                let artifact_with_response = CanisterHttpResponseArtifact {
                    share,
                    response: Some(response), // This should NOT be here for a fully replicated request
                };

                canister_http_pool.insert(UnvalidatedArtifact {
                    message: artifact_with_response,
                    peer_id: replica_config.node_id,
                    timestamp: UNIX_EPOCH,
                });

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // The change action should be HandleInvalid because a fully replicated request's
                // artifact must not contain a response in the unvalidated pool.
                assert_matches!(
                    &changes[0],
                    CanisterHttpChangeAction::HandleInvalid(_, reason) if reason == "Artifact should not contain response"
                );
            })
        });
    }

    #[test]
    fn test_non_replicated_share_response_size_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let delegated_node_id = ic_test_utilities_types::ids::node_test_id(1);
                let max_response_bytes = NumBytes::from(2000);

                // 1. Set up a state context with a specific max_response_bytes limit.
                let request_context = test_request_context(
                    Replication::NonReplicated(delegated_node_id),
                    PricingVersion::Legacy,
                    Some(max_response_bytes),
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request_context,
                        )]))),
                    ));

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager.clone(),
                    shim,
                    crypto.clone(),
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // SCENARIO A: Response size is LARGER than the limit.
                // It should be marked as invalid.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    // Create a response with content that is one byte too large,
                    // accounting for the Candid overhead.
                    let oversized_len =
                        (max_response_bytes.get() + CANDID_OVERHEAD_RESERVE_BYTES + 1) as usize;
                    let response_body_too_large = vec![0; oversized_len];
                    let response = CanisterHttpResponse {
                        id: CallbackId::from(0),
                        content: CanisterHttpResponseContent::Success(response_body_too_large),
                    };

                    let response_metadata = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: CallbackId::from(0),
                            content_hash: ic_types::crypto::crypto_hash(&response),
                            content_size: response.content.count_bytes() as u32,
                            is_reject: false,
                            replica_version: replica_config.replica_version().clone(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };
                    let share = Signed {
                        content: response_metadata.clone(),
                        signature: crypto
                            .sign(
                                &response_metadata,
                                delegated_node_id,
                                RegistryVersion::from(1),
                            )
                            .unwrap(),
                    };
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share,
                            response: Some(response),
                        },
                        peer_id: delegated_node_id,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    let expected_err = format!(
                        "{:?}",
                        InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                            callback_id: CallbackId::from(0),
                            content_size: oversized_len as u32,
                            limit: max_response_bytes.get() + CANDID_OVERHEAD_RESERVE_BYTES,
                        }
                    );

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason) if reason == &expected_err
                    );
                }

                // SCENARIO B: Response size is EXACTLY the limit.
                // It should be successfully validated.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    // Create a response with content that is exactly the max size.
                    let response_body_ok = vec![0; max_response_bytes.get() as usize];
                    let response = CanisterHttpResponse {
                        id: CallbackId::from(0),
                        content: CanisterHttpResponseContent::Success(response_body_ok),
                    };

                    let response_metadata = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: CallbackId::from(0),
                            content_hash: ic_types::crypto::crypto_hash(&response),
                            content_size: response.content.count_bytes() as u32,
                            is_reject: false,
                            replica_version: replica_config.replica_version().clone(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };
                    let share = Signed {
                        content: response_metadata.clone(),
                        signature: crypto
                            .sign(
                                &response_metadata,
                                delegated_node_id,
                                RegistryVersion::from(1),
                            )
                            .unwrap(),
                    };
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share,
                            response: Some(response),
                        },
                        peer_id: delegated_node_id,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::MoveToValidated(_, ResponseVisibility::Publish)
                    );
                }
            })
        });
    }

    #[test]
    fn test_reject_message_valid_when_max_response_is_zero() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                // 1. SETUP: Standard dependencies and a mock for the adapter.
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let delegated_node_id = ic_test_utilities_types::ids::node_test_id(1);

                // 2. CONTEXT: Create a request context where max_response_bytes is 0.
                let request_context = test_request_context(
                    Replication::NonReplicated(delegated_node_id),
                    PricingVersion::Legacy,
                    Some(NumBytes::from(0)), // Set to zero
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request_context,
                        )]))),
                    ));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager.clone(),
                    Arc::new(Mutex::new(Box::new(shim_mock))),
                    crypto.clone(),
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // 3. ARTIFACT: Create a Reject response. Its message size is valid
                //    (i.e., less than MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES), so it should pass
                //    validation despite the context's zero-byte limit for success responses.
                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                let response = CanisterHttpResponse {
                    id: CallbackId::from(0),
                    content: CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::SysTransient,
                        message: "A transient error occurred.".to_string(),
                    }),
                };

                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: ic_types::crypto::crypto_hash(&response),
                        content_size: response.content.count_bytes() as u32,
                        is_reject: true,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let share = Signed {
                    content: response_metadata.clone(),
                    signature: crypto
                        .sign(
                            &response_metadata,
                            delegated_node_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap(),
                };

                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: Some(response),
                    },
                    peer_id: delegated_node_id,
                    timestamp: UNIX_EPOCH,
                });

                // 4. VALIDATE: Call validate_shares and check the result.
                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // 5. ASSERT: The artifact should be successfully validated and moved to the validated pool.
                assert_eq!(changes.len(), 1);
                assert_matches!(
                    &changes[0],
                    CanisterHttpChangeAction::MoveToValidated(_, ResponseVisibility::Publish)
                );
            })
        });
    }

    #[test]
    fn test_dishonest_oversized_reject_is_invalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                // 1. SETUP: Standard dependencies.
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                // This is the ID of the dishonest replica sending the artifact
                let delegated_node_id = ic_test_utilities_types::ids::node_test_id(1);
                let callback_id = CallbackId::from(0);

                // 2. CONTEXT: A valid request context must exist for validation to proceed.
                let request_context = test_request_context(
                    Replication::NonReplicated(delegated_node_id),
                    PricingVersion::Legacy,
                    None,
                );
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            request_context,
                        )]))),
                    ));

                // 3. DISHONEST ARTIFACT:
                let oversized_len = MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES + 1;
                let dishonest_response = CanisterHttpResponse {
                    id: callback_id,
                    content: CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::SysFatal,
                        message: "b".repeat(oversized_len),
                    }),
                };

                let dishonest_hash = ic_types::crypto::crypto_hash(&dishonest_response);
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: callback_id,
                        content_hash: dishonest_hash,
                        content_size: dishonest_response.content.count_bytes() as u32,
                        is_reject: true,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };
                let share = Signed {
                    content: response_metadata.clone(),
                    signature: crypto
                        .sign(
                            &response_metadata,
                            delegated_node_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap(),
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: Some(dishonest_response.clone()),
                    },
                    peer_id: delegated_node_id,
                    timestamp: UNIX_EPOCH,
                });

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // 4. ACTION: Our replica attempts to validate the artifact.
                let change_set =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // 5. ASSERTION: The artifact is now correctly invalidated by the content size check.
                assert_eq!(change_set.len(), 1, "Expected exactly one change action");

                let expected_error = format!(
                    "{:?}",
                    InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                        callback_id,
                        content_size: dishonest_response.content.count_bytes() as u32,
                        limit: CanisterHttpReject::count_bytes_from_parts(
                            MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES
                        ) as u64,
                    }
                );
                assert_matches!(
                    &change_set[0],
                    CanisterHttpChangeAction::HandleInvalid(_, reason) => {
                        assert_eq!(reason, &expected_error);
                    }
                );
            })
        });
    }

    #[test]
    fn test_fully_replicated_oversized_share_is_invalidated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();

                let peer_id = node_test_id(1);
                let callback_id = CallbackId::from(0);

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            test_request_context(
                                Replication::FullyReplicated,
                                PricingVersion::Legacy,
                                None,
                            ),
                        )]))),
                    ));

                // One byte more than the largest response the replica could have
                // returned. No body is gossiped alongside, so the claim costs the
                // dishonest peer nothing.
                let limit = MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES;
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: callback_id,
                        content_hash: CryptoHashOf::new(CryptoHash(vec![0xAB; 32])),
                        content_size: limit as u32 + 1,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };
                let share = Signed {
                    content: response_metadata.clone(),
                    signature: crypto
                        .sign(&response_metadata, peer_id, RegistryVersion::from(1))
                        .unwrap(),
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: None,
                    },
                    peer_id,
                    timestamp: UNIX_EPOCH,
                });

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let change_set =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                let expected_error = format!(
                    "{:?}",
                    InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                        callback_id,
                        content_size: (limit + 1) as u32,
                        limit,
                    }
                );
                assert_matches!(
                    &change_set[..],
                    [CanisterHttpChangeAction::HandleInvalid(_, reason)] => {
                        assert_eq!(reason, &expected_error);
                    }
                );
            })
        });
    }

    #[test]
    fn test_oversized_response_is_not_signed() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                const MAX_RESPONSE_BYTES: u64 = 10;

                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                let callback_id = CallbackId::from(0);
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            test_request_context(
                                Replication::FullyReplicated,
                                PricingVersion::Legacy,
                                Some(NumBytes::from(MAX_RESPONSE_BYTES)),
                            ),
                        )]))),
                    ));

                // One byte past the requested maximum plus the Candid reserve.
                let oversized_len =
                    (MAX_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES) as usize + 1;
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                let mut sequence = Sequence::new();
                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .returning(move || {
                        Ok((
                            CanisterHttpResponse {
                                content: CanisterHttpResponseContent::Success(vec![
                                    0;
                                    oversized_len
                                ]),
                                ..empty_canister_http_response(callback_id.get())
                            },
                            CanisterHttpPaymentReceipt::default(),
                        ))
                    })
                    .in_sequence(&mut sequence);
                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .returning(|| Err(TryReceiveError::Empty))
                    .in_sequence(&mut sequence);

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    Arc::new(Mutex::new(Box::new(shim_mock))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );
                pool_manager
                    .requested_id_cache
                    .borrow_mut()
                    .insert(callback_id);

                assert!(
                    pool_manager
                        .create_shares_from_responses(&pool_manager.latest_state())
                        .is_empty(),
                    "an oversized response must not be signed",
                );
                // The request is deliberately *not* re-requested: the adapter would
                // return the same oversized response. The entry is cleaned up once
                // the context leaves the replicated state.
                assert!(
                    pool_manager
                        .requested_id_cache
                        .borrow()
                        .contains(&callback_id)
                );
            })
        });
    }

    #[test]
    fn test_reject_message_is_valid_when_context_limit_is_too_low() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                // This value is intentionally lower than the reject message size.
                const LOW_MAX_RESPONSE_BYTES: u64 = 10;

                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let delegated_node_id = ic_test_utilities_types::ids::node_test_id(1);

                // 1. Set up a state context with a very low max_response_bytes limit.
                let request_context = test_request_context(
                    Replication::NonReplicated(delegated_node_id),
                    PricingVersion::Legacy,
                    Some(NumBytes::from(LOW_MAX_RESPONSE_BYTES)),
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request_context,
                        )]))),
                    ));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager.clone(),
                    Arc::new(Mutex::new(Box::new(shim_mock))),
                    crypto.clone(),
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // 2. Create a reject message that is larger than the low limit, but smaller
                //    than the minimum floor.
                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                let reject_message =
                    "This error message is definitely longer than 10 bytes.".to_string();
                assert!(reject_message.len() as u64 > LOW_MAX_RESPONSE_BYTES);
                assert!(reject_message.len() <= MAXIMUM_CANISTER_HTTP_ERROR_MESSAGE_BYTES);

                let reject_content = CanisterHttpReject {
                    reject_code: RejectCode::SysFatal,
                    message: reject_message,
                };

                let response = CanisterHttpResponse {
                    id: CallbackId::from(0),
                    content: CanisterHttpResponseContent::Reject(reject_content),
                };

                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: ic_types::crypto::crypto_hash(&response),
                        content_size: response.content.count_bytes() as u32,
                        is_reject: true,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let share = Signed {
                    content: response_metadata.clone(),
                    signature: crypto
                        .sign(
                            &response_metadata,
                            delegated_node_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap(),
                };

                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: Some(response),
                    },
                    peer_id: delegated_node_id,
                    timestamp: UNIX_EPOCH,
                });

                // 3. Call validate_shares and assert that the share is considered VALID.
                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                assert_matches!(
                    &changes[0],
                    CanisterHttpChangeAction::MoveToValidated(_, ResponseVisibility::Publish)
                );
            })
        });
    }

    #[test]
    pub fn test_already_created_shares_not_re_requested() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let request = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::Legacy,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(7),
                            request,
                        )]))),
                    ));

                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(7),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                        content_size: 0,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let signature = crypto
                    .sign(
                        &response_metadata,
                        replica_config.node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();

                let content = empty_canister_http_response(7);
                let share = Signed {
                    content: response_metadata,
                    signature,
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                canister_http_pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
                    share,
                    content,
                    ResponseVisibility::Withhold,
                )]);
                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // Because we already have a share in the pool, we should be
                // able to call on_state_change again without send being called.
                // We haven't sent an expectation on send, so this will fail if
                // send is, in fact called.
                pool_manager.generate_change_set(&canister_http_pool);
            })
        });
    }

    #[test]
    pub fn test_create_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                // There are 2 contexts in the replicated state.
                let contexts = (3..5)
                    .map(|i| {
                        (
                            CallbackId::from(i),
                            test_request_context(
                                Replication::FullyReplicated,
                                PricingVersion::Legacy,
                                None,
                            ),
                        )
                    })
                    .collect();

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(contexts)),
                    ));

                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();

                // `make_new_requests` will try to dispatch contexts to the adapter shim.
                // Accept any number of `send` calls and treat them as no-ops.
                #[allow(clippy::result_large_err)]
                shim_mock.expect_send().returning(|_| Ok(()));

                let mut sequence = Sequence::new();
                for i in 3..5 {
                    shim_mock
                        .expect_try_receive()
                        .times(1)
                        .returning(move || {
                            Ok((
                                empty_canister_http_response(i),
                                CanisterHttpPaymentReceipt::default(),
                            ))
                        })
                        .in_sequence(&mut sequence);
                }

                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .returning(|| Err(TryReceiveError::Empty))
                    .in_sequence(&mut sequence);

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );
                let change_set = pool_manager.generate_change_set(&canister_http_pool);
                assert_eq!(change_set.len(), 2);
                for change in &change_set {
                    assert_matches!(change, CanisterHttpChangeAction::AddToValidated(_, _, _));
                }
            });
        });
    }

    /// Verifies that the pool manager drops adapter responses whose corresponding
    /// request context is no longer present in the replicated state (e.g. because
    /// the request has already been answered by enough peers, or has timed out)
    /// instead of signing a useless share.
    #[test]
    pub fn test_response_without_context_is_dropped() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                let stale_callback_id = CallbackId::from(3);
                let active_callback_id = CallbackId::from(4);

                // Only the second callback has a context in the replicated state.
                // The first one models a stale response whose context has already
                // been removed.
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            active_callback_id,
                            test_request_context(
                                Replication::FullyReplicated,
                                PricingVersion::Legacy,
                                None,
                            ),
                        )]))),
                    ));

                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                let mut sequence = Sequence::new();
                for id in [stale_callback_id, active_callback_id] {
                    shim_mock
                        .expect_try_receive()
                        .times(1)
                        .returning(move || {
                            Ok((
                                empty_canister_http_response(id.get()),
                                CanisterHttpPaymentReceipt::default(),
                            ))
                        })
                        .in_sequence(&mut sequence);
                }
                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .returning(|| Err(TryReceiveError::Empty))
                    .in_sequence(&mut sequence);

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // Pre-populate the in-flight tracking with the stale callback id
                // so we can also verify that it gets cleaned up.
                pool_manager
                    .requested_id_cache
                    .borrow_mut()
                    .insert(stale_callback_id);

                let change_set =
                    pool_manager.create_shares_from_responses(&pool_manager.latest_state());

                // Only the response for the active context produces a share; the
                // stale one is dropped.
                assert_eq!(change_set.len(), 1);
                assert_matches!(
                    &change_set[0],
                    CanisterHttpChangeAction::AddToValidated(share, response, ResponseVisibility::Withhold) => {
                        assert_eq!(share.content.id(), active_callback_id);
                        assert_eq!(response.id, active_callback_id);
                    }
                );

                // The in-flight tracking entry for the dropped response is cleared.
                assert!(
                    !pool_manager
                        .requested_id_cache
                        .borrow()
                        .contains(&stale_callback_id),
                    "stale callback id should have been removed from the in-flight cache",
                );
            });
        });
    }

    #[test]
    pub fn test_non_replicated_response_is_gossiped() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                // Delegate the request to this node so it is the authorized signer
                // and creates a share for the injected response.
                let delegated_node_id = replica_config.node_id;
                let callback_id = CallbackId::from(5);

                // 1. Set up the state to contain a non-replicated request context.
                let request_context = test_request_context(
                    Replication::NonReplicated(delegated_node_id),
                    PricingVersion::Legacy,
                    None,
                );
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            request_context,
                        )]))),
                    ));

                // 2. Mock the adapter shim to return a response matching the non-replicated request.
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                let mut sequence = Sequence::new();
                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .returning(move || {
                        Ok((
                            empty_canister_http_response(callback_id.get()),
                            CanisterHttpPaymentReceipt::default(),
                        ))
                    })
                    .in_sequence(&mut sequence);
                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .returning(|| Err(TryReceiveError::Empty))
                    .in_sequence(&mut sequence);

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // 3. Call the function and get the change set.
                let change_set =
                    pool_manager.create_shares_from_responses(&pool_manager.latest_state());

                // 4. Assert that the correct change action for gossiping the response was produced.
                assert_eq!(change_set.len(), 1);

                if let CanisterHttpChangeAction::AddToValidated(
                    share,
                    response,
                    ResponseVisibility::Publish,
                ) = &change_set[0]
                {
                    let expected_response = empty_canister_http_response(callback_id.get());
                    assert_eq!(*response, expected_response);

                    assert_eq!(share.content.id(), callback_id);
                    assert_eq!(
                        share.content.content_hash(),
                        &ic_types::crypto::crypto_hash(&expected_response)
                    );
                    assert_eq!(share.signature.signer, replica_config.node_id);
                } else {
                    panic!("Expected a published response, but got {:?}", change_set[0]);
                }
            });
        });
    }

    #[test]
    pub fn test_submit_requests() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::Legacy,
                    None,
                );

                // Expect times to be called exactly once to check that already
                // requested cache works.
                shim_mock
                    .expect_send()
                    .with(eq(CanisterHttpRequest {
                        id: CallbackId::from(7),
                        context: request.clone(),
                        socks_proxy_addrs: vec![],
                    }))
                    .times(1)
                    .return_const(Ok(()));

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(7),
                            request,
                        )]))),
                    ));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto.clone(),
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );
                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                let change_set = pool_manager.generate_change_set(&canister_http_pool);
                assert_eq!(change_set.len(), 0);

                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(7),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                        content_size: 0,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let signature = crypto
                    .sign(
                        &response_metadata,
                        replica_config.node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();

                let content = empty_canister_http_response(7);
                let share = Signed {
                    content: response_metadata,
                    signature,
                };

                canister_http_pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
                    share,
                    content,
                    ResponseVisibility::Withhold,
                )]);

                // Now that there are shares in the pool, we should be able to
                // call generate_change_set again without send being called.
                pool_manager.generate_change_set(&canister_http_pool);
            });
        });
    }

    #[test]
    fn test_flexible_make_new_requests_committee_check() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                let committee_member_1_self = replica_config.node_id;
                let committee_member_2 = ic_test_utilities_types::ids::node_test_id(1);
                assert_ne!(committee_member_1_self, committee_member_2);

                // Request where our node IS in the committee -- should be sent.
                let callback_id_in_committee = CallbackId::from(0);
                let request_in_committee = test_request_context(
                    Replication::Flexible {
                        committee: BTreeSet::from([committee_member_1_self, committee_member_2]),
                        min_responses: 1,
                        max_responses: 2,
                    },
                    PricingVersion::PayAsYouGo,
                    None,
                );

                // Request where our node is NOT in the committee -- should be skipped.
                let callback_id_not_in_committee = CallbackId::from(1);
                let non_member_1 = ic_test_utilities_types::ids::node_test_id(2);
                let non_member_2 = ic_test_utilities_types::ids::node_test_id(3);
                let request_not_in_committee = test_request_context(
                    Replication::Flexible {
                        committee: BTreeSet::from([non_member_1, non_member_2]),
                        min_responses: 1,
                        max_responses: 2,
                    },
                    PricingVersion::PayAsYouGo,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([
                            (callback_id_in_committee, request_in_committee),
                            (callback_id_not_in_committee, request_not_in_committee),
                        ]))),
                    ));

                // Expect exactly one send call (only the request where we're in the committee).
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));
                shim_mock
                    .expect_send()
                    .withf(move |req: &CanisterHttpRequest| req.id == callback_id_in_committee)
                    .times(1)
                    .return_const(Ok(()));

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                pool_manager.generate_change_set(&canister_http_pool);
                // Mock will panic if send was called for the wrong request or not called for the right one.
            });
        });
    }

    #[test]
    fn test_flexible_share_from_wrong_signer_is_invalid() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                // 1. SETUP: Create dependencies for a subnet with at least 3 nodes.
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                // Define the delegated node and a different, incorrect signer.
                let committee_member = ic_test_utilities_types::ids::node_test_id(1);
                let wrong_signer_id = ic_test_utilities_types::ids::node_test_id(2);
                let callback_id = CallbackId::from(0);

                // 2. CONTEXT: The request is in the committee.
                let request_context = test_request_context(
                    Replication::Flexible {
                        committee: BTreeSet::from([committee_member]),
                        min_responses: 1,
                        max_responses: 1,
                    },
                    PricingVersion::PayAsYouGo,
                    None,
                );
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            request_context,
                        )]))),
                    ));

                // 3. MALICIOUS ARTIFACT: Create a share that is signed by the `wrong_signer_id`.
                let response = empty_canister_http_response(callback_id.get());
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: callback_id,
                        content_hash: crypto_hash(&response),
                        content_size: response.content.count_bytes() as u32,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };
                let share = Signed {
                    content: response_metadata.clone(),
                    signature: crypto
                        .sign(
                            &response_metadata,
                            wrong_signer_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap(),
                };

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: Some(response),
                    },
                    peer_id: wrong_signer_id, // The artifact comes from the wrong signer.
                    timestamp: UNIX_EPOCH,
                });

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // 4. ACTION: Our replica attempts to validate the artifact.
                let change_set =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // 5. ASSERTION: The artifact must be invalidated with the specific reason.
                assert_eq!(change_set.len(), 1);
                assert_matches!(
                    &change_set[0],
                    CanisterHttpChangeAction::HandleInvalid(_, reason) => {
                        assert_eq!(reason, "Share signed by node not in the request's committee");
                    }
                );
            })
        });
    }

    #[test]
    fn test_flexible_share_validation_logic() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();

                let committee_member = replica_config.node_id;
                let callback_id = CallbackId::from(0);

                let request = test_request_context(
                    Replication::Flexible {
                        committee: BTreeSet::from([committee_member]),
                        min_responses: 1,
                        max_responses: 1,
                    },
                    PricingVersion::PayAsYouGo,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            request,
                        )]))),
                    ));

                let response = empty_canister_http_response(callback_id.get());
                let response_metadata = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: callback_id,
                        content_hash: crypto_hash(&response),
                        content_size: response.content.count_bytes() as u32,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                };

                let signature = crypto
                    .sign(
                        &response_metadata,
                        committee_member,
                        RegistryVersion::from(1),
                    )
                    .unwrap();

                let share = Signed {
                    content: response_metadata.clone(),
                    signature,
                };

                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));
                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager.clone(),
                    shim.clone(),
                    crypto.clone(),
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log.clone(),
                );

                // TEST 1: Flexible artifact is missing the response, while the request is
                // still awaiting one -- should be left unvalidated, to be reconsidered once
                // our state shows the request as responded to.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share: share.clone(),
                            response: None,
                        },
                        peer_id: committee_member,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert!(changes.is_empty(), "{changes:?}");
                }

                // TEST 2: Flexible artifact has a mismatched content hash -- should be invalid.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let mut bad_share = share.clone();
                    bad_share.content.metadata.content_hash =
                        CryptoHashOf::new(CryptoHash(vec![1, 2, 3]));

                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share: bad_share,
                            response: Some(response),
                        },
                        peer_id: committee_member,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason)
                        if reason == "Content hash does not match the response"
                    );
                }

                // TEST 3: Flexible artifact has a mismatched content size -- should be invalid.
                {
                    let response = empty_canister_http_response(callback_id.get());
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let mut bad_share = share.clone();
                    bad_share.content.metadata.content_size =
                        bad_share.content.metadata.content_size.wrapping_add(1);

                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share: bad_share,
                            response: Some(response),
                        },
                        peer_id: committee_member,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason)
                        if reason == "Content size does not match the response"
                    );
                }

                // TEST 4: Flexible artifact has a mismatched is_reject flag -- should be invalid.
                {
                    let response = empty_canister_http_response(callback_id.get());
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let mut bad_share = share.clone();
                    bad_share.content.metadata.is_reject = !bad_share.content.metadata.is_reject;

                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share: bad_share,
                            response: Some(response),
                        },
                        peer_id: committee_member,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason)
                        if reason == "is_reject does not match the response content"
                    );
                }

                // TEST 5: the attached response answers a *different* callback than the
                // share it travels with -- should be invalid.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let mut foreign_response = empty_canister_http_response(callback_id.get());
                    foreign_response.id = CallbackId::from(callback_id.get() + 1);

                    let mut bad_share = share.clone();
                    bad_share.content.metadata.content_hash = crypto_hash(&foreign_response);
                    bad_share.signature = crypto
                        .sign(
                            &bad_share.content,
                            committee_member,
                            RegistryVersion::from(1),
                        )
                        .unwrap();

                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share: bad_share,
                            response: Some(foreign_response),
                        },
                        peer_id: committee_member,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason)
                        if reason.starts_with("Response is for request ID")
                    );
                }
            })
        });
    }

    #[test]
    fn test_flexible_share_response_size_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let committee_member = replica_config.node_id; // irrelevant for the test
                let callback_id = CallbackId::from(0);

                // Flexible requests have max_response_bytes: None, so the 2MB hard limit applies.
                let request_context = test_request_context(
                    Replication::Flexible {
                        committee: BTreeSet::from([committee_member]),
                        min_responses: 1,
                        max_responses: 1,
                    },
                    PricingVersion::Legacy,
                    None,
                );

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            request_context,
                        )]))),
                    ));

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager.clone(),
                    shim,
                    crypto.clone(),
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // SCENARIO A: Response exceeds the 2MB hard limit -- should be invalid.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let oversized_len = (MAX_CANISTER_HTTP_RESPONSE_BYTES
                        + CANDID_OVERHEAD_RESERVE_BYTES
                        + 1) as usize;
                    let response = CanisterHttpResponse {
                        id: callback_id,
                        content: CanisterHttpResponseContent::Success(vec![0; oversized_len]),
                    };

                    let response_metadata = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: callback_id,
                            content_hash: ic_types::crypto::crypto_hash(&response),
                            content_size: response.content.count_bytes() as u32,
                            is_reject: false,
                            replica_version: replica_config.replica_version().clone(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };
                    let share = Signed {
                        content: response_metadata.clone(),
                        signature: crypto
                            .sign(
                                &response_metadata,
                                committee_member,
                                RegistryVersion::from(1),
                            )
                            .unwrap(),
                    };
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share,
                            response: Some(response),
                        },
                        peer_id: committee_member,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    let expected_err = format!(
                        "{:?}",
                        InvalidCanisterHttpPayloadReason::ContentSizeExceedsLimit {
                            callback_id,
                            content_size: oversized_len as u32,
                            limit: MAX_CANISTER_HTTP_RESPONSE_BYTES + CANDID_OVERHEAD_RESERVE_BYTES,
                        }
                    );

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::HandleInvalid(_, reason) if reason == &expected_err
                    );
                }

                // SCENARIO B: Response is exactly at the 2MB limit -- should be accepted.
                {
                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                    let response = CanisterHttpResponse {
                        id: callback_id,
                        content: CanisterHttpResponseContent::Success(vec![
                            0;
                            MAX_CANISTER_HTTP_RESPONSE_BYTES
                                as usize
                        ]),
                    };

                    let response_metadata = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: callback_id,
                            content_hash: ic_types::crypto::crypto_hash(&response),
                            content_size: response.content.count_bytes() as u32,
                            is_reject: false,
                            replica_version: replica_config.replica_version().clone(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };
                    let share = Signed {
                        content: response_metadata.clone(),
                        signature: crypto
                            .sign(
                                &response_metadata,
                                committee_member,
                                RegistryVersion::from(1),
                            )
                            .unwrap(),
                    };
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share,
                            response: Some(response),
                        },
                        peer_id: committee_member,
                        timestamp: UNIX_EPOCH,
                    });

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        &changes[0],
                        CanisterHttpChangeAction::MoveToValidated(_, ResponseVisibility::Publish)
                    );
                }
            })
        });
    }

    #[test]
    fn test_flexible_response_is_gossiped() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                let dummy_node_id = replica_config.node_id; // irrelevant for this test
                let callback_id = CallbackId::from(5);

                // 1. Set up the state to contain a flexible request context.
                let request_context = test_request_context(
                    Replication::Flexible {
                        committee: BTreeSet::from([dummy_node_id]),
                        min_responses: 1,
                        max_responses: 1,
                    },
                    PricingVersion::PayAsYouGo,
                    None,
                );
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            callback_id,
                            request_context,
                        )]))),
                    ));

                // 2. Mock the adapter shim to return a response matching the flexible request.
                let empty_response = empty_canister_http_response(callback_id.get());
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                let mut sequence = Sequence::new();
                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .return_const(Ok((
                        empty_response.clone(),
                        CanisterHttpPaymentReceipt::default(),
                    )))
                    .in_sequence(&mut sequence);
                shim_mock
                    .expect_try_receive()
                    .times(1)
                    .return_const(Err(TryReceiveError::Empty))
                    .in_sequence(&mut sequence);

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config.clone(),
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                // 3. Call the function and get the change set.
                let change_set =
                    pool_manager.create_shares_from_responses(&pool_manager.latest_state());

                // 4. Assert that the correct change action for gossiping the response was produced.
                assert_eq!(change_set.len(), 1);
                assert_matches!(
                    &change_set[0],
                    CanisterHttpChangeAction::AddToValidated(share, response, ResponseVisibility::Publish) => {
                        let expected_response = empty_response;
                        assert_eq!(*response, expected_response);
                        assert_eq!(share.content.id(), callback_id);
                        assert_eq!(share.signature.signer, replica_config.node_id);
                        assert_eq!(
                            share.content.content_hash(),
                            &crypto_hash(&expected_response)
                        );
                    }
                );
            });
        });
    }

    #[test]
    fn test_spent_greater_than_replica_allowance_is_invalid() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();

                // Use a context with a small per-replica allowance.
                let request = CanisterHttpRequestContext {
                    refund_status: RefundStatus {
                        refundable_cycles: Cycles::new(1000),
                        per_replica_allowance: Cycles::new(100),
                        refunded_cycles: Cycles::new(0),
                        refunding_nodes: BTreeSet::new(),
                    },
                    ..test_request_context(
                        Replication::FullyReplicated,
                        PricingVersion::Legacy,
                        None,
                    )
                };

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([(
                            CallbackId::from(0),
                            request,
                        )]))),
                    ));

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                // Build a per-replica receipt share whose spent claim is
                // larger than the per-replica allowance.
                let receipt_share = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                        content_size: 0,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt {
                        spent: Cycles::new(200),
                    },
                };
                let signature = crypto
                    .sign(
                        &receipt_share,
                        replica_config.node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();
                let share = Signed {
                    content: receipt_share,
                    signature,
                };

                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: None,
                    },
                    peer_id: replica_config.node_id,
                    timestamp: UNIX_EPOCH,
                });

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                assert_eq!(changes.len(), 1);
                let expected_err = format!(
                    "{:?}",
                    InvalidCanisterHttpPayloadReason::SpentExceedsLimit {
                        spent: Cycles::new(200),
                        limit: Cycles::new(100),
                    }
                );
                assert_matches!(
                    &changes[0],
                    CanisterHttpChangeAction::HandleInvalid(_, reason) if reason == &expected_err
                );
            })
        });
    }

    #[test]
    fn test_spent_greater_than_replica_allowance_is_valid_on_free_subnet() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 5).build();

                // A free subnet grants a zero per-replica allowance (nothing is
                // charged), yet the reported spend is still accumulated for cost
                // accounting and may exceed that allowance. The `Free` cost
                // schedule is pinned in the request context, raising the spend
                // limit to `MAX_HTTP_OUTCALL_SPEND_FREE_SUBNET`.
                let request = CanisterHttpRequestContext {
                    refund_status: RefundStatus {
                        refundable_cycles: Cycles::new(0),
                        per_replica_allowance: Cycles::new(0),
                        refunded_cycles: Cycles::new(0),
                        refunding_nodes: BTreeSet::new(),
                    },
                    cost_schedule: CanisterCyclesCostSchedule::Free,
                    ..test_request_context(
                        Replication::FullyReplicated,
                        PricingVersion::Legacy,
                        None,
                    )
                };

                let state =
                    state_with_pending_http_calls(BTreeMap::from([(CallbackId::from(0), request)]));

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(Height::from(1), Arc::new(state)));

                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());

                // Build a per-replica receipt share whose spent claim exceeds the
                // (zero) per-replica allowance but stays below the free-subnet
                // maximum. On a `Normal` schedule this would be rejected as
                // overspending (see the test above); on a `Free` schedule it must
                // not be.
                let receipt_share = CanisterHttpResponseReceipt {
                    metadata: CanisterHttpResponseMetadata {
                        id: CallbackId::from(0),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                        content_size: 0,
                        is_reject: false,
                        replica_version: replica_config.replica_version().clone(),
                    },
                    payment_receipt: CanisterHttpPaymentReceipt {
                        spent: Cycles::new(200),
                    },
                };
                let signature = crypto
                    .sign(
                        &receipt_share,
                        replica_config.node_id,
                        RegistryVersion::from(1),
                    )
                    .unwrap();
                let share = Signed {
                    content: receipt_share,
                    signature,
                };

                canister_http_pool.insert(UnvalidatedArtifact {
                    message: CanisterHttpResponseArtifact {
                        share,
                        response: None,
                    },
                    peer_id: replica_config.node_id,
                    timestamp: UNIX_EPOCH,
                });

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let changes =
                    pool_manager.validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                // The share must not be invalidated for overspending.
                assert_eq!(changes.len(), 1);
                assert_matches!(
                    &changes[0],
                    CanisterHttpChangeAction::MoveToValidated(_, ResponseVisibility::Withhold),
                    "free-subnet share was wrongly rejected: {:?}",
                    changes[0]
                );
            })
        });
    }

    // ===================================================================
    // Asynchronous receipts
    // ===================================================================

    /// A share for an outcall that has already been responded to is still validated:
    /// it may yet be picked up as an asynchronous receipt. Whether or not a response is
    /// attached at all makes no difference.
    #[test]
    fn test_share_for_delivered_context_is_validated() {
        let signer = node_test_id(0);
        for (replication, attach_response) in [
            // A fully replicated response is never attached to a share.
            (Replication::FullyReplicated, false),
            (Replication::NonReplicated(signer), false),
            (Replication::NonReplicated(signer), true),
            (
                Replication::Flexible {
                    committee: BTreeSet::from([signer]),
                    min_responses: 1,
                    max_responses: 1,
                },
                false,
            ),
            (
                Replication::Flexible {
                    committee: BTreeSet::from([signer]),
                    min_responses: 1,
                    max_responses: 1,
                },
                true,
            ),
        ] {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                with_test_replica_logger(|log| {
                    let Dependencies {
                        pool,
                        replica_config,
                        crypto,
                        state_manager,
                        registry,
                        ..
                    } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                    assert_eq!(replica_config.node_id, signer);

                    let callback_id = CallbackId::from(0);
                    state_manager
                        .get_mut()
                        .expect_get_latest_state()
                        .return_const(Labeled::new(
                            Height::from(1),
                            Arc::new(state_with_delivered_http_calls(BTreeMap::from([(
                                callback_id,
                                test_request_context(
                                    replication.clone(),
                                    PricingVersion::PayAsYouGo,
                                    None,
                                ),
                            )]))),
                        ));

                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                    let response = empty_canister_http_response(callback_id.get());
                    let receipt_share = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: callback_id,
                            content_hash: crypto_hash(&response),
                            content_size: response.content.count_bytes() as u32,
                            is_reject: false,
                            replica_version: test_replica_version(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };
                    let signature = crypto
                        .sign(&receipt_share, signer, RegistryVersion::from(1))
                        .unwrap();
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share: Signed {
                                content: receipt_share,
                                signature,
                            },
                            response: attach_response.then_some(response),
                        },
                        peer_id: signer,
                        timestamp: UNIX_EPOCH,
                    });

                    let pool_manager = CanisterHttpPoolManagerImpl::new(
                        state_manager as Arc<_>,
                        Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                        crypto,
                        pool.get_cache(),
                        replica_config,
                        SubnetType::Application,
                        Arc::clone(&registry) as Arc<_>,
                        MetricsRegistry::new(),
                        log,
                    );

                    let changes = pool_manager
                        .validate_shares(&pool_manager.latest_state(), &canister_http_pool);

                    assert_matches!(
                        changes.as_slice(),
                        [CanisterHttpChangeAction::MoveToValidated(share, visibility)]
                            if share.content.id() == callback_id
                                && *visibility == ResponseVisibility::Withhold,
                        "{replication:?}, response attached: {attach_response}"
                    );
                })
            });
        }
    }

    /// A share that comes without a response while our own latest state still shows
    /// the outcall as awaiting one is deferred.
    #[test]
    fn test_share_without_response_is_deferred_until_its_context_is_delivered() {
        let signer = node_test_id(0);
        for replication in [
            Replication::NonReplicated(signer),
            Replication::Flexible {
                committee: BTreeSet::from([signer]),
                min_responses: 1,
                max_responses: 1,
            },
        ] {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                with_test_replica_logger(|log| {
                    let Dependencies {
                        pool,
                        replica_config,
                        crypto,
                        state_manager,
                        registry,
                        ..
                    } = DependenciesBuilder::new(pool_config.clone(), 5).build();
                    assert_eq!(replica_config.node_id, signer);

                    let callback_id = CallbackId::from(0);
                    let context =
                        test_request_context(replication.clone(), PricingVersion::PayAsYouGo, None);
                    // The same outcall, before and after its response was delivered.
                    let awaiting_response = state_with_pending_http_calls(BTreeMap::from([(
                        callback_id,
                        context.clone(),
                    )]));
                    let responded_to =
                        state_with_delivered_http_calls(BTreeMap::from([(callback_id, context)]));

                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                    let receipt_share = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: callback_id,
                            content_hash: CryptoHashOf::new(CryptoHash(vec![])),
                            content_size: 0,
                            is_reject: false,
                            replica_version: test_replica_version(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };
                    let signature = crypto
                        .sign(&receipt_share, signer, RegistryVersion::from(1))
                        .unwrap();
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: CanisterHttpResponseArtifact {
                            share: Signed {
                                content: receipt_share,
                                signature,
                            },
                            response: None,
                        },
                        peer_id: signer,
                        timestamp: UNIX_EPOCH,
                    });

                    let metrics_registry = MetricsRegistry::new();
                    let pool_manager = CanisterHttpPoolManagerImpl::new(
                        state_manager as Arc<_>,
                        Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                        crypto,
                        pool.get_cache(),
                        replica_config,
                        SubnetType::Application,
                        Arc::clone(&registry) as Arc<_>,
                        metrics_registry.clone(),
                        log,
                    );

                    // While the outcall is still awaiting a response, the share is held
                    // back, but kept: no change action is produced for it.
                    let changes =
                        pool_manager.validate_shares(&awaiting_response, &canister_http_pool);
                    assert!(changes.is_empty(), "{replication:?}: {changes:?}");
                    // Held back again on the next round, and observed again: the event
                    // counts deferrals, not distinct shares.
                    let changes =
                        pool_manager.validate_shares(&awaiting_response, &canister_http_pool);
                    assert!(changes.is_empty(), "{replication:?}: {changes:?}");
                    assert_eq!(
                        metric_vec(&[(&[("type", "share_deferred_pending_delivery")], 2)]),
                        fetch_int_counter_vec(
                            &metrics_registry,
                            "canister_http_pool_manager_events"
                        ),
                        "{replication:?}"
                    );

                    // Once our state has caught up, the same share is validated.
                    let changes = pool_manager.validate_shares(&responded_to, &canister_http_pool);
                    assert_matches!(
                        changes.as_slice(),
                        [CanisterHttpChangeAction::MoveToValidated(share, visibility)]
                            if share.content.id() == callback_id
                                && *visibility == ResponseVisibility::Withhold,
                        "{replication:?}"
                    );
                })
            });
        }
    }

    /// The share of an outcall that has already been responded to is kept for as long
    /// as its delivered context is around, and purged once it is gone. Its response is
    /// dropped right away: it can never be put into a block again. While the outcall is
    /// still awaiting a response, both are kept.
    #[test]
    fn test_shares_of_delivered_context_are_purged_only_once_it_is_gone() {
        /// The state of the outcall whose share and response are in the pool.
        #[derive(Debug)]
        enum Outcall {
            AwaitingResponse,
            Responded,
            Gone,
        }

        for outcall in [Outcall::AwaitingResponse, Outcall::Responded, Outcall::Gone] {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                with_test_replica_logger(|log| {
                    let Dependencies {
                        pool,
                        replica_config,
                        crypto,
                        state_manager,
                        registry,
                        ..
                    } = DependenciesBuilder::new(pool_config.clone(), 5).build();

                    let callback_id = CallbackId::from(0);
                    let context = test_request_context(
                        Replication::FullyReplicated,
                        PricingVersion::PayAsYouGo,
                        None,
                    );
                    let delivered = match outcall {
                        Outcall::Responded => BTreeMap::from([(callback_id, context.clone())]),
                        Outcall::AwaitingResponse | Outcall::Gone => BTreeMap::new(),
                    };
                    let mut state = state_with_delivered_http_calls(delivered);
                    // Whatever state the outcall is in, the callback id must have been
                    // handed out already.
                    state
                        .metadata
                        .subnet_call_context_manager
                        .push_context(SubnetCallContext::CanisterHttpRequest(context.clone()));
                    let contexts = &mut state.metadata.subnet_call_context_manager;
                    contexts.canister_http_request_contexts.clear();
                    if matches!(outcall, Outcall::AwaitingResponse) {
                        contexts
                            .canister_http_request_contexts
                            .insert(callback_id, context);
                    }
                    state_manager
                        .get_mut()
                        .expect_get_latest_state()
                        .return_const(Labeled::new(Height::from(1), Arc::new(state)));

                    let mut canister_http_pool =
                        CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                    let response = empty_canister_http_response(callback_id.get());
                    let receipt_share = CanisterHttpResponseReceipt {
                        metadata: CanisterHttpResponseMetadata {
                            id: callback_id,
                            content_hash: crypto_hash(&response),
                            content_size: response.content.count_bytes() as u32,
                            is_reject: false,
                            replica_version: test_replica_version(),
                        },
                        payment_receipt: CanisterHttpPaymentReceipt::default(),
                    };
                    let signature = crypto
                        .sign(
                            &receipt_share,
                            replica_config.node_id,
                            RegistryVersion::from(1),
                        )
                        .unwrap();
                    canister_http_pool.apply(vec![CanisterHttpChangeAction::AddToValidated(
                        Signed {
                            content: receipt_share,
                            signature,
                        },
                        response,
                        ResponseVisibility::Withhold,
                    )]);

                    let pool_manager = CanisterHttpPoolManagerImpl::new(
                        state_manager as Arc<_>,
                        Arc::new(Mutex::new(Box::new(MockNonBlockingChannel::new()))),
                        crypto,
                        pool.get_cache(),
                        replica_config,
                        SubnetType::Application,
                        Arc::clone(&registry) as Arc<_>,
                        MetricsRegistry::new(),
                        log,
                    );

                    let changes = pool_manager.purge_shares_of_processed_requests(
                        &pool_manager.latest_state(),
                        &canister_http_pool,
                    );

                    match outcall {
                        // Both are still of use.
                        Outcall::AwaitingResponse => {
                            assert!(changes.is_empty(), "{outcall:?}: {changes:?}")
                        }
                        // The response can no longer be put into a block, while the share
                        // is still to be published as an asynchronous receipt.
                        Outcall::Responded => assert_matches!(
                            changes.as_slice(),
                            [CanisterHttpChangeAction::RemoveContent(_)],
                            "{outcall:?}: {changes:?}"
                        ),
                        // Neither is of any use any more.
                        Outcall::Gone => assert_matches!(
                            changes.as_slice(),
                            [
                                CanisterHttpChangeAction::RemoveValidated(_),
                                CanisterHttpChangeAction::RemoveContent(_),
                            ],
                            "{outcall:?}: {changes:?}"
                        ),
                    }
                })
            });
        }
    }

    /// A share is signed even for an outcall that has already been responded to: the
    /// work was done and paid for, so the receipt has to be published for the spend
    /// to be settled asynchronously. The response itself is neither retained nor
    /// gossiped, whatever the replication: it can never make it into a block any more.
    #[test]
    fn test_share_is_created_for_a_delivered_context() {
        for replication in [
            Replication::FullyReplicated,
            Replication::NonReplicated(node_test_id(0)),
            Replication::Flexible {
                committee: BTreeSet::from([node_test_id(0), node_test_id(1)]),
                min_responses: 1,
                max_responses: 2,
            },
        ] {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                with_test_replica_logger(|log| {
                    let Dependencies {
                        pool,
                        replica_config,
                        crypto,
                        state_manager,
                        registry,
                        ..
                    } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                    let callback_id = CallbackId::from(0);
                    state_manager
                        .get_mut()
                        .expect_get_latest_state()
                        .return_const(Labeled::new(
                            Height::from(1),
                            Arc::new(state_with_delivered_http_calls(BTreeMap::from([(
                                callback_id,
                                test_request_context(
                                    replication.clone(),
                                    PricingVersion::PayAsYouGo,
                                    None,
                                ),
                            )]))),
                        ));

                    let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                    let mut sequence = Sequence::new();
                    shim_mock
                        .expect_try_receive()
                        .times(1)
                        .returning(move || {
                            Ok((
                                empty_canister_http_response(callback_id.get()),
                                CanisterHttpPaymentReceipt::default(),
                            ))
                        })
                        .in_sequence(&mut sequence);
                    shim_mock
                        .expect_try_receive()
                        .times(1)
                        .returning(|| Err(TryReceiveError::Empty))
                        .in_sequence(&mut sequence);

                    let pool_manager = CanisterHttpPoolManagerImpl::new(
                        state_manager,
                        Arc::new(Mutex::new(Box::new(shim_mock))),
                        crypto,
                        pool.get_cache(),
                        replica_config,
                        SubnetType::Application,
                        Arc::clone(&registry) as Arc<_>,
                        MetricsRegistry::new(),
                        log,
                    );
                    pool_manager
                        .requested_id_cache
                        .borrow_mut()
                        .insert(callback_id);

                    let change_set =
                        pool_manager.create_shares_from_responses(&pool_manager.latest_state());

                    assert_matches!(
                        change_set.as_slice(),
                        [CanisterHttpChangeAction::AddToValidated(
                            share,
                            _,
                            ResponseVisibility::Withhold,
                        )] if share.content.id() == callback_id,
                        "{replication:?}"
                    );
                    // The request is no longer in flight.
                    assert!(
                        !pool_manager
                            .requested_id_cache
                            .borrow()
                            .contains(&callback_id)
                    );
                });
            });
        }
    }

    /// No *new* request is made to the HTTP adapter for an outcall that has already
    /// been responded to: there is nothing left to do for it, and the allowance of a
    /// replica that never started is refunded in full when the delivered context
    /// times out.
    #[test]
    fn test_no_new_request_is_made_for_a_delivered_context() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    registry,
                    ..
                } = DependenciesBuilder::new(pool_config.clone(), 4).build();

                let context = test_request_context(
                    Replication::FullyReplicated,
                    PricingVersion::PayAsYouGo,
                    None,
                );
                // A state holding one already responded to request and one still
                // awaiting a response, so that the assertions below distinguish the
                // two rather than just observing an idle pool manager.
                let delivered_id = CallbackId::from(0);
                let mut state = state_with_delivered_http_calls(BTreeMap::from([(
                    delivered_id,
                    context.clone(),
                )]));
                let active_id = state
                    .metadata
                    .subnet_call_context_manager
                    .push_context(SubnetCallContext::CanisterHttpRequest(context));
                assert_ne!(active_id, delivered_id);
                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(Height::from(1), Arc::new(state)));

                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                #[allow(clippy::result_large_err)]
                shim_mock
                    .expect_send()
                    .withf(move |request: &CanisterHttpRequest| request.id == active_id)
                    .times(1)
                    .returning(|_| Ok(()));

                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    Arc::new(Mutex::new(Box::new(shim_mock))),
                    crypto,
                    pool.get_cache(),
                    replica_config,
                    SubnetType::Application,
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                pool_manager.make_new_requests(&pool_manager.latest_state(), &canister_http_pool);

                // Only the request that is still awaiting a response was dispatched.
                assert_eq!(
                    *pool_manager.requested_id_cache.borrow(),
                    BTreeSet::from([active_id])
                );
            })
        });
    }
}
