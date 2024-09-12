//! This module defines the [`CanisterHttpPoolManagerImpl`], which is an object
//! responsible for managing the flow of requests from execution to the
//! networking component, and ensuring that the resulting responses are signed
//! and eventually make it into consensus.
use crate::metrics::CanisterHttpPoolManagerMetrics;
use ic_consensus_utils::{
    crypto::ConsensusCrypto, membership::Membership, registry_version_at_height,
};
use ic_interfaces::{
    canister_http::*, consensus_pool::ConsensusPoolCache, p2p::consensus::PoolMutationsProducer,
};
use ic_interfaces_adapter_client::*;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::*;
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    canister_http::*, consensus::HasHeight, crypto::Signed, messages::CallbackId,
    replica_config::ReplicaConfig, Height,
};
use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
    convert::TryInto,
    sync::{Arc, Mutex},
    time::Duration,
};

pub type CanisterHttpAdapterClient =
    Box<dyn NonBlockingChannel<CanisterHttpRequest, Response = CanisterHttpResponse> + Send>;

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
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    membership: Arc<Membership>,
    replica_config: ReplicaConfig,
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
        registry_client: Arc<dyn RegistryClient>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let membership = Arc::new(Membership::new(
            consensus_pool_cache.clone(),
            registry_client.clone(),
            replica_config.subnet_id,
        ));

        Self {
            state_reader,
            http_adapter_shim,
            crypto,
            replica_config,
            membership,
            consensus_pool_cache,
            registry_client,
            metrics: CanisterHttpPoolManagerMetrics::new(&metrics_registry),
            log,
            requested_id_cache: RefCell::new(BTreeSet::new()),
        }
    }

    /// Purge shares of responses for requests that have already been processed.
    fn purge_shares_of_processed_requests(
        &self,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["purge_shares"])
            .start_timer();

        let active_callback_ids = self.active_callback_ids();
        let next_callback_id = self.next_callback_id();

        let ids_to_remove_from_cache: Vec<_> = self
            .requested_id_cache
            .borrow()
            .difference(&active_callback_ids)
            .cloned()
            .collect();

        for callback_id in ids_to_remove_from_cache.iter() {
            self.requested_id_cache.borrow_mut().remove(callback_id);
        }

        canister_http_pool
            .get_validated_shares()
            .filter_map(|share| {
                if active_callback_ids.contains(&share.content.id) {
                    None
                } else {
                    Some(CanisterHttpChangeAction::RemoveValidated(share.clone()))
                }
            })
            .chain(
                canister_http_pool
                    .get_unvalidated_shares()
                    // Only check the unvalidated shares belonging to the requests that we can validate.
                    .filter(|share| share.content.id < next_callback_id)
                    .filter_map(|share| {
                        if active_callback_ids.contains(&share.content.id) {
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
                        if active_callback_ids.contains(&content.1.id) {
                            None
                        } else {
                            Some(CanisterHttpChangeAction::RemoveContent(content.0.clone()))
                        }
                    }),
            )
            .collect()
    }

    /// Inform the HttpAdapterShim of any new requests that must be made.
    fn make_new_requests(&self, canister_http_pool: &dyn CanisterHttpPool) {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["make_new_requests"])
            .start_timer();

        let http_requests = self
            .state_reader
            .get_latest_state()
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .clone();

        self.metrics
            .in_flight_requests
            .set(http_requests.len().try_into().unwrap());

        let request_ids_in_pool: BTreeSet<_> = canister_http_pool
            .get_validated_shares()
            .filter_map(|share| {
                if share.signature.signer == self.replica_config.node_id {
                    Some(share.content.id)
                } else {
                    None
                }
            })
            .collect();

        let request_ids_already_made: BTreeSet<_> = request_ids_in_pool
            .union(&self.requested_id_cache.borrow())
            .cloned()
            .collect();

        for (id, context) in http_requests {
            if !request_ids_already_made.contains(&id) {
                let timeout = context.time + Duration::from_secs(5 * 60);
                if let Err(err) = self
                    .http_adapter_shim
                    .lock()
                    .unwrap()
                    .send(CanisterHttpRequest {
                        id,
                        timeout,
                        context,
                    })
                {
                    warn!(
                        self.log,
                        "Failed to add canister http request to queue {:?}", err
                    )
                } else {
                    self.requested_id_cache.borrow_mut().insert(id);
                }
            }
        }
    }

    /// Create any shares that should be made from responses provided by the
    /// HttpAdapterShim.
    fn create_shares_from_responses(&self, finalized_height: Height) -> CanisterHttpChangeSet {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["create_shares_from_responses"])
            .start_timer();
        let registry_version = if let Some(registry_version) =
            registry_version_at_height(self.consensus_pool_cache.as_ref(), finalized_height)
        {
            registry_version
        } else {
            error!(
                self.log,
                "Unable to obtain registry version for use for signing canister http responses",
            );
            return Vec::new();
        };
        let mut change_set = Vec::new();
        loop {
            match self.http_adapter_shim.lock().unwrap().try_receive() {
                Err(TryReceiveError::Empty) => break,
                Ok(response) => {
                    let response_metadata = CanisterHttpResponseMetadata {
                        id: response.id,
                        timeout: response.timeout,
                        registry_version,
                        content_hash: ic_types::crypto::crypto_hash(&response),
                    };
                    let signature = if let Ok(signature) = self
                        .crypto
                        .sign(
                            &response_metadata,
                            self.replica_config.node_id,
                            registry_version,
                        )
                        .map_err(|err| error!(self.log, "Failed to sign http response {}", err))
                    {
                        signature
                    } else {
                        continue;
                    };
                    let share = Signed {
                        content: response_metadata,
                        signature,
                    };
                    self.requested_id_cache.borrow_mut().remove(&response.id);
                    self.metrics.shares_signed.inc();
                    change_set.push(CanisterHttpChangeAction::AddToValidated(share, response));
                }
            }
        }
        change_set
    }

    /// Validate any shares found in the unvalidated section of the canister http pool.
    fn validate_shares(
        &self,
        consensus_cache: &dyn ConsensusPoolCache,
        canister_http_pool: &dyn CanisterHttpPool,
        finalized_height: Height,
    ) -> CanisterHttpChangeSet {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["validate_shares"])
            .start_timer();
        let registry_version = if let Some(registry_version) =
            registry_version_at_height(consensus_cache, finalized_height)
        {
            registry_version
        } else {
            error!(
                self.log,
                "Unable to obtain registry version for use for signing canister http responses",
            );
            return Vec::new();
        };

        let active_callback_ids = self.active_callback_ids();
        let next_callback_id = self.next_callback_id();

        let key_from_share =
            |share: &CanisterHttpResponseShare| (share.signature.signer, share.content.id);

        let mut existing_signed_requests: HashSet<_> = canister_http_pool
            .get_validated_shares()
            .map(key_from_share)
            .collect();

        canister_http_pool
            .get_unvalidated_shares()
            // Only consider shares belonging to the requests that we can validate.
            .filter(|share| share.content.id < next_callback_id)
            .filter_map(|share| {
                if existing_signed_requests.contains(&key_from_share(share)) {
                    return Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        "Redundant share".into(),
                    ));
                }

                if !active_callback_ids.contains(&share.content.id) {
                    return Some(CanisterHttpChangeAction::RemoveUnvalidated(share.clone()));
                }

                let node_is_in_committee = self
                    .membership
                    .node_belongs_to_canister_http_committee(
                        finalized_height,
                        share.signature.signer,
                    )
                    .map_err(|e| {
                        warn!(
                            self.log,
                            "Unabled to check membership for share at height {}, {:?}",
                            finalized_height,
                            e
                        );
                        e
                    })
                    .ok()?;
                if !node_is_in_committee {
                    return Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        "Share signed by node that is not a member of the canister http committee"
                            .to_string(),
                    ));
                }
                // TODO: more precise error handling
                if let Err(err) = self.crypto.verify(share, registry_version) {
                    error!(self.log, "Unable to verify signature of share, {}", err);

                    self.metrics.shares_marked_invalid.inc();
                    Some(CanisterHttpChangeAction::HandleInvalid(
                        share.clone(),
                        format!("Unable to verify signature of share, {}", err),
                    ))
                } else {
                    // Update the set of existing signed requests.
                    existing_signed_requests.insert(key_from_share(share));
                    self.metrics.shares_validated.inc();
                    Some(CanisterHttpChangeAction::MoveToValidated(share.clone()))
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

        // Whenever we have artifacts to purge, we insert the purge change actions before everything
        // else, to avoid having in the validated pool artifacts belonging to different epochs and
        // hence preserving the expected maximal number of artifacts in the pool.
        change_set.extend(self.purge_shares_of_processed_requests(canister_http_pool));

        let finalized_height = self.consensus_pool_cache.finalized_block().height();

        if self
            .membership
            .node_belongs_to_canister_http_committee(finalized_height, self.replica_config.node_id)
            .unwrap_or(false)
        {
            // Make any requests that need to be made
            self.make_new_requests(canister_http_pool);

            // Create shares from any responses that are now available
            change_set.extend(self.create_shares_from_responses(finalized_height));
        }

        // Attempt to validate unvalidated shares
        change_set.extend(self.validate_shares(
            self.consensus_pool_cache.as_ref(),
            canister_http_pool,
            finalized_height,
        ));

        self.metrics
            .in_client_requests
            .set(self.requested_id_cache.borrow().len().try_into().unwrap());

        change_set
    }

    fn active_callback_ids(&self) -> BTreeSet<CallbackId> {
        self.state_reader
            .get_latest_state()
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .keys()
            .copied()
            .collect()
    }

    fn next_callback_id(&self) -> CallbackId {
        self.state_reader
            .get_latest_state()
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .next_callback_id()
    }
}

impl<T: CanisterHttpPool> PoolMutationsProducer<T> for CanisterHttpPoolManagerImpl {
    type Mutations = CanisterHttpChangeSet;

    fn on_state_change(&self, canister_http_pool: &T) -> CanisterHttpChangeSet {
        if let Ok(subnet_features) = self.registry_client.get_features(
            self.replica_config.subnet_id,
            self.registry_client.get_latest_version(),
        ) {
            if subnet_features.unwrap_or_default().http_requests {
                return self.generate_change_set(canister_http_pool);
            }
        }
        vec![]
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_consensus_utils::crypto::SignVerify;
    use ic_interfaces::p2p::consensus::{MutablePool, UnvalidatedArtifact};
    use ic_interfaces_state_manager::Labeled;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::SubnetCallContext;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        crypto::{CryptoHash, CryptoHashOf},
        messages::CallbackId,
        time::UNIX_EPOCH,
        Height, RegistryVersion, Time,
    };
    use mockall::predicate::*;
    use mockall::*;
    use std::collections::BTreeMap;

    mock! {
        pub NonBlockingChannel<Request: 'static> {
        }

        impl<Request> NonBlockingChannel<Request> for NonBlockingChannel<Request> {
            type Response = CanisterHttpResponse;

            fn send(&self, request: Request) -> Result<(), SendError<Request>>;
            fn try_receive(&mut self) -> Result<CanisterHttpResponse, TryReceiveError>;
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

    fn empty_canister_http_response(id: u64) -> CanisterHttpResponse {
        CanisterHttpResponse {
            id: CallbackId::from(id),
            canister_id: ic_types::CanisterId::from(0),
            timeout: Time::from_nanos_since_unix_epoch(0),
            content: CanisterHttpResponseContent::Success(Vec::new()),
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
                } = dependencies(pool_config.clone(), 5);
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = CanisterHttpRequestContext {
                    request: ic_test_utilities_types::messages::RequestBuilder::new().build(),
                    url: "".to_string(),
                    max_response_bytes: None,
                    headers: vec![],
                    body: None,
                    http_method: CanisterHttpMethod::GET,
                    transform: None,
                    time: ic_types::Time::from_nanos_since_unix_epoch(10),
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

                // Try to insert a share for request id 1 (while the next expected one is the
                // default value 0).
                {
                    let response_metadata = CanisterHttpResponseMetadata {
                        id: CallbackId::from(1),
                        timeout: ic_types::Time::from_nanos_since_unix_epoch(10),
                        registry_version: RegistryVersion::from(1),
                        content_hash: CryptoHashOf::new(CryptoHash(vec![])),
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
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: share,
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
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let changes = pool_manager.validate_shares(
                    pool.get_cache().as_ref(),
                    &canister_http_pool,
                    Height::from(0),
                );

                // Make sure the changes are empty (share was filtered out)
                assert!(changes.is_empty());
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
                } = dependencies(pool_config.clone(), 5);
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = CanisterHttpRequestContext {
                    request: ic_test_utilities_types::messages::RequestBuilder::new().build(),
                    url: "".to_string(),
                    max_response_bytes: None,
                    headers: vec![],
                    body: None,
                    http_method: CanisterHttpMethod::GET,
                    transform: None,
                    time: ic_types::Time::from_nanos_since_unix_epoch(10),
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

                let response_metadata = CanisterHttpResponseMetadata {
                    id: CallbackId::from(0),
                    timeout: ic_types::Time::from_nanos_since_unix_epoch(10),
                    registry_version: RegistryVersion::from(1),
                    content_hash: CryptoHashOf::new(CryptoHash(vec![])),
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
                    canister_http_pool.apply_changes(vec![
                        CanisterHttpChangeAction::AddToValidated(share, content),
                    ]);
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
                    canister_http_pool.insert(UnvalidatedArtifact {
                        message: share,
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
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );

                let changes = pool_manager.validate_shares(
                    pool.get_cache().as_ref(),
                    &canister_http_pool,
                    Height::from(0),
                );

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
                } = dependencies(pool_config.clone(), 5);
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let request = CanisterHttpRequestContext {
                    request: ic_test_utilities_types::messages::RequestBuilder::new().build(),
                    url: "".to_string(),
                    max_response_bytes: None,
                    headers: vec![],
                    body: None,
                    http_method: CanisterHttpMethod::GET,
                    transform: None,
                    time: ic_types::Time::from_nanos_since_unix_epoch(10),
                };

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

                let response_metadata = CanisterHttpResponseMetadata {
                    id: CallbackId::from(7),
                    timeout: ic_types::Time::from_nanos_since_unix_epoch(10),
                    registry_version: RegistryVersion::from(1),
                    content_hash: CryptoHashOf::new(CryptoHash(vec![])),
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
                canister_http_pool.apply_changes(vec![CanisterHttpChangeAction::AddToValidated(
                    share, content,
                )]);
                let pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager as Arc<_>,
                    shim,
                    crypto,
                    pool.get_cache(),
                    replica_config,
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
                } = dependencies(pool_config.clone(), 4);

                state_manager
                    .get_mut()
                    .expect_get_latest_state()
                    .return_const(Labeled::new(
                        Height::from(1),
                        Arc::new(state_with_pending_http_calls(BTreeMap::from([]))),
                    ));

                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();

                let mut sequence = Sequence::new();
                for i in 3..5 {
                    shim_mock
                        .expect_try_receive()
                        .times(1)
                        .returning(move || Ok(empty_canister_http_response(i)))
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
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );
                let change_set = pool_manager.generate_change_set(&canister_http_pool);
                assert_eq!(change_set.len(), 2);
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
                } = dependencies(pool_config.clone(), 4);
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = CanisterHttpRequestContext {
                    request: ic_test_utilities_types::messages::RequestBuilder::new().build(),
                    url: "".to_string(),
                    max_response_bytes: None,
                    headers: vec![],
                    body: None,
                    http_method: CanisterHttpMethod::GET,
                    transform: None,
                    time: ic_types::Time::from_nanos_since_unix_epoch(10),
                };

                // Expect times to be called exactly once to check that already
                // requested cache works.
                shim_mock
                    .expect_send()
                    .with(eq(CanisterHttpRequest {
                        id: CallbackId::from(7),
                        timeout: ic_types::Time::from_nanos_since_unix_epoch(10)
                            + Duration::from_secs(60 * 5),
                        context: request.clone(),
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
                    Arc::clone(&registry) as Arc<_>,
                    MetricsRegistry::new(),
                    log,
                );
                let mut canister_http_pool =
                    CanisterHttpPoolImpl::new(MetricsRegistry::new(), no_op_logger());
                let change_set = pool_manager.generate_change_set(&canister_http_pool);
                assert_eq!(change_set.len(), 0);

                let response_metadata = CanisterHttpResponseMetadata {
                    id: CallbackId::from(7),
                    timeout: ic_types::Time::from_nanos_since_unix_epoch(10),
                    registry_version: RegistryVersion::from(1),
                    content_hash: CryptoHashOf::new(CryptoHash(vec![])),
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

                canister_http_pool.apply_changes(vec![CanisterHttpChangeAction::AddToValidated(
                    share, content,
                )]);

                // Now that there are shares in the pool, we should be able to
                // call generate_change_set again without send being called.
                pool_manager.generate_change_set(&canister_http_pool);
            });
        });
    }
}
