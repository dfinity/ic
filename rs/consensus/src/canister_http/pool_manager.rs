//! This module defines the [`CanisterHttpPoolManagerImpl`], which is an object
//! responsible for managing the flow of requests from execution to the
//! networking component, and ensuring that the resulting responses are signed
//! and eventually make it into consensus.
use crate::consensus::utils::registry_version_at_height;
use crate::consensus::ConsensusCrypto;
use ic_interfaces::{canister_http::*, consensus_pool::ConsensusPoolCache};
use ic_interfaces_canister_http_adapter_client::*;
use ic_interfaces_state_manager::StateManager;
use ic_logger::*;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    canister_http::*, consensus::HasHeight, crypto::Signed, messages::CallbackId,
    replica_config::ReplicaConfig,
};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// CanisterHttpPoolManagerImpl implements the pool and state monitoring
/// functionality that is necessary to ensure that http requests are made and
/// responses can be inserted into consensus. Concretely, it has the following responsibilities:
/// - It must decide when to trigger purging by noticing when consensus time changes
/// - Inform the HttpAdapterShim to make a request when new requests appear in the replicated state
/// - Sign response shares once a request is made
/// - Validate shares in the unvalidated pool that were received from gossip
pub struct CanisterHttpPoolManagerImpl {
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    http_adapter_shim: Arc<Mutex<CanisterHttpAdapterClient>>,
    crypto: Arc<dyn ConsensusCrypto>,
    replica_config: ReplicaConfig,
    requested_id_cache: BTreeSet<CallbackId>,
    log: ReplicaLogger,
}

impl CanisterHttpPoolManagerImpl {
    /// Create a CanisterHttpPoolManagerImpl
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        http_adapter_shim: Arc<Mutex<CanisterHttpAdapterClient>>,
        crypto: Arc<dyn ConsensusCrypto>,
        replica_config: ReplicaConfig,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            http_adapter_shim,
            crypto,
            replica_config,
            log,
            requested_id_cache: BTreeSet::new(),
        }
    }

    /// Make a purge change action if consensus time has advanced.
    fn purge_shares_of_processed_requests(
        &mut self,
        _consensus_cache: &dyn ConsensusPoolCache,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet {
        let active_callback_ids: BTreeSet<_> = self
            .state_manager
            .get_latest_state()
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .iter()
            .map(|(callback_id, _)| *callback_id)
            .collect();

        let ids_to_remove: Vec<_> = self
            .requested_id_cache
            .difference(&active_callback_ids)
            .cloned()
            .collect();

        for callback_id in ids_to_remove.iter() {
            self.requested_id_cache.remove(callback_id);
        }

        canister_http_pool
            .get_validated_shares()
            .filter_map(|share| {
                if active_callback_ids.contains(&share.content.id) {
                    None
                } else {
                    Some(CanisterHttpChangeAction::RemoveValidated(
                        ic_crypto_hash::crypto_hash(share),
                    ))
                }
            })
            .chain(
                canister_http_pool
                    .get_unvalidated_shares()
                    .filter_map(|share| {
                        if active_callback_ids.contains(&share.content.id) {
                            None
                        } else {
                            Some(CanisterHttpChangeAction::RemoveUnvalidated(
                                ic_crypto_hash::crypto_hash(share),
                            ))
                        }
                    }),
            )
            .collect()
    }

    /// Inform the HttpAdapterShim of any new requests that must be made.
    fn make_new_requests(&mut self, canister_http_pool: &dyn CanisterHttpPool) {
        let http_requests = self
            .state_manager
            .get_latest_state()
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .clone();

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
            .union(&self.requested_id_cache)
            .cloned()
            .collect();

        for (id, content) in http_requests {
            if !request_ids_already_made.contains(&id) {
                let timeout = content.time + Duration::from_secs(5 * 60);
                if let Err(err) = self
                    .http_adapter_shim
                    .lock()
                    .unwrap()
                    .send(CanisterHttpRequest {
                        id,
                        timeout,
                        content,
                    })
                {
                    warn!(
                        self.log,
                        "Failed to add canister http request to queue {:?}", err
                    )
                } else {
                    self.requested_id_cache.insert(id);
                }
            }
        }
    }

    /// Create any shares that should be made from responses provided by the
    /// HttpAdapterShim.
    fn create_shares_from_responses(
        &mut self,
        consensus_cache: &dyn ConsensusPoolCache,
    ) -> CanisterHttpChangeSet {
        let registry_version = if let Some(registry_version) =
            registry_version_at_height(consensus_cache, consensus_cache.finalized_block().height())
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
                        content_hash: ic_crypto_hash::crypto_hash(&response),
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
                    self.requested_id_cache.remove(&response.id);
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
    ) -> CanisterHttpChangeSet {
        // TODO: Selection of registry version may technically need to be more deterministic.
        let registry_version = if let Some(registry_version) =
            registry_version_at_height(consensus_cache, consensus_cache.finalized_block().height())
        {
            registry_version
        } else {
            error!(
                self.log,
                "Unable to obtain registry version for use for signing canister http responses",
            );
            return Vec::new();
        };

        canister_http_pool
            .get_unvalidated_shares()
            .map(|share| {
                // TODO: more precise error handling
                if let Err(err) = self.crypto.verify(share, registry_version) {
                    error!(self.log, "Unable to verify signature of share, {}", err);
                    CanisterHttpChangeAction::HandleInvalid(
                        ic_crypto::crypto_hash(share),
                        format!("Unable to verify signature of share, {}", err),
                    )
                } else {
                    CanisterHttpChangeAction::MoveToValidated(ic_crypto::crypto_hash(share))
                }
            })
            .collect()
    }
}

impl CanisterHttpPoolManager for CanisterHttpPoolManagerImpl {
    fn on_state_change(
        &mut self,
        consensus_cache: &dyn ConsensusPoolCache,
        canister_http_pool: &dyn CanisterHttpPool,
    ) -> CanisterHttpChangeSet {
        // Make any requests that need to be made
        self.make_new_requests(canister_http_pool);

        // Create shares from any responses that are now available
        let mut change_set = self.create_shares_from_responses(consensus_cache);

        // Purge items in the pool that are no longer needed
        change_set
            .extend(self.purge_shares_of_processed_requests(consensus_cache, canister_http_pool));

        // Attempt to validate unvalidated shares
        change_set.extend(self.validate_shares(consensus_cache, canister_http_pool));

        change_set
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::consensus::crypto::SignVerify;
    use crate::consensus::mocks::{dependencies, Dependencies};
    use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_interfaces_state_manager::Labeled;
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities::types::ids::subnet_test_id;
    use ic_test_utilities::with_test_replica_logger;
    use ic_types::{
        crypto::{CryptoHash, CryptoHashOf},
        messages::CallbackId,
        Height, RegistryVersion, Time,
    };
    use mockall::predicate::*;
    use mockall::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    mock! {
        pub NonBlockingChannel<Request: 'static> {
        }

        pub trait NonBlockingChannel<Request> {
            type Response = CanisterHttpResponse;

            fn send(&self, request: Request) -> Result<(), SendError<Request>>;
            fn try_receive(&mut self) -> Result<CanisterHttpResponse, TryReceiveError>;
        }
    }

    fn state_with_pending_http_calls(
        http_calls: BTreeMap<CallbackId, CanisterHttpRequestContext>,
    ) -> ReplicatedState {
        // Add some pending http calls
        let mut replicated_state = ReplicatedState::new_rooted_at(
            subnet_test_id(0),
            SubnetType::System,
            PathBuf::from("/tmp"),
        );
        // let mut metadata = SystemMetadata::new(subnet_test_id(0), SubnetType::System);
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
    pub fn test_already_created_shares_not_re_requested() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|log| {
                let Dependencies {
                    pool,
                    replica_config,
                    crypto,
                    state_manager,
                    ..
                } = dependencies(pool_config.clone(), 4);
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let shim: Arc<Mutex<CanisterHttpAdapterClient>> =
                    Arc::new(Mutex::new(Box::new(shim_mock)));

                let request = CanisterHttpRequestContext {
                    request: ic_test_utilities::types::messages::RequestBuilder::new().build(),
                    url: "".to_string(),
                    headers: vec![],
                    body: None,
                    http_method: CanisterHttpMethod::GET,
                    transform_method_name: None,
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

                let mut canister_http_pool = CanisterHttpPoolImpl::new(MetricsRegistry::new());
                canister_http_pool.apply_changes(vec![CanisterHttpChangeAction::AddToValidated(
                    share, content,
                )]);

                let mut pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    replica_config,
                    log,
                );

                // Because we already have a share in the pool, we should be
                // able to call on_state_change again without send being called.
                // We haven't sent an expectation on send, so this will fail if
                // send is, in fact called.
                pool_manager.on_state_change(pool.as_cache(), &canister_http_pool);
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

                let canister_http_pool = CanisterHttpPoolImpl::new(MetricsRegistry::new());
                let mut pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto,
                    replica_config,
                    log,
                );
                let change_set = pool_manager.on_state_change(pool.as_cache(), &canister_http_pool);
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
                    ..
                } = dependencies(pool_config.clone(), 4);
                let mut shim_mock = MockNonBlockingChannel::<CanisterHttpRequest>::new();
                shim_mock
                    .expect_try_receive()
                    .return_const(Err(TryReceiveError::Empty));

                let request = CanisterHttpRequestContext {
                    request: ic_test_utilities::types::messages::RequestBuilder::new().build(),
                    url: "".to_string(),
                    headers: vec![],
                    body: None,
                    http_method: CanisterHttpMethod::GET,
                    transform_method_name: None,
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
                        content: request.clone(),
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

                let mut pool_manager = CanisterHttpPoolManagerImpl::new(
                    state_manager,
                    shim,
                    crypto.clone(),
                    replica_config.clone(),
                    log,
                );
                let mut canister_http_pool = CanisterHttpPoolImpl::new(MetricsRegistry::new());
                let change_set = pool_manager.on_state_change(pool.as_cache(), &canister_http_pool);
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
                // call on_state_change again without send being called.
                pool_manager.on_state_change(pool.as_cache(), &canister_http_pool);
            });
        });
    }
}
