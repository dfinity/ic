//! The replay tool is to help recover a broken subnet by replaying past blocks
//! and create a checkpoint of the latest state, which can then be used to
//! create recovery CatchUpPackage. It is also used to replay the artifacts
//! stored as backup, to recover a state at any height.
//!
//! It requires the same replica config file as used on the replica. It will use
//! it to locate the relevant consensus pool, state, etc. according to the
//! config file and starts replaying past finalized block, if any of them have
//! not already been executed.
//!
//! It also supports sub-commands that allows direct modifications to canister
//! state (after all past blocks have been executed). All of them are meant to
//! help recover NNS subnet where the registry canister resides.
//!
//! Use `ic-replay --help` to find out more.
use ic_artifact_pool::{
    certification_pool::CertificationPoolImpl,
    consensus_pool::{ConsensusPoolImpl, UncachedConsensusPoolImpl},
};
use ic_config::{
    artifact_pool::ArtifactPoolConfig, registry_client::DataProviderConfig,
    subnet_config::SubnetConfigs, Config,
};
use ic_consensus::consensus::{
    batch_delivery::deliver_batches, pool_reader::PoolReader, utils::crypto_hashable_to_seed,
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::setup_execution;
use ic_interfaces::{
    certification::CertificationPool,
    certification::Verifier,
    execution_environment::{IngressHistoryReader, QueryHandler},
    messaging::{MessageRouting, MessageRoutingError},
    registry::{RegistryClient, RegistryTransportRecord},
    state_manager::{PermanentStateHashError, StateHashError, StateManager, StateReader},
};
use ic_logger::{new_replica_logger, LoggerImpl, ReplicaLogger};
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::{
    replica_version::v1::BlessedReplicaVersions, subnet::v1::SubnetRecord,
};
use ic_registry_client::client::{create_data_provider, RegistryClientImpl};
use ic_registry_common::{
    local_store::{Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreWriter},
    registry::registry_deltas_to_registry_transport_records,
    values::deserialize_registry_value,
};
use ic_registry_keys::{make_blessed_replica_version_key, make_subnet_record_key};
use ic_registry_transport::{
    deserialize_get_changes_since_response, deserialize_get_latest_version_response,
    deserialize_get_value_response, serialize_get_changes_since_request,
    serialize_get_value_request,
};
use ic_replica::setup::get_subnet_type;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::StateManagerImpl;
use ic_types::{
    batch::{Batch, BatchPayload, IngressPayload},
    consensus::{CatchUpPackage, HasVersion},
    ingress::{IngressStatus, WasmResult},
    messages::{MessageId, SignedIngress, UserQuery},
    time::current_time,
    Height, PrincipalId, Randomness, RegistryVersion, ReplicaVersion, SubnetId, Time, UserId,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;

mod backup;
pub mod cmd;
pub mod ingress;

// Amount of time we are waiting for execution, after batches are delivered.
const WAIT_DURATION: Duration = Duration::from_millis(200);

/// The main ic-replay component that sets up consensus and execution
/// environment to replay past blocks.
pub struct Player {
    state_manager: Arc<StateManagerImpl>,
    message_routing: MessageRoutingImpl,
    consensus_pool: Option<ConsensusPoolImpl>,
    http_query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    certification_pool: Option<CertificationPoolImpl>,
    registry: Arc<RegistryClientImpl>,
    local_store_path: Option<PathBuf>,
    replica_version: ReplicaVersion,
    _log: ReplicaLogger,
    /// The id of the subnet where the artifacts are taken from.
    pub subnet_id: SubnetId,
    backup_dir: Option<PathBuf>,
    tmp_dir: Option<TempDir>,
    // The target height until which the state will be replayed.
    // None means finalized height.
    replay_target_height: Option<u64>,
}

impl Player {
    /// Create and return a `Player` from a replica configuration object for
    /// restoring states from backups.
    pub async fn new_for_backup(
        mut cfg: Config,
        replica_version: ReplicaVersion,
        backup_spool_path: &Path,
        registry_local_store_path: &Path,
        subnet_id: SubnetId,
        start_height: u64,
    ) -> Self {
        let logger = LoggerImpl::new(&cfg.logger, "ic-replay".to_string());
        let log = new_replica_logger(logger.root.clone(), &cfg.logger);
        let data_provided_config = cfg
            .registry_client
            .data_provider
            .as_ref()
            .expect("No registry provider found");

        // In the special case where we start from the Genesis height, we want to clean
        // up the execution state before.
        if start_height == 0 {
            let state_path = &cfg.state_manager.state_root();
            let registry_path = match &cfg.registry_client.data_provider {
                Some(DataProviderConfig::LocalStore(path)) => path,
                _ => panic!("The registry local store path is not configured."),
            };
            delete_folders_if_consent_given(state_path, registry_path);
            let data_provider = create_data_provider(
                &DataProviderConfig::LocalStore(registry_local_store_path.into()),
                None,
            );
            // Because we use the LocalStoreImpl, we know that we get the
            // registry in one chunk when calling get_update_since().
            let records = data_provider
                .get_updates_since(RegistryVersion::from(0))
                .expect("Couldn't get the initial registry contents");
            if let DataProviderConfig::LocalStore(path) = data_provided_config {
                write_records_to_local_store(path, RegistryVersion::from(0), records);
            } else {
                panic!("The replica config must point to a registry local store");
            }
        }

        let data_provider = create_data_provider(data_provided_config, None);
        let registry = Arc::new(RegistryClientImpl::new(data_provider, None));
        registry
            .poll_once()
            .expect("Couldn't poll the registry data provider");
        // Since we read all artifacts from the disc, we don't care about the initial
        // state of the consensus pool.
        let tmp_dir = tempfile::Builder::new()
            .prefix("replay_artifact_pool_")
            .tempdir()
            .expect("Couldn't create a temporary directory");
        cfg.artifact_pool.consensus_pool_path = tmp_dir.path().into();
        // If the backup was configured, make sure we switch it off during the replay.
        cfg.artifact_pool.backup = None;
        println!(
            "Using {:?} for the temporary consensus pool...",
            cfg.artifact_pool.consensus_pool_path
        );
        let artifact_pool_config = ArtifactPoolConfig::from(cfg.artifact_pool.clone());
        let backup_dir = backup_spool_path
            .join(subnet_id.to_string())
            .join(replica_version.to_string());
        // Extract the genesis CUP and instantiate a new pool.
        let initial_cup = backup::read_cup_at_height(
            registry.clone(),
            subnet_id,
            &backup_dir,
            Height::from(start_height),
        );
        // This would create a new pool with just the genesis CUP.
        let pool = ConsensusPoolImpl::new_from_cup_without_bytes(
            subnet_id,
            initial_cup,
            artifact_pool_config,
            MetricsRegistry::global(),
            log.clone(),
        );

        let mut player = Player::new_with_params(
            cfg,
            Arc::new(backup::MockVerifier {}),
            registry,
            subnet_id,
            Some(pool),
            log,
            Some(backup_dir),
            replica_version,
        )
        .await;
        player.tmp_dir = Some(tmp_dir);
        player
    }

    /// Create and return a `Player` from a replica configuration object for
    /// subnet recovery.
    pub async fn new(cfg: Config, subnet_id: SubnetId) -> Self {
        let logger = LoggerImpl::new(&cfg.logger, "ic-replay".to_string());
        let log = new_replica_logger(logger.root.clone(), &cfg.logger);
        let metrics_registry = MetricsRegistry::global();
        let registry = setup_registry(cfg.clone(), Some(&metrics_registry));

        let mut replica_version = Default::default();
        let consensus_pool = if cfg.artifact_pool.consensus_pool_path.exists() {
            let mut artifact_pool_config = ArtifactPoolConfig::from(cfg.artifact_pool.clone());
            // We don't want to modify the original consensus pool during the subnet
            // recovery.
            artifact_pool_config.persistent_pool_read_only = true;
            let consensus_pool = ConsensusPoolImpl::from_uncached(
                UncachedConsensusPoolImpl::new(artifact_pool_config, log.clone()),
                MetricsRegistry::global(),
            );
            // Use the replica version from the finalized tip in the pool.
            replica_version = PoolReader::new(&consensus_pool)
                .get_finalized_tip()
                .version()
                .clone();
            Some(consensus_pool)
        } else {
            None
        };

        println!("Using replica version {}", replica_version);

        Player::new_with_params(
            cfg,
            Arc::new(backup::MockVerifier {}),
            registry,
            subnet_id,
            consensus_pool,
            log,
            None,
            replica_version,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_with_params(
        cfg: Config,
        verifier: Arc<dyn Verifier>,
        registry: Arc<RegistryClientImpl>,
        subnet_id: SubnetId,
        consensus_pool: Option<ConsensusPoolImpl>,
        log: ReplicaLogger,
        backup_dir: Option<PathBuf>,
        replica_version: ReplicaVersion,
    ) -> Self {
        let subnet_type = get_subnet_type(
            registry.as_ref(),
            subnet_id,
            registry.get_latest_version(),
            &log,
        )
        .await;
        let local_store_path = if let Some(DataProviderConfig::LocalStore(path)) =
            cfg.registry_client.data_provider.clone()
        {
            Some(path)
        } else {
            None
        };

        let metrics_registry = MetricsRegistry::global();
        let subnet_config = SubnetConfigs::default().own_subnet_config(subnet_type);

        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            subnet_type,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        ));
        let state_manager = Arc::new(StateManagerImpl::new(
            verifier,
            subnet_id,
            subnet_type,
            log.clone(),
            &metrics_registry,
            &cfg.state_manager,
            ic_types::malicious_flags::MaliciousFlags::default(),
        ));
        let (_, ingress_history_writer, ingress_history_reader, http_query_handler, _, scheduler) =
            setup_execution(
                log.clone(),
                &metrics_registry,
                subnet_id,
                subnet_type,
                subnet_config.scheduler_config,
                cfg.hypervisor.clone(),
                Arc::clone(&cycles_account_manager),
                Arc::clone(&state_manager) as Arc<_>,
            );
        let message_routing = MessageRoutingImpl::new(
            state_manager.clone(),
            state_manager.clone(),
            ingress_history_writer.clone(),
            scheduler,
            cfg.hypervisor,
            cycles_account_manager,
            subnet_id,
            &metrics_registry,
            log.clone(),
            registry.clone(),
        );
        let certification_pool = if consensus_pool.is_some() {
            Some(CertificationPoolImpl::new(
                ArtifactPoolConfig::from(cfg.artifact_pool.clone()),
                log.clone(),
                metrics_registry.clone(),
            ))
        } else {
            None
        };

        Player {
            state_manager,
            message_routing,
            consensus_pool,
            http_query_handler,
            ingress_history_reader,
            certification_pool,
            registry,
            local_store_path,
            subnet_id,
            replica_version,
            backup_dir,
            _log: log,
            tmp_dir: None,
            replay_target_height: None,
        }
    }

    /// Set the replay target height
    pub fn with_replay_target_height(mut self, replay_target_height: Option<u64>) -> Self {
        self.replay_target_height = replay_target_height;
        self
    }

    /// Replay past finalized but un-executed blocks by delivering ingress
    /// messages for execution, and make a full checkpoint of the latest
    /// state when they all finish.
    ///
    /// It takes a function argument, which can be used to make extra ingress
    /// messages for execution, which are delivered after the last finalized
    /// block has been replayed. Note that this will advance the executed
    /// batch height but not advance finalized block height in consensus
    /// pool.
    pub fn replay<F: FnMut(&Player, Time) -> Vec<SignedIngress>>(&self, extra: F) {
        if let (Some(consensus_pool), Some(certification_pool)) =
            (&self.consensus_pool, &self.certification_pool)
        {
            let pool_reader = &PoolReader::new(consensus_pool);
            let finalized_height = pool_reader.get_finalized_height();
            let target_height = Some(
                finalized_height.min(
                    self.replay_target_height
                        .map(Height::from)
                        .unwrap_or_else(|| finalized_height),
                ),
            );
            let last_batch_height =
                self.deliver_batches(&self.message_routing, pool_reader, target_height);
            self.wait_for_state(last_batch_height);
            // We only want to persist the checkpoint after the latest batch.
            self.state_manager.remove_states_below(last_batch_height);

            // Redeliver certifications to state manager. It will panic if there is any
            // mismatch.
            for h in certification_pool.certified_heights() {
                let certification = certification_pool
                    .certification_at_height(h)
                    .unwrap_or_else(|| panic!("Missing certification at height {:?}", h));
                self.state_manager
                    .deliver_state_certification(certification);
            }
        }

        let (latest_context_time, extra_batch_delivery) =
            self.deliver_extra_batch(&self.message_routing, self.consensus_pool.as_ref(), extra);

        if let Some((last_batch_height, msg_ids)) = extra_batch_delivery {
            self.wait_for_state(last_batch_height);
            // We only want to persist the checkpoint after the latest batch.
            self.state_manager.remove_states_below(last_batch_height);

            // check if the extra messages have been delivered successfully
            let get_latest_status = self.ingress_history_reader.get_latest_status();
            for msg_id in msg_ids {
                match get_latest_status(&msg_id) {
                    IngressStatus::Completed {
                        result: WasmResult::Reply(bytes),
                        ..
                    } => println!("Ingress id={} response={}", &msg_id, hex::encode(bytes)),
                    status => panic!("Execution of {} has failed: {:?}", msg_id, status),
                }
            }
        }

        // If we are not replaying NNS subnet, this query will fail.
        // If it fails, we'll query registry client for latest version instead.
        let registry_version = self
            .get_latest_registry_version(latest_context_time)
            .unwrap_or_else(|_| self.registry.get_latest_version());
        println!("Latest registry version: {}", registry_version);
    }

    // Blocks until the state at the given height is committed.
    fn wait_for_state(&self, height: Height) {
        loop {
            let latest_state_height = self.state_manager.latest_state_height();
            if latest_state_height >= height {
                match self.state_manager.get_state_hash_at(height) {
                    Ok(hash) => {
                        println!("Latest checkpoint at height: {}", height);
                        println!("Latest state hash: {}", hex::encode(&hash.get().0));
                        break;
                    }
                    Err(StateHashError::Transient(err)) => {
                        println!("Transient state hash error: {:?}", err);
                    }
                    // This only happens for partially certified heights.
                    Err(StateHashError::Permanent(
                        PermanentStateHashError::StateNotFullyCertified(h),
                    )) if h == height => break,
                    Err(err) => {
                        panic!("State computation failed: {:?}", err)
                    }
                }
            }
            std::thread::sleep(WAIT_DURATION);
        }
        println!(
            "Latest state height is {}",
            self.state_manager.latest_state_height()
        );
        assert_eq!(
            height,
            self.state_manager.latest_state_height(),
            "Latest delivered batch is of height {} while the latest known state is at height {}",
            height,
            self.state_manager.latest_state_height()
        );
    }

    /// Fetch registry records from the given `nns_url`, and update the local
    /// registry store with the new records.
    pub fn update_registry_local_store(&self) {
        let local_store_path = self.local_store_path.clone().expect(
           "update_registry_local_store can only be used with registry configured with local store");
        println!("RegistryLocalStore path: {:?}", local_store_path);
        let latest_version = self.registry.get_latest_version();
        println!("RegistryLocalStore latest version: {}", latest_version);
        let records = self
            .get_changes_since(
                latest_version.get(),
                current_time() + Duration::from_secs(60),
            )
            .unwrap_or_else(|err| panic!("Error in get_certified_changes_since: {}", err));
        write_records_to_local_store(&local_store_path, latest_version, records)
    }

    /// Deliver finalized batches since last expected batch height.
    fn deliver_batches(
        &self,
        message_routing: &dyn MessageRouting,
        pool: &PoolReader<'_>,
        replay_target_height: Option<Height>,
    ) -> Height {
        let expected_batch_height = message_routing.expected_batch_height();
        let last_batch_height = loop {
            match deliver_batches(
                message_routing,
                pool,
                &*self.state_manager,
                &*self.registry,
                self.subnet_id,
                self.replica_version.clone(),
                &self._log,
                replay_target_height,
                None,
            ) {
                Ok(h) => break h,
                Err(MessageRoutingError::QueueIsFull) => std::thread::sleep(WAIT_DURATION),
                Err(MessageRoutingError::Ignored { .. }) => {
                    unreachable!();
                }
            }
        };
        println!(
            "latest_batch_height = {}, batches = {}",
            last_batch_height,
            last_batch_height - expected_batch_height.decrement()
        );
        println!("Delivered batches up to the height {}", last_batch_height);
        last_batch_height
    }

    fn deliver_extra_batch<F: FnMut(&Player, Time) -> Vec<SignedIngress>>(
        &self,
        message_routing: &dyn MessageRouting,
        pool: Option<&ConsensusPoolImpl>,
        mut extra: F,
    ) -> (Time, Option<(Height, Vec<MessageId>)>) {
        let (registry_version, time, randomness) = match pool {
            None => (
                self.registry.get_latest_version(),
                ic_types::time::current_time(),
                Randomness::from([0; 32]),
            ),
            Some(pool) => {
                let pool = PoolReader::new(pool);
                let finalized_height = pool.get_finalized_height();
                let last_block = pool
                    .get_finalized_block(finalized_height)
                    .unwrap_or_else(|| {
                        panic!(
                            "Finalized block is not found at height {}",
                            finalized_height
                        )
                    });

                (
                    last_block.context.registry_version,
                    last_block.context.time + Duration::from_nanos(1),
                    Randomness::from(crypto_hashable_to_seed(&last_block)),
                )
            }
        };
        let batch_number = message_routing.expected_batch_height();
        let mut extra_batch = Batch {
            batch_number,
            requires_full_state_hash: true,
            payload: BatchPayload::default(),
            // Use a fake randomness here since we don't have random tape for extra messages
            randomness,
            registry_version,
            time,
            consensus_responses: Vec::new(),
        };
        let context_time = extra_batch.time;
        let extra_msgs = extra(self, context_time);
        if extra_msgs.is_empty() {
            return (context_time, None);
        }
        let extra_msg_ids = extra_msgs.iter().map(|msg| msg.id()).collect::<Vec<_>>();
        if !extra_msgs.is_empty() {
            extra_batch.payload.ingress = IngressPayload::from(extra_msgs);
            println!("extra_batch created with new ingress");
        }
        let batch_number = extra_batch.batch_number;
        loop {
            match message_routing.deliver_batch(extra_batch.clone()) {
                Ok(()) => {
                    println!("Delivered batch {}", batch_number);
                    break;
                }
                Err(MessageRoutingError::QueueIsFull) => std::thread::sleep(WAIT_DURATION),
                Err(MessageRoutingError::Ignored { .. }) => {
                    unreachable!("Unexpected error on a valid batch number {}", batch_number);
                }
            }
        }
        (
            context_time,
            Some((extra_batch.batch_number, extra_msg_ids)),
        )
    }

    /// Return latest BlessedReplicaVersions record by querying the registry
    /// canister.
    pub fn get_blessed_replica_versions(
        &self,
        ingress_expiry: Time,
    ) -> Result<BlessedReplicaVersions, String> {
        let key = make_blessed_replica_version_key();
        let query = UserQuery {
            source: UserId::from(PrincipalId::new_anonymous()),
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_value".to_string(),
            method_payload: serialize_get_value_request(key.as_bytes().to_vec(), None)
                .map_err(|err| format!("{}", err))?,
            ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            nonce: None,
        };
        match self.http_query_handler.query(
            query,
            self.state_manager.get_latest_state().take(),
            Vec::new(),
        ) {
            Ok(wasm_result) => match wasm_result {
                WasmResult::Reply(v) => {
                    let bytes = deserialize_get_value_response(v)
                        .map_err(|err| format!("{}", err))?
                        .0;
                    let record =
                        deserialize_registry_value::<BlessedReplicaVersions>(Ok(Some(bytes)))
                            .map_err(|err| format!("{}", err))?
                            .expect("BlessedReplicaVersions does not exist");
                    Ok(record)
                }
                WasmResult::Reject(e) => Err(format!("Query rejected: {}", e)),
            },
            Err(err) => Err(format!("Query failed: {:?}", err)),
        }
    }

    /// Return the latest registry version by querying the registry canister.
    pub fn get_latest_registry_version(
        &self,
        ingress_expiry: Time,
    ) -> Result<RegistryVersion, String> {
        let query = UserQuery {
            source: UserId::from(PrincipalId::new_anonymous()),
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_latest_version".to_string(),
            method_payload: Vec::new(),
            ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            nonce: None,
        };
        match self.http_query_handler.query(
            query,
            self.state_manager.get_latest_state().take(),
            Vec::new(),
        ) {
            Ok(wasm_result) => match wasm_result {
                WasmResult::Reply(v) => deserialize_get_latest_version_response(v)
                    .map(RegistryVersion::from)
                    .map_err(|err| format!("{}", err)),
                WasmResult::Reject(e) => Err(format!("Query rejected: {}", e)),
            },
            Err(err) => Err(format!("Failed run query: {:?}", err)),
        }
    }

    /// Return the highest CatchUpPackage
    pub fn get_highest_catch_up_package(&self) -> CatchUpPackage {
        PoolReader::new(self.consensus_pool.as_ref().unwrap()).get_highest_catch_up_package()
    }

    /// Query the registry canister and return registry records since the given
    /// version.
    pub fn get_changes_since(
        &self,
        version: u64,
        ingress_expiry: Time,
    ) -> Result<Vec<RegistryTransportRecord>, String> {
        let payload = serialize_get_changes_since_request(version).unwrap();
        let query = UserQuery {
            source: UserId::from(PrincipalId::new_anonymous()),
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_changes_since".to_string(),
            method_payload: payload,
            ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            nonce: None,
        };
        match self.http_query_handler.query(
            query,
            self.state_manager.get_latest_state().take(),
            Vec::new(),
        ) {
            Ok(wasm_result) => match wasm_result {
                WasmResult::Reply(v) => deserialize_get_changes_since_response(v)
                    .and_then(|(deltas, _)| registry_deltas_to_registry_transport_records(deltas))
                    .map_err(|err| format!("{:?}", err)),
                WasmResult::Reject(e) => Err(format!("Query rejected: {}", e)),
            },
            Err(err) => Err(format!("Failed run query: {:?}", err)),
        }
    }

    /// Return the SubnetRecord of this subnet at the latest registry version.
    pub fn get_subnet_record(&self, ingress_expiry: Time) -> Result<SubnetRecord, String> {
        let subnet_record_key = make_subnet_record_key(self.subnet_id);
        let query = UserQuery {
            source: UserId::from(PrincipalId::new_anonymous()),
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_value".to_string(),
            method_payload: serialize_get_value_request(
                subnet_record_key.as_bytes().to_vec(),
                None,
            )
            .map_err(|err| format!("{}", err))?,
            ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            nonce: None,
        };
        match self.http_query_handler.query(
            query,
            self.state_manager.get_latest_state().take(),
            Vec::new(),
        ) {
            Ok(wasm_result) => match wasm_result {
                WasmResult::Reply(v) => {
                    let bytes = deserialize_get_value_response(v)
                        .map_err(|err| format!("{}", err))?
                        .0;
                    let record = deserialize_registry_value::<SubnetRecord>(Ok(Some(bytes)))
                        .map_err(|err| format!("{}", err))?
                        .expect("SubnetRecord does not exist");
                    Ok(record)
                }
                WasmResult::Reject(e) => Err(format!("Query rejected: {}", e)),
            },
            Err(err) => Err(format!("Failed run query: {:?}", err)),
        }
    }

    /// Restores the execution state starting from the given height.
    pub fn restore(&mut self, start_height: u64) {
        let target_height = self.replay_target_height.map(Height::from);
        let backup_dir = self.backup_dir.as_ref().expect("No backup path found");
        let start_height = Height::from(start_height);
        let mut height_to_batches = backup::heights_to_artifacts_metadata(backup_dir, start_height)
            .unwrap_or_else(|err| panic!("File scanning failed: {:?}", err));
        println!(
            "Restoring the replica state of subnet {:?} starting from the height {:?}",
            backup_dir, start_height
        );
        // Assert consistent initial state
        backup::assert_consistency_and_clean_up(
            &*self.state_manager,
            self.consensus_pool.as_mut().unwrap(),
        );
        // We start with the specified height and restore heights until we run out of
        // heights on the backup spool or bump into a newer replica version.
        loop {
            let result = backup::deserialize_consensus_artifacts(
                self.registry.clone(),
                self.consensus_pool.as_mut().unwrap(),
                &mut height_to_batches,
                self.subnet_id,
                &self.replica_version,
                self.state_manager.latest_state_height(),
            );

            let last_batch_height = self.deliver_batches(
                &self.message_routing,
                &PoolReader::new(self.consensus_pool.as_ref().unwrap()),
                self.replay_target_height.map(Height::from),
            );
            self.wait_for_state(last_batch_height);
            if let Some(height) = target_height {
                if last_batch_height >= height {
                    println!("Target height {} reached.", height);
                    return;
                }
            }

            match result {
                // Since the pool cache assumes we always have at most one CUP inside the pool,
                // we should deliver all batches before inserting a new CUP into the pool.
                backup::ExitPoint::CUPHeightWasFinalized(cup_height) => {
                    backup::insert_cup_at_height(
                        self.consensus_pool.as_mut().unwrap(),
                        self.registry.clone(),
                        self.subnet_id,
                        backup_dir,
                        cup_height,
                    );
                    backup::assert_consistency_and_clean_up(
                        &*self.state_manager,
                        self.consensus_pool.as_mut().unwrap(),
                    );
                }
                // When we run into a proposal referencing a newer registry version, we need to dump
                // all changes from the registry canister into the local store and apply them.
                backup::ExitPoint::NewerRegistryVersion(new_version) => {
                    self.update_registry_local_store();
                    self.registry
                        .poll_once()
                        .expect("Couldn't update the registry from the local store");
                    assert!(
                        self.registry.get_latest_version() >= new_version,
                        "The registry client couldn't be updated to version {:?} (highest available version is {:?})",
                        new_version, self.registry.get_latest_version()
                    );
                    println!("Updated the registry.");
                }
                backup::ExitPoint::StateBehind(certified_height) => {
                    assert!(
                        certified_height <= self.state_manager.latest_state_height(),
                        "The state manager didn't catch up with the expected certified height"
                    );
                    self.state_manager.remove_states_below(certified_height);
                }
                backup::ExitPoint::Done => {
                    println!(
                        "Restored the state at the height {:?}",
                        self.state_manager.latest_state_height()
                    );
                    return;
                }
            }
        }
    }
}

fn write_records_to_local_store(
    local_store_path: &Path,
    latest_version: RegistryVersion,
    mut records: Vec<RegistryTransportRecord>,
) {
    let local_store = LocalStoreImpl::new(local_store_path);
    println!(
        "Found {:?} deltas in registry canister since version {:?}",
        records.len(),
        latest_version
    );
    records.sort_by_key(|tr| tr.version);
    let changelog = records.iter().fold(Changelog::default(), |mut cl, r| {
        let rel_version = (r.version - latest_version).get();
        if cl.len() < rel_version as usize {
            cl.push(ChangelogEntry::default());
        }
        cl.last_mut().unwrap().push(KeyMutation {
            key: r.key.clone(),
            value: r.value.clone(),
        });
        cl
    });

    changelog
        .into_iter()
        .enumerate()
        .try_for_each(|(i, cle)| {
            let v = latest_version + RegistryVersion::from(i as u64 + 1);
            println!("Writing data of registry version {}", v);
            local_store.store(v, cle)
        })
        .expect("Writing to the file system failed: Stop.");
}

fn delete_folders_if_consent_given(state_path: &Path, registry_path: &Path) {
    println!("Since we start with the genesis height, it's recommended to delete the following directories:");
    [registry_path, state_path].iter().for_each(|v| {
        println!(
            "- {}",
            v.to_str().expect("Couldn't convert path to string.")
        )
    });
    if consent_given("Do you want to delete these directories before the replay?") {
        println!("Cleaning up previous state and registry local store...");
        std::fs::remove_dir_all(state_path).unwrap_or_default();
        std::fs::remove_dir_all(registry_path).unwrap_or_default();
    }
}

/// Prints a question to the user and returns `true`
/// if the user replied with a yes.
pub fn consent_given(question: &str) -> bool {
    use std::io::{stdin, stdout, Write};
    println!("{} [Y/n] ", question);
    let _ = stdout().flush();
    let mut s = String::new();
    stdin().read_line(&mut s).expect("Couldn't read user input");
    matches!(s.as_str(), "\n" | "y\n" | "Y\n")
}

fn setup_registry(
    config: Config,
    metrics_registry: Option<&MetricsRegistry>,
) -> std::sync::Arc<RegistryClientImpl> {
    let data_provider = create_data_provider(
        &config
            .registry_client
            .data_provider
            .expect("Data provider required"),
        None,
    );

    let registry = Arc::new(RegistryClientImpl::new(data_provider, metrics_registry));
    if let Err(e) = registry.fetch_and_start_polling() {
        panic!("fetch_and_start_polling failed: {}", e);
    }
    registry
}
