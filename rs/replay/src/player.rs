use crate::{
    backup,
    backup::{cup_file_name, rename_file},
    ingress::IngressWithPrinter,
    validator::{InvalidArtifact, ReplayValidator},
};
use ic_artifact_pool::{
    certification_pool::CertificationPoolImpl,
    consensus_pool::{ConsensusPoolImpl, UncachedConsensusPoolImpl},
};
use ic_config::{artifact_pool::ArtifactPoolConfig, subnet_config::SubnetConfig, Config};
use ic_consensus::{certification::VerifierImpl, consensus::batch_delivery::deliver_batches};
use ic_consensus_utils::{
    crypto_hashable_to_seed, lookup_replica_version, membership::Membership,
    pool_reader::PoolReader,
};
use ic_crypto_for_verification_only::CryptoComponentForVerificationOnly;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::ExecutionServices;
use ic_interfaces::{
    certification::CertificationPool,
    execution_environment::{IngressHistoryReader, QueryExecutionError, QueryExecutionService},
    messaging::{MessageRouting, MessageRoutingError},
    time_source::SysTimeSource,
};
use ic_interfaces_registry::{RegistryClient, RegistryTransportRecord};
use ic_interfaces_state_manager::{
    PermanentStateHashError, StateHashError, StateManager, StateReader,
};
use ic_logger::{new_replica_logger_from_config, ReplicaLogger};
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::{
    registry::{replica_version::v1::BlessedReplicaVersions, subnet::v1::SubnetRecord},
    types::v1 as pb,
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::{deserialize_registry_value, subnet::SubnetRegistry};
use ic_registry_keys::{make_blessed_replica_versions_key, make_subnet_record_key};
use ic_registry_local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreWriter,
};
use ic_registry_nns_data_provider::registry::registry_deltas_to_registry_transport_records;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{
    deserialize_get_changes_since_response, deserialize_get_latest_version_response,
    deserialize_get_value_response, serialize_get_changes_since_request,
    serialize_get_value_request,
};
use ic_state_manager::StateManagerImpl;
use ic_types::{
    batch::{Batch, BatchMessages, BlockmakerMetrics},
    consensus::{
        certification::{Certification, CertificationContent, CertificationShare},
        CatchUpContentProtobufBytes, CatchUpPackage, HasHeight, HasVersion,
    },
    crypto::{
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        CombinedThresholdSig, CombinedThresholdSigOf, Signed,
    },
    ingress::{IngressState, IngressStatus, WasmResult},
    malicious_flags::MaliciousFlags,
    messages::{CertificateDelegation, Query, QuerySource},
    signature::ThresholdSignature,
    time::current_time,
    CryptoHashOfPartialState, CryptoHashOfState, Height, NodeId, PrincipalId, Randomness,
    RegistryVersion, ReplicaVersion, SubnetId, Time, UserId,
};
use serde::{Deserialize, Serialize};
use slog_async::AsyncGuard;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tower::{buffer::Buffer as TowerBuffer, ServiceExt};

// Amount of time we are waiting for execution, after batches are delivered.
const WAIT_DURATION: Duration = Duration::from_millis(500);

/// Represents the height, hash and registry version of the last execution state
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateParams {
    pub height: Height,
    pub hash: String,
    pub registry_version: RegistryVersion,
    pub invalid_artifacts: Vec<InvalidArtifact>,
}

#[derive(Clone, Debug)]
pub enum ReplayError {
    /// Can't proceed because the state has diverged.
    StateDivergence(Height),
    /// Can't proceed because an upgrade was detected.
    UpgradeDetected(StateParams),
    /// Can't proceed because artifact validation failed after the given height.
    ValidationIncomplete(Height, Vec<InvalidArtifact>),
    /// Can't proceed because CUP verification failed at the given height.
    CUPVerificationFailed(Height),
    /// Replay was successful, but manual inspection is required to choose correct state.
    ManualInspectionRequired(StateParams),
}

pub type ReplayResult = Result<StateParams, ReplayError>;

/// The main ic-replay component that sets up consensus and execution
/// environment to replay past blocks.
pub struct Player {
    state_manager: Arc<StateManagerImpl>,
    message_routing: Arc<dyn MessageRouting>,
    consensus_pool: Option<ConsensusPoolImpl>,
    membership: Option<Arc<Membership>>,
    validator: Option<ReplayValidator>,
    crypto: Arc<dyn CryptoComponentForVerificationOnly>,
    query_handler:
        tower::buffer::Buffer<QueryExecutionService, (Query, Option<CertificateDelegation>)>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    certification_pool: Option<CertificationPoolImpl>,
    pub registry: Arc<RegistryClientImpl>,
    local_store_path: PathBuf,
    replica_version: ReplicaVersion,
    pub log: ReplicaLogger,
    _async_log_guard: AsyncGuard,
    /// The id of the subnet where the artifacts are taken from.
    pub subnet_id: SubnetId,
    backup_dir: Option<PathBuf>,
    tmp_dir: Option<TempDir>,
    // The target height until which the state will be replayed.
    // None means finalized height.
    replay_target_height: Option<u64>,
    runtime: Runtime,
}

impl Player {
    /// Create and return a `Player` from a replica configuration object for
    /// restoring states from backups.
    pub fn new_for_backup(
        mut cfg: Config,
        replica_version: ReplicaVersion,
        backup_spool_path: &Path,
        registry_local_store_path: &Path,
        subnet_id: SubnetId,
        start_height: u64,
    ) -> Self {
        let (log, _async_log_guard) = new_replica_logger_from_config(&cfg.logger);

        let time_source = Arc::new(SysTimeSource::new());
        let data_provider = Arc::new(LocalStoreImpl::new(registry_local_store_path));
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
        let cup_file = backup::cup_file_name(&backup_dir, Height::from(start_height));
        let initial_cup_proto = backup::read_cup_proto_file(&cup_file)
            .expect("CUP of the starting block should be valid");
        // This would create a new pool with just the genesis CUP.
        let pool = ConsensusPoolImpl::new(
            NodeId::from(PrincipalId::new_anonymous()),
            subnet_id,
            // Note: it's important to pass the original proto which came from the command line (as
            // opposed to, for example, a proto which was first deserialized and then serialized
            // again). Since the proto file could have been produced and signed by nodes running a
            // different replica version, there is a possibility that the format of
            // `pb::CatchUpContent` has changed across the versions, in which case deserializing and
            // serializing the proto could result in a different value of
            // `pb::CatchUpPackage::content` which will make it impossible to validate the signature
            // of the proto.
            initial_cup_proto,
            artifact_pool_config,
            MetricsRegistry::new(),
            log.clone(),
            time_source,
        );

        let mut player = Player::new_with_params(
            cfg,
            registry,
            subnet_id,
            Some(pool),
            Some(backup_dir),
            replica_version,
            log,
            _async_log_guard,
        );
        player.tmp_dir = Some(tmp_dir);
        player
    }

    /// Create and return a `Player` from a replica configuration object for
    /// subnet recovery.
    pub fn new(cfg: Config, subnet_id: SubnetId) -> Self {
        let (log, _async_log_guard) = new_replica_logger_from_config(&cfg.logger);
        let metrics_registry = MetricsRegistry::new();
        let registry = setup_registry(cfg.clone(), Some(&metrics_registry));
        let time_source = Arc::new(SysTimeSource::new());

        let consensus_pool = if cfg.artifact_pool.consensus_pool_path.exists() {
            let mut artifact_pool_config = ArtifactPoolConfig::from(cfg.artifact_pool.clone());
            // We don't want to modify the original consensus pool during the subnet
            // recovery.
            artifact_pool_config.persistent_pool_read_only = true;
            let consensus_pool = ConsensusPoolImpl::from_uncached(
                NodeId::from(PrincipalId::new_anonymous()),
                UncachedConsensusPoolImpl::new(artifact_pool_config, log.clone()),
                MetricsRegistry::new(),
                log.clone(),
                time_source,
            );
            Some(consensus_pool)
        } else {
            None
        };

        let replica_version = if let Some(pool) = &consensus_pool {
            // Use the replica version from the finalized tip in the pool.
            PoolReader::new(pool).get_finalized_tip().version().clone()
        } else {
            Default::default()
        };

        Player::new_with_params(
            cfg,
            registry,
            subnet_id,
            consensus_pool,
            None,
            replica_version,
            log,
            _async_log_guard,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_params(
        cfg: Config,
        registry: Arc<RegistryClientImpl>,
        subnet_id: SubnetId,
        consensus_pool: Option<ConsensusPoolImpl>,
        backup_dir: Option<PathBuf>,
        replica_version: ReplicaVersion,
        log: ReplicaLogger,
        _async_log_guard: AsyncGuard,
    ) -> Self {
        println!("Setting default replica version {}", replica_version);
        if ReplicaVersion::set_default_version(replica_version.clone()).is_err() {
            println!("Failed to set default replica version");
        }

        let subnet_type = match registry.get_subnet_record(subnet_id, registry.get_latest_version())
        {
            Ok(Some(record)) => {
                SubnetType::try_from(record.subnet_type).expect("Failed to decode subnet type")
            }
            err => panic!(
                "Failed to extract subnet type of {:?} from registry: {:?}",
                subnet_id, err
            ),
        };

        let metrics_registry = MetricsRegistry::new();
        let subnet_config = SubnetConfig::new(subnet_type);

        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            subnet_type,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        ));
        let crypto = ic_crypto_for_verification_only::new(registry.clone());
        let crypto = Arc::new(crypto);

        let verifier = Arc::new(VerifierImpl::new(crypto.clone()));
        let state_manager = Arc::new(StateManagerImpl::new(
            verifier.clone(),
            subnet_id,
            subnet_type,
            log.clone(),
            &metrics_registry,
            &cfg.state_manager,
            None,
            MaliciousFlags::default(),
        ));
        let (completed_execution_messages_tx, _) = tokio::sync::mpsc::channel(1);
        let execution_service = ExecutionServices::setup_execution(
            log.clone(),
            &metrics_registry,
            subnet_id,
            subnet_type,
            subnet_config.scheduler_config,
            cfg.hypervisor.clone(),
            Arc::clone(&cycles_account_manager),
            Arc::clone(&state_manager) as Arc<_>,
            state_manager.get_fd_factory(),
            completed_execution_messages_tx,
        );
        let message_routing = Arc::new(MessageRoutingImpl::new(
            state_manager.clone(),
            state_manager.clone(),
            execution_service.ingress_history_writer.clone(),
            execution_service.scheduler,
            cfg.hypervisor.clone(),
            cycles_account_manager,
            subnet_id,
            &metrics_registry,
            log.clone(),
            registry.clone(),
            MaliciousFlags::default(),
        ));
        let certification_pool = consensus_pool.as_ref().map(|_| {
            CertificationPoolImpl::new(
                NodeId::from(PrincipalId::new_anonymous()),
                ArtifactPoolConfig::from(cfg.artifact_pool.clone()),
                log.clone(),
                metrics_registry.clone(),
            )
        });
        let local_store_path = cfg.registry_client.local_store.clone();
        let validator = consensus_pool.as_ref().map(|pool| {
            ReplayValidator::new(
                cfg,
                subnet_id,
                crypto.clone(),
                crypto.clone(),
                verifier,
                pool.get_cache().clone(),
                registry.clone(),
                state_manager.clone(),
                message_routing.clone(),
                log.clone(),
            )
        });
        let membership = consensus_pool.as_ref().map(|pool| {
            Arc::new(Membership::new(
                pool.get_cache(),
                registry.clone(),
                subnet_id,
            ))
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to create a tokio runtime");
        Player {
            state_manager,
            message_routing,
            consensus_pool,
            membership,
            validator,
            crypto,
            query_handler: runtime
                .block_on(async { TowerBuffer::new(execution_service.query_execution_service, 1) }),
            ingress_history_reader: execution_service.ingress_history_reader,
            certification_pool,
            registry,
            local_store_path,
            subnet_id,
            replica_version,
            backup_dir,
            log,
            _async_log_guard,
            tmp_dir: None,
            replay_target_height: None,
            runtime,
        }
    }

    /// Set the replay target height
    pub fn with_replay_target_height(mut self, replay_target_height: Option<u64>) -> Self {
        self.replay_target_height = replay_target_height;
        self
    }

    /// In case a consensus pool was supplied, replay past finalized but
    /// un-executed blocks by delivering ingress messages for execution,
    /// and make a full checkpoint of the latest state when they all finish.
    ///
    /// It takes a function argument, which can be used to make extra ingress
    /// messages for execution, which are delivered after the last finalized
    /// block has been replayed. Note that this will advance the executed
    /// batch height but not advance finalized block height in consensus
    /// pool.
    pub fn replay<F: FnMut(&Player, Time) -> Vec<IngressWithPrinter>>(
        &self,
        extra: F,
    ) -> ReplayResult {
        let (inspection_required, invalid_artifacts) = if let (
            Some(consensus_pool),
            Some(certification_pool),
            Some(validator),
            Some(membership),
        ) = (
            &self.consensus_pool,
            &self.certification_pool,
            &self.validator,
            &self.membership,
        ) {
            self.replay_consensus_pool(consensus_pool, membership, certification_pool, validator)?
        } else {
            Default::default()
        };

        let (latest_context_time, extra_batch_delivery) = self.deliver_extra_batch(
            self.message_routing.as_ref(),
            self.consensus_pool.as_ref(),
            extra,
        );

        if let Some((last_batch_height, msgs)) = extra_batch_delivery {
            self.wait_for_state(last_batch_height);
            // We only want to persist the checkpoint after the latest batch.
            self.state_manager.remove_states_below(last_batch_height);

            // check if the extra messages have been delivered successfully
            let get_latest_status = self.ingress_history_reader.get_latest_status();
            for msg in msgs {
                match get_latest_status(&msg.ingress.id()) {
                    IngressStatus::Known {
                        state: IngressState::Completed(WasmResult::Reply(bytes)),
                        ..
                    } => match msg.print {
                        Some(printer) => printer(bytes),
                        _ => println!(
                            "Ingress id={} response={}",
                            &msg.ingress.id(),
                            hex::encode(bytes)
                        ),
                    },
                    status => panic!("Execution of {} has failed: {:?}", msg.ingress.id(), status),
                }
            }
        }

        let state_params =
            self.get_latest_state_params(Some(latest_context_time), invalid_artifacts);
        println!("Latest registry version: {}", state_params.registry_version);

        if inspection_required {
            Err(ReplayError::ManualInspectionRequired(state_params))
        } else {
            Ok(state_params)
        }
    }

    // Validate and replay artifacts in the given consensus and certification pools.
    fn replay_consensus_pool(
        &self,
        consensus_pool: &ConsensusPoolImpl,
        membership: &Membership,
        certification_pool: &CertificationPoolImpl,
        validator: &ReplayValidator,
    ) -> Result<(bool, Vec<InvalidArtifact>), ReplayError> {
        match self.verify_latest_cup() {
            Err(ReplayError::UpgradeDetected(_)) | Ok(_) => {}
            other => other?,
        };

        let pool_reader = &PoolReader::new(consensus_pool);
        let finalized_height = pool_reader.get_finalized_height();
        let target_height = finalized_height.min(
            self.replay_target_height
                .map(Height::from)
                .unwrap_or_else(|| finalized_height),
        );

        // Validate artifacts in temporary pool
        let mut invalid_artifacts = Vec::new();
        invalid_artifacts.append(&mut validator.validate_in_tmp_pool(
            consensus_pool,
            self.get_latest_cup_proto(),
            target_height,
        )?);
        if !invalid_artifacts.is_empty() {
            println!("Invalid artifacts:");
            invalid_artifacts.iter().for_each(|a| println!("{:?}", a));
        }

        let last_batch_height = self.deliver_batches(
            self.message_routing.as_ref(),
            pool_reader,
            membership,
            Some(target_height),
        );
        self.wait_for_state(last_batch_height);

        // Redeliver certifications to state manager. It will panic if there is any
        // mismatch.
        let manual_inspection_required =
            self.redeliver_certifications(certification_pool, validator);

        println!("All blocks successfully replayed.");
        // We only want to persist the checkpoint after the latest batch.
        self.state_manager.remove_states_below(last_batch_height);

        Ok((manual_inspection_required, invalid_artifacts))
    }

    // Verify and redeliver all full certifications found in the certification pool.
    // This function panics if for any height the hash of the full certification does not match the locally
    // computed one or if verification of a certification (share) fails.
    // For all locally computed state heights for which we can't find full a certification, compare the state's
    // hash to the certification shares found at that height. See `is_manual_share_investigation_required` for details.
    // Returns whether manual inspection is required or not.
    fn redeliver_certifications(
        &self,
        certification_pool: &CertificationPoolImpl,
        validator: &ReplayValidator,
    ) -> bool {
        print!("Redelivering certifications:");
        let mut cert_heights = Vec::from_iter(certification_pool.certified_heights());
        cert_heights.sort();
        for (i, &h) in cert_heights.iter().enumerate() {
            if i > 0 && cert_heights[i - 1].increment() != h {
                println!(
                    "\nMissing certifications starting at height {:?}",
                    cert_heights[i - 1].increment()
                );
            }
            let certification = certification_pool
                .certification_at_height(h)
                .unwrap_or_else(|| panic!("Missing certification at height {:?}", h));
            validator
                .verify_certification(&certification)
                .map_err(|e| {
                    panic!(
                        "\nFailed to verify certification at height {h}: {e}. \
                    If this is a recovery, find and delete the offending certification pool. \
                    Delete the combined certification pool and reset the replay checkpoint. \
                    Then restart recovery from the combine certifications step."
                    )
                })
                .ok();
            self.state_manager
                .deliver_state_certification(certification);
            print!(" {}", h);
        }
        println!();

        println!("Comparing uncertified state hashes to certification shares:");
        self.registry.poll_once().ok();
        let f = match self
            .registry
            .get_subnet_size(self.subnet_id, self.registry.get_latest_version())
        {
            Ok(Some(size)) => (size - 1) / 3,
            err => {
                println!("Failed to determine subnet size: {err:?}, continuing with f = 0!");
                0
            }
        };

        let verify = |s: &CertificationShare| {
            validator
                .verify_share(s)
                .map_err(|e| {
                    panic!(
                        "\nFailed to verify {s:?}: {e}. \
                If this is a recovery, find and delete the offending certification pool. \
                Delete the combined certification pool and reset the replay checkpoint. \
                Then restart recovery from the merge certification pools step."
                    )
                })
                .is_ok()
        };

        let malicious_nodes =
            find_malicious_nodes(certification_pool, self.get_latest_cup().height(), &verify);

        // Get heights and local state hashes without a full certification
        let mut missing_certifications = self.state_manager.list_state_hashes_to_certify();
        missing_certifications.sort_by_key(|(height, _)| height.get());
        missing_certifications
            .into_iter()
            .fold(false, |ret, (height, hash)| {
                ret | is_manual_share_investigation_required(
                    certification_pool,
                    &malicious_nodes,
                    height,
                    hash,
                    f,
                )
            })
    }

    // Blocks until the state at the given height is committed.
    fn wait_for_state(&self, height: Height) {
        loop {
            // We first check if `height` was executed. Otherwise the state manager
            // would return a permanent error on a too big height.
            if self.state_manager.latest_state_height() >= height {
                if let Some(hash) = get_state_hash(&*self.state_manager, height) {
                    println!("Latest checkpoint at height: {}", height);
                    println!("Latest state hash: {}", hex::encode(hash.get().0));
                };
                break;
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

    /// Return latest height and state hash according to state manager (latest checkpoint or CUP
    /// state). Additionally returns the latest registry version:
    /// * In case a `latest_context_time` is given (i.a. when adding extra ingress), get the latest
    ///   version by querying the registry canister using the time as ingress expiry
    /// * Otherwise, query the registry client
    pub fn get_latest_state_params(
        &self,
        latest_context_time: Option<Time>,
        invalid_artifacts: Vec<InvalidArtifact>,
    ) -> StateParams {
        // If we are not replaying NNS subnet, this query will fail.
        // If it fails, we'll query registry client for latest version instead.
        let registry_version = if let Some(time) = latest_context_time {
            self.get_latest_registry_version(time)
        } else {
            Ok(self.registry.get_latest_version())
        }
        .unwrap_or_else(|_| self.registry.get_latest_version());

        let (height, hash_raw) = {
            let height = self.state_manager.latest_state_height();
            self.wait_for_state(height);
            if let Ok(hash_raw) = self.state_manager.get_state_hash_at(height) {
                (height, hash_raw)
            } else {
                // If the latest state height corresponds to an in-memory state only, we return the
                // state hash of the latest CUP
                let last_cup = self.get_latest_cup();
                (last_cup.height(), last_cup.content.state_hash)
            }
        };
        let hash = hex::encode(hash_raw.get().0);

        StateParams {
            height,
            hash,
            registry_version,
            invalid_artifacts,
        }
    }

    /// Fetch registry records from the given `nns_url`, and update the local
    /// registry store with the new records.
    pub fn update_registry_local_store(&self) {
        println!("RegistryLocalStore path: {:?}", &self.local_store_path);
        let latest_version = self.registry.get_latest_version();
        println!("RegistryLocalStore latest version: {}", latest_version);
        let records = self
            .get_changes_since(
                latest_version.get(),
                current_time() + Duration::from_secs(60),
            )
            .unwrap_or_else(|err| panic!("Error in get_certified_changes_since: {}", err));
        write_records_to_local_store(&self.local_store_path, latest_version, records)
    }

    /// Deliver finalized batches since last expected batch height.
    fn deliver_batches(
        &self,
        message_routing: &dyn MessageRouting,
        pool: &PoolReader<'_>,
        membership: &Membership,
        replay_target_height: Option<Height>,
    ) -> Height {
        let expected_batch_height = message_routing.expected_batch_height();
        let last_batch_height = loop {
            match deliver_batches(
                message_routing,
                membership,
                pool,
                &*self.registry,
                self.subnet_id,
                self.replica_version.clone(),
                &self.log,
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

    fn deliver_extra_batch<F: FnMut(&Player, Time) -> Vec<IngressWithPrinter>>(
        &self,
        message_routing: &dyn MessageRouting,
        pool: Option<&ConsensusPoolImpl>,
        mut extra: F,
    ) -> (Time, Option<(Height, Vec<IngressWithPrinter>)>) {
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
        let mut extra_batch = Batch {
            batch_number: message_routing.expected_batch_height(),
            batch_summary: None,
            requires_full_state_hash: false,
            messages: BatchMessages::default(),
            // Use a fake randomness here since we don't have random tape for extra messages
            randomness,
            idkg_subnet_public_keys: BTreeMap::new(),
            idkg_pre_signature_ids: BTreeMap::new(),
            registry_version,
            time,
            consensus_responses: Vec::new(),
            blockmaker_metrics: BlockmakerMetrics::new_for_test(),
        };
        let context_time = extra_batch.time;
        let extra_msgs = extra(self, context_time);
        if extra_msgs.is_empty() {
            return (context_time, None);
        }
        if !extra_msgs.is_empty() {
            extra_batch.messages.signed_ingress_msgs = extra_msgs
                .iter()
                .map(|fm| fm.ingress.clone())
                .collect::<Vec<_>>();
            println!("extra_batch created with new ingress");
        }
        loop {
            match message_routing.deliver_batch(extra_batch.clone()) {
                Ok(()) => {
                    println!("Delivered batch {}", extra_batch.batch_number);
                    self.wait_for_state(extra_batch.batch_number);

                    // We are done once we delivered a batch for a new checkpoint
                    if extra_batch.requires_full_state_hash {
                        break;
                    }

                    // If we have messages that could not be completed, we need to keep delivering
                    // empty batches. If all messages could be completed, we need to deliver one
                    // more batch triggering checkpoint creation.
                    let msg_status = self.ingress_history_reader.get_latest_status();
                    let incomplete_msgs_exists =
                        extra_msgs
                            .iter()
                            .any(|msg| match msg_status(&msg.ingress.id()) {
                                IngressStatus::Unknown => true,
                                IngressStatus::Known { state, .. } => !state.is_terminal(),
                            });

                    extra_batch = extra_batch.clone();
                    extra_batch.messages.signed_ingress_msgs = Default::default();
                    extra_batch.batch_number = message_routing.expected_batch_height();
                    extra_batch.time += Duration::from_nanos(1);

                    if !incomplete_msgs_exists {
                        extra_batch.requires_full_state_hash = true;
                    }
                }
                Err(MessageRoutingError::QueueIsFull) => std::thread::sleep(WAIT_DURATION),
                Err(MessageRoutingError::Ignored { .. }) => {
                    unreachable!(
                        "Unexpected error on a valid batch number {}",
                        extra_batch.batch_number
                    );
                }
            }
        }
        (context_time, Some((extra_batch.batch_number, extra_msgs)))
    }

    fn certify_state_with_dummy_certification(&self) {
        if self.state_manager.latest_state_height() > self.state_manager.latest_certified_height() {
            let state_hashes = self.state_manager.list_state_hashes_to_certify();
            let (height, hash) = state_hashes
                .last()
                .expect("There should be at least one state hash to certify");
            self.state_manager
                .deliver_state_certification(Self::certify_hash(
                    self.subnet_id,
                    height,
                    hash,
                ));
        }
    }

    fn certify_hash(
        subnet_id: SubnetId,
        height: &Height,
        hash: &CryptoHashOfPartialState,
    ) -> Certification {
        let combined_sig =
            CombinedThresholdSigOf::from(CombinedThresholdSig(vec![]));
        Certification {
            height: *height,
            signed: Signed {
                content: CertificationContent { hash: hash.clone() },
                signature: ThresholdSignature {
                    signature: combined_sig,
                    signer: NiDkgId {
                        dealer_subnet: subnet_id,
                        target_subnet: NiDkgTargetSubnet::Local,
                        start_block_height: *height,
                        dkg_tag: NiDkgTag::LowThreshold,
                    },
                },
            },
        }
    }

    /// Return latest BlessedReplicaVersions record by querying the registry
    /// canister.
    pub fn get_blessed_replica_versions(
        &self,
        ingress_expiry: Time,
    ) -> Result<BlessedReplicaVersions, String> {
        let key = make_blessed_replica_versions_key();
        let query = Query {
            source: QuerySource::User {
                user_id: UserId::from(PrincipalId::new_anonymous()),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
                nonce: None,
            },
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_value".to_string(),
            method_payload: serialize_get_value_request(key.as_bytes().to_vec(), None)
                .map_err(|err| format!("{}", err))?,
        };
        self.certify_state_with_dummy_certification();
        match self
            .runtime
            .block_on(self.query_handler.clone().oneshot((query, None)))
            .unwrap()
        {
            Ok((Ok(wasm_result), _)) => match wasm_result {
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
            Ok((Err(err), _)) => Err(format!("Query failed: {:?}", err)),
            Err(QueryExecutionError::CertifiedStateUnavailable) => {
                panic!("Certified state unavailable for query call.")
            }
        }
    }

    /// Return the latest registry version by querying the registry canister.
    pub fn get_latest_registry_version(
        &self,
        ingress_expiry: Time,
    ) -> Result<RegistryVersion, String> {
        let query = Query {
            source: QuerySource::User {
                user_id: UserId::from(PrincipalId::new_anonymous()),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
                nonce: None,
            },
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_latest_version".to_string(),
            method_payload: Vec::new(),
        };
        self.certify_state_with_dummy_certification();
        match self
            .runtime
            .block_on(self.query_handler.clone().oneshot((query, None)))
            .unwrap()
        {
            Ok((Ok(wasm_result), _)) => match wasm_result {
                WasmResult::Reply(v) => deserialize_get_latest_version_response(v)
                    .map(RegistryVersion::from)
                    .map_err(|err| format!("{}", err)),
                WasmResult::Reject(e) => Err(format!("Query rejected: {}", e)),
            },
            Ok((Err(err), _)) => Err(format!("Query failed: {:?}", err)),
            Err(QueryExecutionError::CertifiedStateUnavailable) => {
                panic!("Certified state unavailable for query call.")
            }
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
        let query = Query {
            source: QuerySource::User {
                user_id: UserId::from(PrincipalId::new_anonymous()),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
                nonce: None,
            },
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_changes_since".to_string(),
            method_payload: payload,
        };
        self.certify_state_with_dummy_certification();
        match self
            .runtime
            .block_on(self.query_handler.clone().oneshot((query, None)))
            .unwrap()
        {
            Ok((Ok(wasm_result), _)) => match wasm_result {
                WasmResult::Reply(v) => deserialize_get_changes_since_response(v)
                    .and_then(|(deltas, _)| registry_deltas_to_registry_transport_records(deltas))
                    .map_err(|err| format!("{:?}", err)),
                WasmResult::Reject(e) => Err(format!("Query rejected: {}", e)),
            },
            Ok((Err(err), _)) => Err(format!("Query failed: {:?}", err)),
            Err(QueryExecutionError::CertifiedStateUnavailable) => {
                panic!("Certified state unavailable for query call.")
            }
        }
    }

    /// Return the SubnetRecord of this subnet at the latest registry version.
    pub fn get_subnet_record(&self, ingress_expiry: Time) -> Result<SubnetRecord, String> {
        let subnet_record_key = make_subnet_record_key(self.subnet_id);
        let query = Query {
            source: QuerySource::User {
                user_id: UserId::from(PrincipalId::new_anonymous()),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
                nonce: None,
            },
            receiver: REGISTRY_CANISTER_ID,
            method_name: "get_value".to_string(),
            method_payload: serialize_get_value_request(
                subnet_record_key.as_bytes().to_vec(),
                None,
            )
            .map_err(|err| format!("{}", err))?,
        };
        self.certify_state_with_dummy_certification();
        match self
            .runtime
            .block_on(self.query_handler.clone().oneshot((query, None)))
            .unwrap()
        {
            Ok((Ok(wasm_result), _)) => match wasm_result {
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
            Ok((Err(err), _)) => Err(format!("Query failed: {:?}", err)),
            Err(QueryExecutionError::CertifiedStateUnavailable) => {
                panic!("Certified state unavailable for query call.")
            }
        }
    }

    /// Restores the execution state starting from the given height.
    pub fn restore(&mut self, start_height: u64) -> ReplayResult {
        let target_height = self.replay_target_height.map(Height::from);
        let backup_dir = self
            .backup_dir
            .as_ref()
            .expect("No backup path found")
            .clone();
        let start_height = Height::from(start_height);
        let mut height_to_batches =
            backup::heights_to_artifacts_metadata(&backup_dir, start_height)
                .unwrap_or_else(|err| panic!("File scanning failed: {:?}", err));
        println!(
            "Restoring the replica state of subnet {:?} starting from the height {:?}",
            backup_dir, start_height
        );

        // Assert consistent initial state
        if let Err(err) = self.verify_latest_cup() {
            if let ReplayError::CUPVerificationFailed(height) = err {
                let file = cup_file_name(&backup_dir, height);
                println!("Invalid CUP detected: {:?}", file);
                rename_file(&file);
            }
            return Err(err);
        }

        let mut dkg_manager = self
            .validator
            .as_ref()
            .unwrap()
            .new_key_manager(&PoolReader::new(self.consensus_pool.as_ref().unwrap()));
        let mut invalid_artifacts = Vec::new();
        // We start with the specified height and restore heights until we run out of
        // heights on the backup spool or bump into a newer replica version.
        loop {
            let result = backup::deserialize_consensus_artifacts(
                self.registry.clone(),
                self.crypto.clone(),
                self.consensus_pool.as_mut().unwrap(),
                &mut height_to_batches,
                self.subnet_id,
                self.validator.as_ref().unwrap(),
                &mut dkg_manager,
                &mut invalid_artifacts,
            );

            let last_batch_height = self.deliver_batches(
                self.message_routing.as_ref(),
                &PoolReader::new(self.consensus_pool.as_ref().unwrap()),
                self.membership.as_ref().unwrap(),
                self.replay_target_height.map(Height::from),
            );
            self.wait_for_state(last_batch_height);
            if let Some(height) = target_height {
                if last_batch_height >= height {
                    println!("Target height {} reached.", height);
                    return Ok(self.get_latest_state_params(None, invalid_artifacts));
                }
            }

            match result {
                // Since the pool cache assumes we always have at most one CUP inside the pool,
                // we should deliver all batches before inserting a new CUP into the pool.
                Err(backup::ExitPoint::CUPHeightWasFinalized(cup_height)) => {
                    backup::insert_cup_at_height(
                        self.consensus_pool.as_mut().unwrap(),
                        &backup_dir,
                        cup_height,
                    )?;
                    if let Err(err) = self.assert_consistency_and_clean_up() {
                        if let ReplayError::CUPVerificationFailed(height) = err {
                            let file = cup_file_name(&backup_dir, height);
                            println!("Invalid CUP detected: {:?}", file);
                            rename_file(&file);
                        }
                        return Err(err);
                    }
                }
                // When we run into an NNS block referencing a newer registry version, we need to dump
                // all changes from the registry canister into the local store and apply them.
                Err(backup::ExitPoint::NewerRegistryVersion(new_version)) => {
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
                Err(backup::ExitPoint::ValidationIncomplete(last_validated_height)) => {
                    println!(
                        "Validation of artifacts at height {:?} is not complete",
                        last_validated_height
                    );
                    return Err(ReplayError::ValidationIncomplete(
                        last_validated_height,
                        invalid_artifacts,
                    ));
                }
                Ok(_) => {
                    println!(
                        "Restored the state at the height {:?}",
                        self.state_manager.latest_state_height()
                    );
                    return Ok(self.get_latest_state_params(None, invalid_artifacts));
                }
            }
        }
    }

    // Checks that the restored catch-up package contains the same state hash as
    // the one computed by the state manager from the restored artifacts and drops
    // all states below the last CUP.
    fn assert_consistency_and_clean_up(&mut self) -> Result<StateParams, ReplayError> {
        self.verify_latest_cup()?;
        let params = self.get_latest_state_params(None, Vec::new());
        let pool = self.consensus_pool.as_mut().expect("no consensus_pool");
        let cache = pool.get_cache();
        let purge_height = cache.catch_up_package().height();
        println!("Removing all states below height {:?}", purge_height);
        self.state_manager.remove_states_below(purge_height);
        use ic_interfaces::{consensus_pool::ChangeAction, p2p::consensus::MutablePool};
        pool.apply(ChangeAction::PurgeValidatedBelow(purge_height).into());
        Ok(params)
    }

    fn get_latest_cup(&self) -> CatchUpPackage {
        let pool = self
            .consensus_pool
            .as_ref()
            .expect("no consensus_pool")
            .get_cache();
        pool.catch_up_package()
    }

    fn get_latest_cup_proto(&self) -> pb::CatchUpPackage {
        let pool = self
            .consensus_pool
            .as_ref()
            .expect("no consensus_pool")
            .get_cache();
        pool.cup_as_protobuf()
    }

    /// Checks that the catch-up package inside the consensus pool contains the same state hash as
    /// the one computed by the state manager. Additionally, it verifies the CUP's signature.
    pub fn verify_latest_cup(&self) -> Result<(), ReplayError> {
        let last_cup = self.get_latest_cup();
        let protobuf = self.get_latest_cup_proto();

        // We cannot verify the genesis CUP with this subnet's public key. And there is no state.
        if last_cup.height() == Height::from(0) {
            return Ok(());
        }

        // Verify the CUP signature.
        if let Err(err) = self.crypto.verify_combined_threshold_sig_by_public_key(
            &CombinedThresholdSigOf::new(CombinedThresholdSig(protobuf.signature.clone())),
            &CatchUpContentProtobufBytes::from(&protobuf),
            self.subnet_id,
            last_cup.content.block.get_value().context.registry_version,
        ) {
            println!("Verification of the signature on the CUP failed: {:?}", err);
            return Err(ReplayError::CUPVerificationFailed(last_cup.height()));
        }

        if last_cup.height() < self.state_manager.latest_state_height() {
            // In subnet recovery mode we persist states but do not create newer CUPs, hence we cannot
            // assume anymore that every CUP has a corresponding checkpoint. So if we know that the
            // latest checkpoint is above the latest CUP height, we should not compare state hashes.
            return Ok(());
        }

        // Verify state hash against the state hash in the CUP
        if get_state_hash(&*self.state_manager, last_cup.height())
            .expect("No state hash at a current CUP height found")
            != last_cup.content.state_hash
        {
            println!(
                "The state hash of the CUP at height {:?} differs from the local state's hash",
                last_cup.height()
            );
            return Err(ReplayError::StateDivergence(last_cup.height()));
        }

        match lookup_replica_version(
            &*self.registry,
            self.subnet_id,
            &ic_logger::replica_logger::no_op_logger(),
            last_cup.content.registry_version(),
        ) {
            Some(replica_version) if replica_version != self.replica_version => {
                println!(
                    "⚠️  Please use the replay tool of version {} to continue backup recovery from height {:?}",
                    replica_version, last_cup.height()
                );
                return Err(ReplayError::UpgradeDetected(
                    self.get_latest_state_params(None, Vec::new()),
                ));
            }
            _ => {}
        }

        Ok(())
    }
}

/// Return the set of signers that created multiple valid certification shares for the same height
fn find_malicious_nodes(
    certification_pool: &CertificationPoolImpl,
    latest_cup_height: Height,
    verify: &dyn Fn(&CertificationShare) -> bool,
) -> HashSet<NodeId> {
    let mut malicious = HashSet::new();
    if let Some(range) = certification_pool
        .persistent_pool
        .certification_shares()
        .height_range()
    {
        // Do not try to verify shares below the CUP height
        // They are not needed and we may not have the key material to do so
        let min = std::cmp::max(range.min.get(), latest_cup_height.get());

        for h in min..=range.max.get() {
            let shares = certification_pool
                .shares_at_height(Height::from(h))
                .filter(verify)
                .map(|s| (s.signed.content, s.signed.signature.signer))
                .collect::<HashSet<_>>();
            let signers =
                shares
                    .into_iter()
                    .map(|(_, signer)| signer)
                    .fold(HashMap::new(), |mut acc, s| {
                        acc.entry(s).and_modify(|e| *e += 1).or_insert(1);
                        acc
                    });
            signers
                .into_iter()
                .filter(|(_, c)| *c > 1)
                .for_each(|(s, c)| {
                    println!(
                        "Node {s} created {c} shares for height {h}. Ignoring all of its shares."
                    );
                    malicious.insert(s);
                });
        }
    }
    malicious
}

// Find all certification shares at the given heights and count which hashes occurred how many times. Shares created
// by malicious nodes (those creating more than one share for the same height) are ignored while counting.
//
// This is necessary in order to detect non-determinism:
// Consider a subnet of size n=3f+1. Suppose f+1 honest nodes agree on one execution path, while the
// remaining f honest nodes as well as the ic-replay tool agree on a different second path. Moreover,
// suppose that f-2 bad nodes are unreachable, while the two reachable bad nodes pretend to follow the
// second path. Note that an adversary would be able to create a certification for the first path from
// the f+1 honest certification shares and the f nodes that he controls.
//
// For that reason, after counting certification shares, there are three possible actions:
// 1. If there is no hash with f+1 or more certification shares, continue with the next height.
// 2. If there is exactly one hash with f+1 or more certification shares, ensure that it matches the locally
//    computed one, otherwise indicate that manual inspection is required.
// 3. If there are multiple hashes with f+1 or more certification shares, then there is no perfect way to choose
//    the correct state. Return that manual inspection is required. During this inspection:
//    a) Repetitively run the ic-replay tool to produce full states for all hashes with f+1 or more shares.
//    b) Inspect how these states differ, estimate how bad it would be if certifications for all of them were issued.
//    c) Decide which of both states is "preferable" to continue the subnet from and recover the subnet from there.
fn is_manual_share_investigation_required(
    certification_pool: &CertificationPoolImpl,
    malicious_nodes: &HashSet<NodeId>,
    height: Height,
    computed_hash: CryptoHashOfPartialState,
    f: usize,
) -> bool {
    println!("{height}: {computed_hash:?}");
    let certified_hashes =
        get_share_certified_hashes(height, f, certification_pool, malicious_nodes);
    match &certified_hashes[..] {
        [share_hash] => {
            println!("Found enough shares to produce ONE valid certification.");
            if &computed_hash != share_hash {
                println!("Hash mismatch! State divergence detected for outstanding shares!");
            } else {
                println!("Produced state hash matches certification shares!");
            }
            &computed_hash != share_hash
        }
        [] => false,
        other => {
            println!("Found {} different hashes with enough shares to produce valid certifications, investigate manually!", other.len());
            true
        }
    }
}

/// Return state hashes for the given height with at least f + 1 valid shares, excluding shares
/// created by malicious nodes.
fn get_share_certified_hashes(
    height: Height,
    f: usize,
    certification_pool: &CertificationPoolImpl,
    malicious_nodes: &HashSet<NodeId>,
) -> Vec<CryptoHashOfPartialState> {
    let shares = certification_pool
        .shares_at_height(height)
        .filter(|c| !malicious_nodes.contains(&c.signed.signature.signer))
        .map(|s| (s.signed.content, s.signed.signature.signer))
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|(content, _)| content.hash);

    let counter = shares.fold(HashMap::new(), |mut acc, hash| {
        acc.entry(hash).and_modify(|e| *e += 1).or_insert(1);
        acc
    });

    if !counter.is_empty() {
        println!("Number of unique shares per hash at this height: {counter:#?}");
    }

    // Only keep hashes with at least f+1 shares
    counter
        .into_iter()
        .filter_map(|(k, v)| (v > f).then_some(k))
        .collect::<Vec<_>>()
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

fn setup_registry(
    config: Config,
    metrics_registry: Option<&MetricsRegistry>,
) -> std::sync::Arc<RegistryClientImpl> {
    let data_provider = Arc::new(LocalStoreImpl::new(config.registry_client.local_store));

    let registry = Arc::new(RegistryClientImpl::new(data_provider, metrics_registry));
    if let Err(e) = registry.fetch_and_start_polling() {
        panic!("fetch_and_start_polling failed: {}", e);
    }
    registry
}

// Returns the state hash for the given height once it is computed. For non-checkpoints heights
// or when transient error persists `None` is returned.
fn get_state_hash<T>(
    state_manager: &dyn StateManager<State = T>,
    height: Height,
) -> Option<CryptoHashOfState> {
    for _ in 0..120 {
        match state_manager.get_state_hash_at(height) {
            Ok(hash) => return Some(hash),
            Err(StateHashError::Transient(err)) => {
                println!("Waiting for state hash: {:?}", err);
            }
            // This only happens for partially certified heights.
            Err(StateHashError::Permanent(PermanentStateHashError::StateNotFullyCertified(h)))
                if h == height =>
            {
                return None
            }
            Err(err) => {
                panic!("State computation failed: {:?}", err)
            }
        }
        std::thread::sleep(WAIT_DURATION);
    }
    None
}

#[cfg(test)]
mod tests {
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_consensus::fake::FakeSigner;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        consensus::certification::{
            CertificationContent, CertificationMessage, CertificationShare,
        },
        crypto::{CryptoHash, Signed},
        signature::ThresholdSignatureShare,
    };

    use super::*;

    fn make_share(height: u64, hash: Vec<u8>, node_id: u64) -> CertificationMessage {
        CertificationMessage::CertificationShare(CertificationShare {
            height: Height::from(height),
            signed: Signed {
                content: CertificationContent::new(CryptoHash(hash).into()),
                signature: ThresholdSignatureShare::fake(node_test_id(node_id)),
            },
        })
    }

    #[test]
    fn test_get_share_certified_hashes() {
        let tmp = tempfile::tempdir().expect("Could not create a temp dir");
        let pool = CertificationPoolImpl::new(
            node_test_id(0),
            ArtifactPoolConfig::new(tmp.path().to_path_buf()),
            no_op_logger(),
            MetricsRegistry::new(),
        );
        let verify = |_: &CertificationShare| true;
        let f = 2;

        // Node 7 is malicious and creates multiple shares for height 3. All of its shares should be ignored.
        let shares = vec![
            // Height 1:
            // 3 shares for hash "1"
            make_share(1, vec![1], 1),
            make_share(1, vec![1], 2),
            make_share(1, vec![1], 3),
            // 3 shares for hash "2", but one of them is from malicious node 7
            // (should be ignored)
            make_share(1, vec![2], 4),
            make_share(1, vec![2], 5),
            make_share(1, vec![2], 7),
            // Height 2:
            // 1 share for hash "2"
            make_share(2, vec![2], 5),
            // Height 3:
            // 3 shares for hash "1"
            make_share(3, vec![1], 1),
            make_share(3, vec![1], 2),
            make_share(3, vec![1], 3),
            // 4 shares for hash "2"
            make_share(3, vec![2], 4),
            make_share(3, vec![2], 5),
            make_share(3, vec![2], 6),
            make_share(3, vec![2], 7),
            // 1 share for hash "3" by malicious node 7
            make_share(3, vec![3], 7),
        ];

        shares
            .into_iter()
            .for_each(|s| pool.persistent_pool.insert(s));

        let malicious = find_malicious_nodes(&pool, Height::new(0), &verify);
        assert_eq!(malicious.len(), 1);
        assert_eq!(*malicious.iter().next().unwrap(), node_test_id(7));

        let hashes = get_share_certified_hashes(Height::from(1), f, &pool, &malicious);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].get_ref().0, vec![1]);
        assert!(!is_manual_share_investigation_required(
            &pool,
            &malicious,
            Height::from(1),
            CryptoHash(vec![1]).into(),
            f
        ));
        assert!(is_manual_share_investigation_required(
            &pool,
            &malicious,
            Height::from(1),
            CryptoHash(vec![2]).into(),
            f
        ));

        let hashes = get_share_certified_hashes(Height::from(2), f, &pool, &malicious);
        assert!(!is_manual_share_investigation_required(
            &pool,
            &malicious,
            Height::from(2),
            CryptoHash(vec![1]).into(),
            f
        ));
        assert!(hashes.is_empty());

        let hashes = get_share_certified_hashes(Height::from(3), f, &pool, &malicious);
        assert_eq!(hashes.len(), 2);
        assert_ne!(hashes[0], hashes[1]);
        assert!(hashes
            .into_iter()
            .map(|h| h.get().0)
            .all(|h| h == vec![1] || h == vec![2]));
        assert!(is_manual_share_investigation_required(
            &pool,
            &malicious,
            Height::from(3),
            CryptoHash(vec![1]).into(),
            f
        ));
        assert!(is_manual_share_investigation_required(
            &pool,
            &malicious,
            Height::from(3),
            CryptoHash(vec![2]).into(),
            f
        ));
        assert!(is_manual_share_investigation_required(
            &pool,
            &malicious,
            Height::from(3),
            CryptoHash(vec![3]).into(),
            f
        ));
    }
}
