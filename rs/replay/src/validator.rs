use std::sync::{Arc, RwLock};

use ic_artifact_pool::{consensus_pool::ConsensusPoolImpl, dkg_pool::DkgPoolImpl};
use ic_config::{artifact_pool::ArtifactPoolConfig, Config};
use ic_consensus::consensus::{
    dkg_key_manager::DkgKeyManager, pool_reader::PoolReader, validator::Validator, ConsensusCrypto,
    Membership, ValidatorMetrics,
};
use ic_consensus_message::ConsensusMessageHashable;
use ic_crypto::CryptoComponentFatClient;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact,
    consensus_pool::{
        ChangeAction, ConsensusPool, ConsensusPoolCache, HeightIndexedPool, MutableConsensusPool,
    },
    messaging::MessageRouting,
    registry::RegistryClient,
    time_source::{SysTimeSource, TimeSource},
};
use ic_interfaces_state_manager::StateManager;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::ConsensusMessageId,
    consensus::{Block, CatchUpPackage, ConsensusMessage, ConsensusMessageHash, HasBlockHash},
    crypto::CryptoHashOf,
    replica_config::ReplicaConfig,
    Height, SubnetId,
};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::{mocks::MockPayloadBuilder, player::ReplayError};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct InvalidArtifact {
    pub id: ConsensusMessageId,
    pub block_hash: Option<CryptoHashOf<Block>>,
    pub message: String,
}

impl InvalidArtifact {
    pub fn get_file_name(&self) -> Option<String> {
        let mut name = match self.id.hash {
            ConsensusMessageHash::RandomBeacon(_) => "random_beacon",
            ConsensusMessageHash::Finalization(_) => "finalization",
            ConsensusMessageHash::Notarization(_) => "notarization",
            ConsensusMessageHash::BlockProposal(_) => "block_proposal",
            ConsensusMessageHash::RandomTape(_) => "random_tape",
            ConsensusMessageHash::CatchUpPackage(_) => "catch_up_package",
            _ => return None,
        }
        .to_string();

        if let Some(hash) = &self.block_hash {
            name.push_str(&format!(
                "_{}_{}",
                self.bytes_to_hex_string(&hash.get_ref().0),
                self.bytes_to_hex_string(&self.id.hash.digest().0)
            ));
        }

        name.push_str(".bin");
        Some(name)
    }

    fn bytes_to_hex_string(&self, v: &[u8]) -> String {
        v.iter().fold(String::new(), |mut hash, byte| {
            hash.push_str(&format!("{:X}", byte));
            hash
        })
    }
}

pub struct ReplayValidator {
    cfg: Config,
    pub replica_cfg: ReplicaConfig,
    validator: Validator,
    crypto: Arc<dyn ConsensusCrypto>,
    _crypto_dir: TempDir,
    metrics_registry: MetricsRegistry,
    log: ReplicaLogger,
    time_source: Arc<dyn TimeSource>,
}

impl ReplayValidator {
    pub fn new(
        cfg: Config,
        subnet_id: SubnetId,
        pool_cache: Arc<dyn ConsensusPoolCache>,
        registry: Arc<dyn RegistryClient>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        message_routing: Arc<dyn MessageRouting>,
        log: ReplicaLogger,
    ) -> Self {
        let (crypto, node_id, crypto_dir) =
            CryptoComponentFatClient::new_temp_with_all_keys(registry.clone(), log.clone());
        let crypto = Arc::new(crypto);

        let metrics_registry = MetricsRegistry::new();
        let membership = Membership::new(pool_cache, registry.clone(), subnet_id);
        let time_source = Arc::new(SysTimeSource::new());
        let dkg_pool = RwLock::new(DkgPoolImpl::new(metrics_registry.clone()));
        let replica_cfg = ReplicaConfig::new(node_id, subnet_id);

        let validator = Validator::new(
            replica_cfg.clone(),
            Arc::new(membership),
            registry,
            Arc::clone(&crypto) as Arc<_>,
            Arc::new(MockPayloadBuilder {}) as Arc<_>,
            state_manager,
            message_routing,
            Arc::new(dkg_pool) as Arc<_>,
            log.clone(),
            ValidatorMetrics::new(metrics_registry.clone()),
            time_source.clone(),
        );

        Self {
            cfg,
            replica_cfg,
            validator,
            crypto,
            _crypto_dir: crypto_dir,
            metrics_registry,
            log,
            time_source,
        }
    }

    pub fn get_validator(&self) -> &Validator {
        &self.validator
    }

    /// `on_state_change()` of [DkgKeyManager] requires mutable access. We delegate
    /// ownership to the caller, to allow [ReplayValidator] to stay immutable.
    pub fn new_key_manager(&self, pool_reader: &PoolReader) -> DkgKeyManager {
        DkgKeyManager::new(
            self.metrics_registry.clone(),
            self.crypto.clone(),
            self.log.clone(),
            pool_reader,
        )
    }

    pub fn get_timesource(&self) -> Arc<dyn TimeSource> {
        self.time_source.clone()
    }

    /// Insert artifacts of the given [HeightIndexedPool] into the given consensus pool
    /// by mapping them to [UnvalidatedArtifact].
    pub fn insert_into_pool<T: ConsensusMessageHashable>(
        &self,
        from: &dyn HeightIndexedPool<T>,
        to: &mut ConsensusPoolImpl,
    ) {
        from.get_all()
            .map(|hashable| UnvalidatedArtifact {
                message: hashable.into_message(),
                peer_id: self.replica_cfg.node_id,
                timestamp: self.time_source.get_relative_time(),
            })
            .for_each(|u| to.insert(u));
    }

    /// Return a new consensus pool in a temp directory. Validated artifacts of the given pool are inserted as
    /// unvalidated artifacts into the new pool.
    pub fn get_new_unvalidated(
        &self,
        consensus_pool: &dyn ConsensusPool,
        cup: CatchUpPackage,
    ) -> ConsensusPoolImpl {
        let tmp_dir = tempfile::Builder::new()
            .prefix("replay_artifact_pool_")
            .tempdir()
            .expect("Couldn't create a temporary directory");

        let mut cfg = self.cfg.clone();
        cfg.artifact_pool.consensus_pool_path = tmp_dir.path().into();
        // If the backup was configured, make sure we switch it off during the replay.
        cfg.artifact_pool.backup = None;
        println!(
            "Using {:?} for the temporary consensus pool...",
            cfg.artifact_pool.consensus_pool_path
        );
        let artifact_pool_config = ArtifactPoolConfig::from(cfg.artifact_pool);

        // This creates a new pool with just the genesis CUP.
        let mut pool = ConsensusPoolImpl::new_from_cup_without_bytes(
            self.replica_cfg.subnet_id,
            cup,
            artifact_pool_config,
            MetricsRegistry::new(),
            self.log.clone(),
        );

        let validated = consensus_pool.validated();

        self.insert_into_pool(validated.block_proposal(), &mut pool);
        self.insert_into_pool(validated.notarization(), &mut pool);
        self.insert_into_pool(validated.random_beacon(), &mut pool);
        self.insert_into_pool(validated.random_tape(), &mut pool);
        self.insert_into_pool(validated.finalization(), &mut pool);

        pool
    }

    /// Push an [InvalidArtifact] to the given vector if it doesn't exist yet.
    pub fn push_dedup(&self, to: &mut Vec<InvalidArtifact>, artifact: InvalidArtifact) {
        if !to.iter().any(|x| x.eq(&artifact)) {
            to.push(artifact);
        }
    }

    /// Validate the given consensus pool and apply resulting changes, until no more changes are found.
    /// Discovered invalid artifacts are returned. An error is returned if validation stops before the
    /// target finalized height is reached.
    pub fn validate(
        &self,
        pool: &mut ConsensusPoolImpl,
        dkg: &mut DkgKeyManager,
        target_height: Height,
    ) -> Result<Vec<InvalidArtifact>, ReplayError> {
        let validator = self.get_validator();
        let time = self.get_timesource();

        let mut invalid_artifacts = Vec::new();

        loop {
            let changes = {
                let pool_reader = &PoolReader::new(pool);
                dkg.on_state_change(pool_reader);
                validator.on_state_change(pool_reader)
            };

            changes.iter().for_each(|action| match action {
                ChangeAction::HandleInvalid(ref a, ref s) => {
                    let block_hash = match a {
                        ConsensusMessage::Finalization(f) => Some(f.block_hash().clone()),
                        ConsensusMessage::Notarization(n) => Some(n.block_hash().clone()),
                        ConsensusMessage::BlockProposal(b) => Some(b.block_hash().clone()),
                        _ => None,
                    };
                    self.push_dedup(
                        &mut invalid_artifacts,
                        InvalidArtifact {
                            id: a.get_id(),
                            block_hash,
                            message: s.clone(),
                        },
                    );
                }
                ChangeAction::MoveToValidated(_) => {}
                other => {
                    println!("Unexpected change action: {:?}", other);
                }
            });

            if changes.is_empty() {
                break;
            } else {
                pool.apply_changes(time.as_ref(), changes);
            }
        }

        let new_height = PoolReader::new(pool).get_finalized_height();
        println!(
            "Validated artifacts up to new finalized height: {}",
            new_height
        );

        if new_height < target_height {
            Err(ReplayError::ValidationIncomplete(
                new_height,
                invalid_artifacts,
            ))
        } else {
            Ok(invalid_artifacts)
        }
    }

    /// Validate the given consensus pool by moving its artifacts to the unvalidated section of a
    /// temp pool, and doing validation there.
    pub fn validate_in_tmp_pool(
        &self,
        consensus_pool: &dyn ConsensusPool,
        cup: CatchUpPackage,
        target_height: Height,
    ) -> Result<Vec<InvalidArtifact>, ReplayError> {
        let mut pool = self.get_new_unvalidated(consensus_pool, cup);
        let mut dkg = self.new_key_manager(&PoolReader::new(&pool));
        self.validate(&mut pool, &mut dkg, target_height)
    }
}
