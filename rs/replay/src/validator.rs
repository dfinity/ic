use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use ic_artifact_pool::{consensus_pool::ConsensusPoolImpl, dkg_pool::DkgPoolImpl};
use ic_config::{artifact_pool::ArtifactPoolConfig, Config};
use ic_consensus::{
    certification::CertificationCrypto,
    consensus::{dkg_key_manager::DkgKeyManager, validator::Validator, ValidatorMetrics},
};
use ic_consensus_utils::{
    active_high_threshold_nidkg_id, crypto::ConsensusCrypto, membership::Membership,
    pool_reader::PoolReader, registry_version_at_height,
};
use ic_interfaces::{
    certification::Verifier,
    consensus_pool::{ChangeAction, ConsensusPool, ConsensusPoolCache, HeightIndexedPool},
    messaging::MessageRouting,
    p2p::consensus::{MutablePool, UnvalidatedArtifact},
    time_source::{SysTimeSource, TimeSource},
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::types::v1 as pb;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::ConsensusMessageId,
    consensus::{
        certification::{Certification, CertificationShare},
        Block, ConsensusMessage, ConsensusMessageHash, ConsensusMessageHashable, HasBlockHash,
        HasCommittee,
    },
    crypto::CryptoHashOf,
    replica_config::ReplicaConfig,
    Height, NodeId, PrincipalId, SubnetId,
};
use serde::{Deserialize, Serialize};

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
    verifier: Arc<dyn Verifier>,
    membership: Arc<Membership>,
    pool_cache: Arc<dyn ConsensusPoolCache>,
    consensus_crypto: Arc<dyn ConsensusCrypto>,
    certification_crypto: Arc<dyn CertificationCrypto>,
    metrics_registry: MetricsRegistry,
    registry: Arc<dyn RegistryClient>,
    log: ReplicaLogger,
    time_source: Arc<dyn TimeSource>,
}

impl ReplayValidator {
    pub fn new(
        cfg: Config,
        subnet_id: SubnetId,
        consensus_crypto: Arc<dyn ConsensusCrypto>,
        certification_crypto: Arc<dyn CertificationCrypto>,
        verifier: Arc<dyn Verifier>,
        pool_cache: Arc<dyn ConsensusPoolCache>,
        registry: Arc<dyn RegistryClient>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        message_routing: Arc<dyn MessageRouting>,
        log: ReplicaLogger,
    ) -> Self {
        let metrics_registry = MetricsRegistry::new();
        let membership = Arc::new(Membership::new(
            pool_cache.clone(),
            registry.clone(),
            subnet_id,
        ));
        let time_source = Arc::new(SysTimeSource::new());
        let dkg_pool = RwLock::new(DkgPoolImpl::new(metrics_registry.clone(), log.clone()));
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));
        let replica_cfg = ReplicaConfig::new(node_id, subnet_id);

        let validator = Validator::new(
            replica_cfg.clone(),
            membership.clone(),
            registry.clone(),
            consensus_crypto.clone(),
            Arc::new(MockPayloadBuilder {}) as Arc<_>,
            state_manager,
            message_routing,
            Arc::new(dkg_pool) as Arc<_>,
            log.clone(),
            ValidatorMetrics::new(metrics_registry.clone()),
            time_source.clone(),
            /*ingress_selector=*/ None,
        );

        Self {
            cfg,
            replica_cfg,
            validator,
            verifier,
            membership,
            registry,
            pool_cache,
            consensus_crypto,
            certification_crypto,
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
            self.consensus_crypto.clone(),
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
    fn get_new_unvalidated(
        &self,
        consensus_pool: &dyn ConsensusPool,
        cup: pb::CatchUpPackage,
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
        let mut pool = ConsensusPoolImpl::new(
            self.replica_cfg.node_id,
            self.replica_cfg.subnet_id,
            cup,
            artifact_pool_config,
            MetricsRegistry::new(),
            self.log.clone(),
            self.time_source.clone(),
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

    /// Verify the given certification against the state of the registry version at that height.
    /// We do not verify that the certification contains the same state hash as our local one.
    /// We treat transient errors as permanent.
    pub fn verify_certification(&self, certification: &Certification) -> Result<(), String> {
        let registry_version =
            registry_version_at_height(self.pool_cache.as_ref(), certification.height)
                .unwrap_or_else(|| self.registry.get_latest_version());

        self.verifier
            .validate(self.replica_cfg.subnet_id, certification, registry_version)
            .map_err(|e| format!("{:?}", e))
    }

    /// Verify the given certification share against the membership defined by the local consensus pool cache
    /// We do not verify that the certification contains the same state hash as our local one.
    /// We treat transient errors as permanent.
    pub fn verify_share(&self, share: &CertificationShare) -> Result<(), String> {
        let signer = share.signed.signature.signer;
        match self.membership.node_belongs_to_threshold_committee(
            signer,
            share.height,
            Certification::committee(),
        ) {
            // In case of an error, we simply skip this artifact.
            Err(e) => Err(format!("Failed to determine membership: {:?}", e)),
            // If the signer does not belong to the signers committee at the
            // given height, reject this artifact.
            Ok(false) => Err("Signer does not belong to committee.".into()),
            // The signer is valid.
            Ok(true) => {
                // Verify the signature.
                let dkg_id = active_high_threshold_nidkg_id(self.pool_cache.as_ref(), share.height)
                    .ok_or_else(|| "Failed to get active transcript.".to_string())?;
                self.certification_crypto
                    .verify(&share.signed, dkg_id)
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// Validate the given consensus pool and apply resulting changes, until no more changes are found.
    /// Discovered invalid artifacts are returned. An error is returned if validation stops before the
    /// target finalized height is reached.
    pub fn validate(
        &self,
        pool: &mut ConsensusPoolImpl,
        expected: &mut HashMap<ConsensusMessageHash, PathBuf>,
        dkg: &mut DkgKeyManager,
        target_height: Height,
    ) -> Result<Vec<InvalidArtifact>, ReplayError> {
        let validator = self.get_validator();

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
                ChangeAction::MoveToValidated(a) => {
                    let hash = a.get_cm_hash();
                    expected.remove(&hash);
                }
                other => {
                    println!("Unexpected change action: {:?}", other);
                }
            });

            if changes.is_empty() {
                break;
            } else {
                pool.apply_changes(changes);
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
    pub(crate) fn validate_in_tmp_pool(
        &self,
        consensus_pool: &dyn ConsensusPool,
        cup: pb::CatchUpPackage,
        target_height: Height,
    ) -> Result<Vec<InvalidArtifact>, ReplayError> {
        let mut pool = self.get_new_unvalidated(consensus_pool, cup);
        let mut dkg = self.new_key_manager(&PoolReader::new(&pool));
        self.validate(&mut pool, &mut HashMap::new(), &mut dkg, target_height)
    }
}
