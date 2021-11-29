use crate::backup::Backup;
use crate::{
    consensus_pool_cache::{
        get_highest_catch_up_package, get_highest_finalized_block, update_summary_block,
        ConsensusCacheImpl,
    },
    inmemory_pool::InMemoryPoolSection,
    metrics::{LABEL_POOL_TYPE, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
};
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_consensus_message::ConsensusMessageHashable;
use ic_interfaces::{
    consensus_pool::{
        ChangeAction, ChangeSet, ConsensusPool, ConsensusPoolCache, HeightIndexedPool, HeightRange,
        MutableConsensusPool, PoolSection, UnvalidatedConsensusArtifact,
        ValidatedConsensusArtifact,
    },
    gossip_pool::{ConsensusGossipPool, GossipPool},
    time_source::TimeSource,
};
use ic_logger::ReplicaLogger;
use ic_types::{
    artifact::ConsensusMessageId, consensus::catchup::CUPWithOriginalProtobuf, consensus::*,
    Height, SubnetId, Time,
};
use prometheus::{labels, opts, IntGauge};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum PoolSectionOp<T> {
    Insert(T),
    Remove(ConsensusMessageId),
    PurgeBelow(Height), // Non-inclusive
}

#[derive(Clone, Debug, Default)]
pub struct PoolSectionOps<T> {
    pub ops: Vec<PoolSectionOp<T>>,
}

impl<T> PoolSectionOps<T> {
    pub fn new() -> PoolSectionOps<T> {
        PoolSectionOps { ops: Vec::new() }
    }
    pub fn insert(&mut self, artifact: T) {
        self.ops.push(PoolSectionOp::Insert(artifact));
    }
    pub fn remove(&mut self, msg_id: ConsensusMessageId) {
        self.ops.push(PoolSectionOp::Remove(msg_id));
    }
    pub fn purge_below(&mut self, height: Height) {
        self.ops.push(PoolSectionOp::PurgeBelow(height));
    }
}

pub trait InitializablePoolSection: MutablePoolSection<ValidatedConsensusArtifact> {
    fn insert_cup_with_proto(&self, cup_with_proto: CUPWithOriginalProtobuf);
}

pub trait MutablePoolSection<T>: PoolSection<T> {
    fn mutate(&mut self, ops: PoolSectionOps<T>);
    fn pool_section(&self) -> &dyn PoolSection<T>;
}

struct PerTypeMetrics<T> {
    max_height: prometheus::IntGauge,
    min_height: prometheus::IntGauge,
    phantom: PhantomData<T>,
}

const LABEL_TYPE: &str = "type";
const LABEL_STAT: &str = "stat";

impl<T> PerTypeMetrics<T> {
    fn new(registry: &ic_metrics::MetricsRegistry, pool_portion: &str, type_name: &str) -> Self {
        const NAME: &str = "artifact_pool_consensus_height_stat";
        const HELP: &str =
            "The height of objects in a consensus pool, by pool type, object type and stat";
        Self {
            max_height: registry.register(
                IntGauge::with_opts(opts!(
                    NAME,
                    HELP,
                    labels! {LABEL_POOL_TYPE => pool_portion, LABEL_TYPE => type_name, LABEL_STAT => "max"}
                ))
                .unwrap(),
            ),
            min_height: registry.register(
                IntGauge::with_opts(opts!(
                    NAME,
                    HELP,
                    labels! {LABEL_POOL_TYPE => pool_portion, LABEL_TYPE => type_name, LABEL_STAT => "min"}
                ))
                .unwrap(),
            ),
            phantom: PhantomData,
        }
    }

    fn update_from_height_indexed_pool(&self, index: &dyn HeightIndexedPool<T>) {
        let (min, max) = index
            .height_range()
            .map_or((-1, -1), |r| (r.min.get() as i64, r.max.get() as i64));
        if min >= 0 {
            self.min_height.set(min);
        }
        if max >= 0 {
            self.max_height.set(max);
        }
    }
}

struct PoolMetrics {
    random_beacon: PerTypeMetrics<RandomBeacon>,
    random_tape: PerTypeMetrics<RandomTape>,
    finalization: PerTypeMetrics<Finalization>,
    notarization: PerTypeMetrics<Notarization>,
    catch_up_package: PerTypeMetrics<CatchUpPackage>,
    block_proposal: PerTypeMetrics<BlockProposal>,
    random_beacon_share: PerTypeMetrics<RandomBeaconShare>,
    random_tape_share: PerTypeMetrics<RandomTapeShare>,
    notarization_share: PerTypeMetrics<NotarizationShare>,
    finalization_share: PerTypeMetrics<FinalizationShare>,
    catch_up_package_share: PerTypeMetrics<CatchUpPackageShare>,
    total_size: prometheus::IntGauge,
}

impl PoolMetrics {
    fn new(registry: ic_metrics::MetricsRegistry, pool_portion: &str) -> Self {
        Self {
            random_beacon: PerTypeMetrics::new(&registry, pool_portion, "random_beacon"),
            random_tape: PerTypeMetrics::new(&registry, pool_portion, "random_tape"),
            finalization: PerTypeMetrics::new(&registry, pool_portion, "finalization"),
            notarization: PerTypeMetrics::new(&registry, pool_portion, "notarization"),
            catch_up_package: PerTypeMetrics::new(&registry, pool_portion, "catch_up_package"),
            block_proposal: PerTypeMetrics::new(&registry, pool_portion, "block_proposal"),
            random_beacon_share: PerTypeMetrics::new(
                &registry,
                pool_portion,
                "random_beacon_share",
            ),
            random_tape_share: PerTypeMetrics::new(&registry, pool_portion, "random_tape_share"),
            notarization_share: PerTypeMetrics::new(&registry, pool_portion, "notarization_share"),
            finalization_share: PerTypeMetrics::new(&registry, pool_portion, "finalization_share"),
            catch_up_package_share: PerTypeMetrics::new(
                &registry,
                pool_portion,
                "catch_up_package_share",
            ),
            total_size: registry.register(
                IntGauge::with_opts(opts!(
                    "consensus_pool_size",
                    "The total size of a consensus pool",
                    labels! {LABEL_POOL_TYPE => pool_portion}
                ))
                .unwrap(),
            ),
        }
    }

    fn update<T>(&mut self, pool_section: &dyn PoolSection<T>) {
        self.random_beacon
            .update_from_height_indexed_pool(pool_section.random_beacon());
        self.random_tape
            .update_from_height_indexed_pool(pool_section.random_tape());
        self.finalization
            .update_from_height_indexed_pool(pool_section.finalization());
        self.notarization
            .update_from_height_indexed_pool(pool_section.notarization());
        self.catch_up_package
            .update_from_height_indexed_pool(pool_section.catch_up_package());
        self.block_proposal
            .update_from_height_indexed_pool(pool_section.block_proposal());
        self.random_beacon_share
            .update_from_height_indexed_pool(pool_section.random_beacon_share());
        self.random_tape_share
            .update_from_height_indexed_pool(pool_section.random_tape_share());
        self.notarization_share
            .update_from_height_indexed_pool(pool_section.notarization_share());
        self.finalization_share
            .update_from_height_indexed_pool(pool_section.finalization_share());
        self.catch_up_package_share
            .update_from_height_indexed_pool(pool_section.catch_up_package_share());
        self.total_size.set(pool_section.size() as i64)
    }
}

pub struct ConsensusPoolImpl {
    validated: Box<dyn InitializablePoolSection + Send + Sync>,
    unvalidated: Box<dyn MutablePoolSection<UnvalidatedConsensusArtifact> + Send + Sync>,
    validated_metrics: PoolMetrics,
    unvalidated_metrics: PoolMetrics,
    cache: Arc<ConsensusCacheImpl>,
    backup: Option<Backup>,
}

// A temporary pool implementation used for genesis initialization.
pub struct UncachedConsensusPoolImpl {
    pub validated: Box<dyn InitializablePoolSection + Send + Sync>,
    unvalidated: Box<dyn MutablePoolSection<UnvalidatedConsensusArtifact> + Send + Sync>,
}

impl UncachedConsensusPoolImpl {
    pub fn new(config: ArtifactPoolConfig, log: ReplicaLogger) -> UncachedConsensusPoolImpl {
        let validated = match config.persistent_pool_backend {
            PersistentPoolBackend::Lmdb(lmdb_config) => Box::new(
                crate::lmdb_pool::PersistentHeightIndexedPool::new_consensus_pool(
                    lmdb_config,
                    config.persistent_pool_read_only,
                    log.clone(),
                ),
            ) as Box<_>,
            #[cfg(feature = "rocksdb_backend")]
            PersistentPoolBackend::RocksDB(config) => Box::new(
                crate::rocksdb_pool::PersistentHeightIndexedPool::new_consensus_pool(
                    config,
                    log.clone(),
                ),
            ) as Box<_>,
            #[allow(unreachable_patterns)]
            cfg => {
                unimplemented!("Configuration {:?} is not supported", cfg)
            }
        };

        UncachedConsensusPoolImpl {
            validated,
            unvalidated: Box::new(InMemoryPoolSection::new(log)),
        }
    }
}

impl ConsensusPoolCache for UncachedConsensusPoolImpl {
    fn finalized_block(&self) -> Block {
        get_highest_finalized_block(self, &self.catch_up_package())
    }

    fn consensus_time(&self) -> Option<Time> {
        let block = self.finalized_block();
        if block.height() == Height::from(0) {
            None
        } else {
            Some(block.context.time)
        }
    }

    fn catch_up_package(&self) -> CatchUpPackage {
        get_highest_catch_up_package(self).cup
    }

    fn cup_with_protobuf(&self) -> CUPWithOriginalProtobuf {
        get_highest_catch_up_package(self)
    }

    fn summary_block(&self) -> Block {
        let finalized_block = get_highest_finalized_block(self, &self.catch_up_package());
        let mut summary_block = self.catch_up_package().content.block.into_inner();
        update_summary_block(self, &mut summary_block, &finalized_block);
        summary_block
    }
}

impl ConsensusPool for UncachedConsensusPoolImpl {
    fn validated(&self) -> &dyn PoolSection<ValidatedConsensusArtifact> {
        self.validated.pool_section()
    }

    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedConsensusArtifact> {
        self.unvalidated.pool_section()
    }

    fn as_cache(&self) -> &dyn ConsensusPoolCache {
        self
    }
}

impl ConsensusPoolImpl {
    /// Create a consensus pool from a given `config`, and initialize it with
    /// the given `catch_up_package`. If a catch-up package already exists in
    /// the validated pool, the one that is greater (with respect to
    /// height and registry version) will be used.
    pub fn new(
        subnet_id: SubnetId,
        catch_up_package: CUPWithOriginalProtobuf,
        config: ArtifactPoolConfig,
        registry: ic_metrics::MetricsRegistry,
        log: ReplicaLogger,
    ) -> ConsensusPoolImpl {
        let mut pool = UncachedConsensusPoolImpl::new(config.clone(), log.clone());
        Self::init_genesis(catch_up_package, pool.validated.as_mut());
        let mut pool = Self::from_uncached(pool, registry.clone());
        // If the back up directory is set, instantiate the backup component
        // and create a subdirectory with the subnet id as directory name.
        pool.backup = config.backup_config.map(|config| {
            Backup::new(
                &pool,
                config.spool_path.clone(),
                config
                    .spool_path
                    .join(subnet_id.to_string())
                    .join(ic_types::ReplicaVersion::default().to_string()),
                Duration::from_secs(config.retention_time_secs),
                Duration::from_secs(config.purging_interval_secs),
                registry,
                log,
            )
        });

        // Initial update to the metrics, such that they always report the state, even
        // when a subnet is halted.
        pool.validated_metrics.update(pool.validated.pool_section());
        pool.unvalidated_metrics
            .update(pool.unvalidated.pool_section());
        pool
    }

    fn init_genesis(cup: CUPWithOriginalProtobuf, pool_section: &mut dyn InitializablePoolSection) {
        let should_insert = match pool_section.catch_up_package().get_highest() {
            Ok(existing) => CatchUpPackageParam::from(&cup) > CatchUpPackageParam::from(&existing),
            Err(_) => true,
        };

        if should_insert {
            let mut ops = PoolSectionOps::new();
            ops.insert(ValidatedConsensusArtifact {
                msg: cup
                    .cup
                    .content
                    .random_beacon
                    .as_ref()
                    .clone()
                    .into_message(),
                timestamp: cup.cup.content.block.as_ref().context.time,
            });
            pool_section.mutate(ops);
            pool_section.insert_cup_with_proto(cup);
        }
    }

    /// Can be used to instantiate an empty pool without a CUP.
    pub fn from_uncached(
        uncached: UncachedConsensusPoolImpl,
        registry: ic_metrics::MetricsRegistry,
    ) -> ConsensusPoolImpl {
        let cache = Arc::new(ConsensusCacheImpl::new(&uncached));
        ConsensusPoolImpl {
            validated: uncached.validated,
            unvalidated: uncached.unvalidated,
            validated_metrics: PoolMetrics::new(registry.clone(), POOL_TYPE_VALIDATED),
            unvalidated_metrics: PoolMetrics::new(registry, POOL_TYPE_UNVALIDATED),
            cache,
            backup: None,
        }
    }

    pub fn new_from_cup_without_bytes(
        subnet_id: SubnetId,
        catch_up_package: CatchUpPackage,
        config: ArtifactPoolConfig,
        registry: ic_metrics::MetricsRegistry,
        log: ReplicaLogger,
    ) -> ConsensusPoolImpl {
        Self::new(
            subnet_id,
            CUPWithOriginalProtobuf::from_cup(catch_up_package),
            config,
            registry,
            log,
        )
    }

    /// Get a copy of ConsensusPoolCache.
    pub fn get_cache(&self) -> Arc<dyn ConsensusPoolCache> {
        Arc::clone(&self.cache) as Arc<_>
    }

    fn apply_changes_validated(&mut self, ops: PoolSectionOps<ValidatedConsensusArtifact>) {
        if !ops.ops.is_empty() {
            self.validated.mutate(ops);
            self.validated_metrics.update(self.validated.pool_section());
        }
    }

    fn apply_changes_unvalidated(&mut self, ops: PoolSectionOps<UnvalidatedConsensusArtifact>) {
        if !ops.ops.is_empty() {
            self.unvalidated.mutate(ops);
            self.unvalidated_metrics
                .update(self.unvalidated.pool_section());
        }
    }
}

impl ConsensusPool for ConsensusPoolImpl {
    fn validated(&self) -> &dyn PoolSection<ValidatedConsensusArtifact> {
        self.validated.pool_section()
    }

    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedConsensusArtifact> {
        self.unvalidated.pool_section()
    }

    fn as_cache(&self) -> &dyn ConsensusPoolCache {
        self.cache.as_ref()
    }
}

impl MutableConsensusPool for ConsensusPoolImpl {
    fn insert(&mut self, unvalidated_artifact: UnvalidatedConsensusArtifact) {
        let mut ops = PoolSectionOps::new();
        ops.insert(unvalidated_artifact);
        self.apply_changes_unvalidated(ops);
    }

    fn apply_changes(&mut self, time_source: &dyn TimeSource, change_set: ChangeSet) {
        let updates = self.cache.prepare(&change_set);
        let mut unvalidated_ops = PoolSectionOps::new();
        let mut validated_ops = PoolSectionOps::new();

        // DO NOT Add a default nop. Explicitly mention all cases.
        // This helps with keeping this readable and obvious what
        // change is causing tests to break.
        for change_action in change_set {
            match change_action {
                ChangeAction::AddToValidated(to_add) => {
                    validated_ops.insert(ValidatedConsensusArtifact {
                        msg: to_add,
                        timestamp: time_source.get_relative_time(),
                    });
                }
                ChangeAction::MoveToValidated(to_move) => {
                    let msg_id = to_move.get_id();
                    let timestamp = self.unvalidated.get_timestamp(&msg_id).unwrap_or_else(|| {
                        panic!("Timestmap is not found for MoveToValidated: {:?}", to_move)
                    });
                    unvalidated_ops.remove(msg_id);
                    validated_ops.insert(ValidatedConsensusArtifact {
                        msg: to_move,
                        timestamp,
                    });
                }
                ChangeAction::RemoveFromValidated(to_remove) => {
                    validated_ops.remove(to_remove.get_id());
                }
                ChangeAction::RemoveFromUnvalidated(to_remove) => {
                    unvalidated_ops.remove(to_remove.get_id());
                }
                ChangeAction::PurgeValidatedBelow(height) => {
                    validated_ops.purge_below(height);
                }
                ChangeAction::PurgeUnvalidatedBelow(height) => {
                    unvalidated_ops.purge_below(height);
                }
                ChangeAction::HandleInvalid(to_remove, _) => {
                    unvalidated_ops.remove(to_remove.get_id());
                }
            }
        }

        let artifacts_for_backup = validated_ops
            .ops
            .iter()
            .filter_map(|op| match op {
                PoolSectionOp::Insert(artifact) => Some(artifact.msg.clone()),
                _ => None,
            })
            .collect();
        self.apply_changes_unvalidated(unvalidated_ops);
        self.apply_changes_validated(validated_ops);
        if let Some(backup) = &self.backup {
            backup.store(time_source, artifacts_for_backup);
        }
        if !updates.is_empty() {
            self.cache.update(self, updates);
        }
    }
}

impl GossipPool<ConsensusMessage, ChangeSet> for ConsensusPoolImpl {
    type MessageId = ConsensusMessageId;
    type Filter = Height;

    fn contains(&self, id: &ConsensusMessageId) -> bool {
        self.unvalidated.contains(id) || self.validated.contains(id)
    }

    fn get_validated_by_identifier(&self, id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        self.validated.get(id)
    }

    // Return an iterator of all artifacts that is required to make progress
    // above the given height filter.
    fn get_all_validated_by_filter(
        &self,
        filter: Self::Filter,
    ) -> Box<dyn Iterator<Item = ConsensusMessage> + '_> {
        let max_catch_up_height = self
            .validated
            .catch_up_package()
            .height_range()
            .map(|x| x.max)
            .unwrap();
        // Since random beacon of previous height is required, min_random_beacon_height
        // should be one less than the normal min height.
        let min_random_beacon_height = max_catch_up_height.max(filter);
        let min = min_random_beacon_height.increment();
        let max_finalized_height = self
            .validated
            .finalization()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        let min_finalized_height = min;
        let max_finalized_share_height = self
            .validated
            .finalization_share()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        let min_finalized_share_height = max_finalized_height.increment();
        let max_notarization_height = self
            .validated
            .notarization()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        let min_notarization_height = min;
        let max_notarization_share_height = self
            .validated
            .notarization_share()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        let min_notarization_share_height = max_notarization_height.increment();
        let max_random_beacon_height = self
            .validated
            .random_beacon()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min_random_beacon_height);
        let max_random_beacon_share_height = self
            .validated
            .random_beacon_share()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        let min_random_beacon_share_height = max_random_beacon_height.increment();
        let max_block_proposal_height = self
            .validated
            .block_proposal()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        let min_block_proposal_height = min;

        // Because random tape & shares do not come in a consecutive sequence, we
        // compute a custom iterator through their height range to either return
        // a random tape if it is found, or the set of shares when the tape is
        // not found.
        let max_random_tape_height = self
            .validated
            .random_tape()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        let min_random_tape_height = min;
        let max_random_tape_share_height = self
            .validated
            .random_tape_share()
            .height_range()
            .map(|x| x.max)
            .unwrap_or(min);
        // Compute a combined range
        let tape_range = min_random_tape_height.get()
            ..=max_random_tape_height
                .max(max_random_tape_share_height)
                .get();
        let random_tapes = tape_range
            .clone()
            .map(move |h| self.validated.random_tape().get_by_height(Height::from(h)));
        let random_tape_shares = tape_range.map(move |h| {
            self.validated
                .random_tape_share()
                .get_by_height(Height::from(h))
        });
        let random_tape_iterator =
            random_tapes
                .zip(random_tape_shares)
                .flat_map(|(mut tape, shares)| {
                    tape.next().map_or_else(
                        || shares.map(|x| x.into_message()).collect::<Vec<_>>(),
                        |x| vec![x.into_message()],
                    )
                });

        Box::new(
            self.validated
                .catch_up_package()
                .get_by_height_range(HeightRange {
                    min: max_catch_up_height.max(filter),
                    max: max_catch_up_height,
                })
                .map(|x| x.into_message())
                .chain(
                    self.validated
                        .finalization()
                        .get_by_height_range(HeightRange {
                            min: min_finalized_height,
                            max: max_finalized_height,
                        })
                        .map(|x| x.into_message()),
                )
                .chain(
                    self.validated
                        .finalization_share()
                        .get_by_height_range(HeightRange {
                            min: min_finalized_share_height,
                            max: max_finalized_share_height,
                        })
                        .map(|x| x.into_message()),
                )
                .chain(
                    self.validated
                        .notarization()
                        .get_by_height_range(HeightRange {
                            min: min_notarization_height,
                            max: max_notarization_height,
                        })
                        .map(|x| x.into_message()),
                )
                .chain(
                    self.validated
                        .notarization_share()
                        .get_by_height_range(HeightRange {
                            min: min_notarization_share_height,
                            max: max_notarization_share_height,
                        })
                        .map(|x| x.into_message()),
                )
                .chain(
                    self.validated
                        .random_beacon()
                        .get_by_height_range(HeightRange {
                            min: min_random_beacon_height,
                            max: max_random_beacon_height,
                        })
                        .map(|x| x.into_message()),
                )
                .chain(
                    self.validated
                        .random_beacon_share()
                        .get_by_height_range(HeightRange {
                            min: min_random_beacon_share_height,
                            max: max_random_beacon_share_height,
                        })
                        .map(|x| x.into_message()),
                )
                .chain(
                    self.validated
                        .block_proposal()
                        .get_by_height_range(HeightRange {
                            min: min_block_proposal_height,
                            max: max_block_proposal_height,
                        })
                        .map(|x| x.into_message()),
                )
                .chain(random_tape_iterator),
        )
    }
}

impl ConsensusGossipPool for ConsensusPoolImpl {}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces::artifact_pool::UnvalidatedArtifact;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::types::v1 as pb;
    use ic_test_utilities::{
        consensus::{fake::*, make_genesis},
        mock_time,
        types::ids::{node_test_id, subnet_test_id},
        FastForwardTimeSource,
    };
    use ic_types::{
        batch::ValidationContext,
        consensus::{BlockProposal, RandomBeacon},
        crypto::{CryptoHash, CryptoHashOf},
        RegistryVersion,
    };
    use prost::Message;
    use std::{convert::TryFrom, fs, io::Read, time::Instant};

    #[test]
    fn test_timestamp() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let time_0 = time_source.get_relative_time();
            let mut pool = ConsensusPoolImpl::new_from_cup_without_bytes(
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
            );

            let mut random_beacon = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(0),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ));
            let msg_0 = random_beacon.clone().into_message();
            let msg_id_0 = random_beacon.get_id();
            random_beacon.content.height = Height::from(1);
            let msg_1 = random_beacon.clone().into_message();
            let msg_id_1 = random_beacon.get_id();

            pool.insert(UnvalidatedArtifact {
                message: msg_0.clone(),
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });

            let time_1 = time_0 + Duration::from_secs(100);
            time_source.set_time(time_1).unwrap();

            pool.insert(UnvalidatedArtifact {
                message: msg_1.clone(),
                peer_id: node_test_id(1),
                timestamp: time_source.get_relative_time(),
            });

            // Check timestamp is the insertion time.
            assert_eq!(pool.unvalidated().get_timestamp(&msg_id_0), Some(time_0));
            assert_eq!(pool.unvalidated().get_timestamp(&msg_id_1), Some(time_1));

            let changeset = vec![
                ChangeAction::MoveToValidated(msg_0),
                ChangeAction::RemoveFromUnvalidated(msg_1),
            ];
            pool.apply_changes(time_source.as_ref(), changeset);

            // Check timestamp is carried over for msg_0.
            assert_eq!(pool.unvalidated().get_timestamp(&msg_id_0), None);
            assert_eq!(pool.validated().get_timestamp(&msg_id_0), Some(time_0));

            // Check timestamp is removed for msg_1.
            assert_eq!(pool.unvalidated().get_timestamp(&msg_id_1), None);
            assert_eq!(pool.validated().get_timestamp(&msg_id_1), None);
        })
    }

    #[test]
    // We create multiple artifacts for multiple heights, check that all of them are
    // written to the disk and can be restored.
    fn test_backup() {
        use crate::backup::bytes_to_hex_str;

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let backup_dir = tempfile::Builder::new().tempdir().unwrap();
            let subnet_id = subnet_test_id(0);
            let root_path = backup_dir
                .path()
                .join(subnet_id.to_string())
                .join(ic_types::ReplicaVersion::default().to_string());
            let mut pool = ConsensusPoolImpl::new_from_cup_without_bytes(
                subnet_id,
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
            );

            let purging_interval = Duration::from_millis(100);
            pool.backup = Some(Backup::new(
                &pool,
                backup_dir.path().into(),
                root_path.clone(),
                // We purge all artifacts older than 5ms millisecond.
                Duration::from_millis(100),
                // We purge every 5 milliseconds.
                purging_interval,
                MetricsRegistry::new(),
                no_op_logger(),
            ));

            // All tests in this group work on artifacts inside the same group, so we extend
            // the path with it.
            let path = root_path.join("0");

            let random_beacon = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(1),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ));
            let random_tape = RandomTape::fake(RandomTapeContent::new(Height::from(2)));
            let notarization = Notarization::fake(NotarizationContent::new(
                Height::from(2),
                CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
            ));
            let finalization = Finalization::fake(FinalizationContent::new(
                Height::from(3),
                CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
            ));
            let proposal = BlockProposal::fake(
                Block::new(
                    CryptoHashOf::from(CryptoHash(Vec::new())),
                    Payload::new(
                        ic_crypto::crypto_hash,
                        ic_types::consensus::dkg::Summary::fake().into(),
                    ),
                    Height::from(4),
                    Rank(456),
                    ValidationContext {
                        registry_version: RegistryVersion::from(99),
                        certified_height: Height::from(42),
                        time: mock_time(),
                    },
                ),
                node_test_id(333),
            );

            let genesis_cup = make_genesis(ic_types::consensus::dkg::Summary::fake());
            let mut cup = genesis_cup.clone();
            cup.content.random_beacon = hashed::Hashed::new(
                ic_crypto::crypto_hash,
                RandomBeacon::fake(RandomBeaconContent::new(
                    Height::from(4),
                    CryptoHashOf::from(CryptoHash(Vec::new())),
                )),
            );

            let changeset = vec![
                random_beacon.clone().into_message(),
                random_tape.clone().into_message(),
                finalization.clone().into_message(),
                notarization.clone().into_message(),
                proposal.clone().into_message(),
                cup.clone().into_message(),
            ]
            .into_iter()
            .map(ChangeAction::AddToValidated)
            .collect();

            pool.apply_changes(time_source.as_ref(), changeset);
            // We sync the backup before checking the asserts to make sure all backups have
            // been written.
            pool.backup.as_ref().unwrap().sync_backup();

            // Check backup for height 0
            assert!(
                path.join("0").join("catch_up_package.bin").exists(),
                "catch-up package at height 0 was backed up"
            );
            assert!(
                path.join("0").join("random_beacon.bin").exists(),
                "random beacon at height 0 was backed up"
            );
            assert_eq!(
                fs::read_dir(path.join("0")).unwrap().count(),
                2,
                "two artifacts for height 0 were backed up"
            );
            let mut file = fs::File::open(path.join("0").join("catch_up_package.bin")).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                CatchUpPackage::try_from(&pb::CatchUpPackage::decode(buffer.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(
                genesis_cup, restored,
                "restored catch-up package is identical with the original one"
            );

            // Check backup for height 1
            assert!(
                path.join("1").join("random_beacon.bin").exists(),
                "random beacon at height 1 was backed up"
            );
            assert_eq!(
                fs::read_dir(path.join("1")).unwrap().count(),
                1,
                "only one artifact for height 1 was backed up"
            );
            let mut file = fs::File::open(path.join("1").join("random_beacon.bin")).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                RandomBeacon::try_from(pb::RandomBeacon::decode(buffer.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(
                random_beacon, restored,
                "restored random beacon is identical with the original one"
            );

            let notarization_path = path.join("2").join(format!(
                "notarization_{}_{}.bin",
                bytes_to_hex_str(&notarization.content.block),
                bytes_to_hex_str(&ic_crypto::crypto_hash(&notarization)),
            ));
            assert!(
                path.join("2").join("random_tape.bin").exists(),
                "random tape at height 2 was backed up"
            );
            assert!(
                notarization_path.exists(),
                "notarization at height 2 was backed up"
            );
            assert_eq!(
                fs::read_dir(path.join("2")).unwrap().count(),
                2,
                "only two artifacts for height 2 were backed up"
            );
            let mut file = fs::File::open(path.join("2").join("random_tape.bin")).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                RandomTape::try_from(pb::RandomTape::decode(buffer.as_slice()).unwrap()).unwrap();
            assert_eq!(
                random_tape, restored,
                "restored random tape is identical with the original one"
            );
            let mut file = fs::File::open(notarization_path).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                Notarization::try_from(pb::Notarization::decode(buffer.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(
                notarization, restored,
                "restored notarization is identical with the original one"
            );

            // Check backup for height 3
            let finalization_path = path.join("3").join(format!(
                "finalization_{}_{}.bin",
                bytes_to_hex_str(&finalization.content.block),
                bytes_to_hex_str(&ic_crypto::crypto_hash(&finalization)),
            ));
            assert!(
                finalization_path.exists(),
                "finalization at height 3 was backed up",
            );
            assert_eq!(
                fs::read_dir(path.join("3")).unwrap().count(),
                1,
                "only one artifact for height 3 was backed up"
            );
            let mut file = fs::File::open(path.join("3").join(finalization_path)).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                Finalization::try_from(pb::Finalization::decode(buffer.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(
                finalization, restored,
                "restored finalization is identical with the original one"
            );

            // Check backup for height 4
            let proposal_path = path.join("4").join(format!(
                "block_proposal_{}_{}.bin",
                bytes_to_hex_str(proposal.content.get_hash()),
                bytes_to_hex_str(&ic_crypto::crypto_hash(&proposal)),
            ));
            assert!(
                path.join("4").join("catch_up_package.bin").exists(),
                "catch-up package at height 4 was backed up"
            );
            assert!(
                proposal_path.exists(),
                "block proposal at height 4 was backed up"
            );
            assert_eq!(
                fs::read_dir(path.join("4")).unwrap().count(),
                2,
                "two artifacts for height 4 were backed up"
            );
            let mut file = fs::File::open(path.join("4").join("catch_up_package.bin")).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                CatchUpPackage::try_from(&pb::CatchUpPackage::decode(buffer.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(
                cup, restored,
                "restored catch-up package is identical with the original one"
            );

            let mut file = fs::File::open(proposal_path).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                BlockProposal::try_from(pb::BlockProposal::decode(buffer.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(
                proposal, restored,
                "restored catch-up package is identical with the original one"
            );

            // Now we fast-forward the time for purging being definitely overdue.
            std::thread::sleep(purging_interval);
            time_source
                .set_time(time_source.get_relative_time() + purging_interval)
                .unwrap();
            pool.apply_changes(time_source.as_ref(), Vec::new());
            pool.backup.as_ref().unwrap().sync_purging();

            // Make sure the subnet directory is empty, as we purged everything.
            assert_eq!(fs::read_dir(&path).unwrap().count(), 0);

            // We sleep for ont interval more and make sure we also delete the subnet
            // directory
            let sleep_time = 2 * purging_interval;
            std::thread::sleep(sleep_time);
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();
            pool.apply_changes(time_source.as_ref(), Vec::new());
            pool.backup.as_ref().unwrap().sync_purging();
            assert!(!path.exists());
        })
    }

    #[test]
    #[ignore]
    fn test_backup_purging() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let backup_dir = tempfile::Builder::new().tempdir().unwrap();
            let subnet_id = subnet_test_id(0);
            let path = backup_dir.path().join(format!("{:?}", subnet_id));
            let mut pool = ConsensusPoolImpl::new_from_cup_without_bytes(
                subnet_id,
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
            );

            // NOTE: Unfortunately, this test can not trivially be made walltime
            // independend. We are tracking the time this test takes, to provide some
            // context, should the test fail.
            let test_start_time = Instant::now();
            let mut next_wakeup_time = test_start_time;

            let purging_interval = Duration::from_millis(3000);
            pool.backup = Some(Backup::new(
                &pool,
                backup_dir.path().into(),
                backup_dir.path().join(format!("{:?}", subnet_id)),
                // Artifact retention time
                Duration::from_millis(2700),
                purging_interval,
                MetricsRegistry::new(),
                no_op_logger(),
            ));

            let random_beacon = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(1),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ));
            let random_tape = RandomTape::fake(RandomTapeContent::new(Height::from(2)));
            let notarization = Notarization::fake(NotarizationContent::new(
                Height::from(3),
                CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
            ));
            let proposal = BlockProposal::fake(
                Block::new(
                    CryptoHashOf::from(CryptoHash(Vec::new())),
                    Payload::new(
                        ic_crypto::crypto_hash,
                        ic_types::consensus::dkg::Summary::fake().into(),
                    ),
                    Height::from(4),
                    Rank(456),
                    ValidationContext {
                        registry_version: RegistryVersion::from(99),
                        certified_height: Height::from(42),
                        time: mock_time(),
                    },
                ),
                node_test_id(333),
            );

            let changeset = vec![random_beacon.into_message(), random_tape.into_message()]
                .into_iter()
                .map(ChangeAction::AddToValidated)
                .collect();

            // Apply changes
            pool.apply_changes(time_source.as_ref(), changeset);
            // sync
            pool.backup.as_ref().unwrap().sync_backup();

            let group_path = &path.join("0");
            // We expect 3 folders for heights 0 to 2.
            assert_eq!(fs::read_dir(&group_path).unwrap().count(), 3);

            // Let's sleep so that the previous heights are close to being purged.
            let sleep_time = purging_interval / 10 * 8;
            next_wakeup_time += sleep_time;
            sleep_until(next_wakeup_time, test_start_time);
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();

            // Now add new artifacts
            let changeset = vec![notarization.into_message(), proposal.into_message()]
                .into_iter()
                .map(ChangeAction::AddToValidated)
                .collect();

            pool.apply_changes(time_source.as_ref(), changeset);
            // sync
            pool.backup.as_ref().unwrap().sync_backup();

            // We expect 5 folders for heights 0 to 4.
            assert_eq!(fs::read_dir(&group_path).unwrap().count(), 5);

            // We sleep just enough so that purging is overdue and the oldest artifacts are
            // approximately 1 purging interval old.
            let sleep_time = purging_interval / 10 * 3;
            next_wakeup_time += sleep_time;
            sleep_until(next_wakeup_time, test_start_time);
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();

            // Trigger the purging.
            pool.apply_changes(time_source.as_ref(), Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            // We expect only 2 folders to survive the purging: 3, 4
            assert_eq!(fs::read_dir(&group_path).unwrap().count(), 2);
            assert!(group_path.join("3").exists());
            assert!(group_path.join("4").exists());

            let sleep_time = purging_interval + purging_interval / 10 * 3;
            next_wakeup_time += sleep_time;
            sleep_until(next_wakeup_time, test_start_time);

            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();

            // Trigger the purging.
            pool.apply_changes(time_source.as_ref(), Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            // We deleted all artifacts, but the group folder was updated by this and needs
            // to age now.
            assert!(group_path.exists());
            assert_eq!(fs::read_dir(&group_path).unwrap().count(), 0);

            let sleep_time = purging_interval + purging_interval / 10 * 3;
            next_wakeup_time += sleep_time;
            sleep_until(next_wakeup_time, test_start_time);
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();

            // Trigger the purging.
            pool.apply_changes(time_source.as_ref(), Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            //print_time_elapsed(&test_start_time, &(purging_interval / 10 * 37));
            // The group folder expired and was deleted.
            assert!(!group_path.exists());
            assert_eq!(fs::read_dir(&path).unwrap().count(), 0);

            // We wait more and make sure the subnet folder is purged.
            let sleep_time = purging_interval + purging_interval / 10 * 3;
            next_wakeup_time += sleep_time;
            sleep_until(next_wakeup_time, test_start_time);
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();

            // Trigger the purging.
            pool.apply_changes(time_source.as_ref(), Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            // The subnet_id folder expired and was deleted.
            assert!(!path.exists());
            assert_eq!(fs::read_dir(&backup_dir).unwrap().count(), 0);
        })
    }

    fn sleep_until(time: Instant, test_start_time: Instant) {
        let now = Instant::now();

        if now < time {
            let sleep_time = time.duration_since(now);
            std::thread::sleep(sleep_time);
        }

        let now = Instant::now();
        println!(
            "Runtime: {:?} ms, expected: {:?} ms",
            now.duration_since(test_start_time).as_millis(),
            time.duration_since(test_start_time).as_millis()
        );
    }
}
