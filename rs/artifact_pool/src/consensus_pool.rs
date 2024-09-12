use crate::backup::Backup;
use crate::height_index::HeightIndexedInstants;
use crate::{
    consensus_pool_cache::{
        get_highest_finalized_block, update_summary_block, ConsensusBlockChainImpl,
        ConsensusCacheImpl,
    },
    inmemory_pool::InMemoryPoolSection,
    metrics::{LABEL_POOL_TYPE, POOL_TYPE_UNVALIDATED, POOL_TYPE_VALIDATED},
};
use ic_config::artifact_pool::{ArtifactPoolConfig, PersistentPoolBackend};
use ic_interfaces::p2p::consensus::ArtifactWithOpt;
use ic_interfaces::{
    consensus_pool::{
        ChangeAction, ConsensusBlockCache, ConsensusBlockChain, ConsensusPool, ConsensusPoolCache,
        ConsensusTime, HeightIndexedPool, HeightRange, Mutations, PoolSection,
        PurgeableArtifactType, UnvalidatedConsensusArtifact, ValidatedConsensusArtifact,
    },
    p2p::consensus::{ArtifactTransmit, ArtifactTransmits, MutablePool, ValidatedPoolReader},
    time_source::TimeSource,
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::buckets::linear_buckets;
use ic_protobuf::types::v1 as pb;
use ic_types::crypto::CryptoHashOf;
use ic_types::NodeId;
use ic_types::{artifact::ConsensusMessageId, consensus::*, Height, SubnetId, Time};
use prometheus::{histogram_opts, labels, opts, Histogram, IntCounter, IntGauge};
use std::time::Instant;
use std::{marker::PhantomData, sync::Arc, time::Duration};

#[derive(Clone, Debug)]
pub enum PoolSectionOp<T> {
    /// Insert the artifact into the pool section.
    Insert(T),
    /// Remove the artifact with the given [`ConsensusMessageId`] from the pool section.
    Remove(ConsensusMessageId),
    /// Remove all the artifacts _strictly_ below the height from the pool section.
    PurgeBelow(Height),
    /// Remove all the artifacts of the given type _strictly_ below the height from the pool
    /// section.
    PurgeTypeBelow(PurgeableArtifactType, Height),
}

#[derive(Clone, Debug, Default)]
pub struct PoolSectionOps<T> {
    pub ops: Vec<PoolSectionOp<T>>,
}

impl<T> PoolSectionOps<T> {
    pub fn new() -> PoolSectionOps<T> {
        PoolSectionOps { ops: Vec::new() }
    }

    /// Insert the artifact into the pool section.
    pub fn insert(&mut self, artifact: T) {
        self.ops.push(PoolSectionOp::Insert(artifact));
    }

    /// Remove the artifact with the given [`ConsensusMessageId`] from the pool section.
    pub(crate) fn remove(&mut self, msg_id: ConsensusMessageId) {
        self.ops.push(PoolSectionOp::Remove(msg_id));
    }

    /// Remove all the artifacts _strictly_ below the height from the pool section.
    pub(crate) fn purge_below(&mut self, height: Height) {
        self.ops.push(PoolSectionOp::PurgeBelow(height));
    }

    /// Remove all the artifacts of the given type _strictly_ below the height from the pool
    /// section.
    pub(crate) fn purge_type_below(
        &mut self,
        artifact_type: PurgeableArtifactType,
        height: Height,
    ) {
        self.ops
            .push(PoolSectionOp::PurgeTypeBelow(artifact_type, height));
    }
}

pub trait InitializablePoolSection: MutablePoolSection<ValidatedConsensusArtifact> {
    fn insert_cup_with_proto(&self, cup_proto: pb::CatchUpPackage);
}

pub trait MutablePoolSection<T>: PoolSection<T> {
    /// Mutate the pool by applying the given [`PoolSectionOps`]. Return [`ConsensusMessageId`]s
    /// of artifacts that were deleted during the mutation.
    fn mutate(&mut self, ops: PoolSectionOps<T>) -> Vec<ConsensusMessageId>;

    /// Return a reference to the [`PoolSection`].
    fn pool_section(&self) -> &dyn PoolSection<T>;
}

struct PerTypeMetrics<T> {
    max_height: IntGauge,
    min_height: IntGauge,
    count: IntGauge,
    count_per_height: Histogram,
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
            count: registry.register(
                IntGauge::with_opts(opts!(
                    "consensus_pool_size",
                    "The number of artifacts in a consensus pool, by pool type and object type",
                    labels! {LABEL_POOL_TYPE => pool_portion, LABEL_TYPE => type_name}
                ))
                .unwrap(),
            ),
            count_per_height: registry.register(
                Histogram::with_opts(histogram_opts!(
                    "artifact_pool_consensus_count_per_height",
                    "The number of artifacts of the given height in a consensus pool, by pool type \
                    and object type",
                    // 1, 2, ..., 10
                    linear_buckets(1.0, 1.0, 10),
                    labels! {LABEL_POOL_TYPE.to_string() => pool_portion.to_string(), LABEL_TYPE.to_string() => type_name.to_string()}
                ))
                .unwrap(),
            ),
            phantom: PhantomData,
        }
    }

    fn update_from_height_indexed_pool(&self, pool: &dyn HeightIndexedPool<T>) {
        if let Some(height_range) = pool.height_range() {
            self.min_height.set(height_range.min.get() as i64);
            self.max_height.set(height_range.max.get() as i64);
        }

        self.count.set(pool.size() as i64);
    }

    /// Updates the number of artifacts for each height in [last_height, new_height)
    fn update_count_per_height(
        &self,
        pool: &dyn HeightIndexedPool<T>,
        last_height: Height,
        new_height: Height,
    ) {
        let mut height = last_height;
        while height < new_height {
            let count = pool.get_by_height(height).count();
            self.count_per_height.observe(count as f64);
            height.inc_assign();
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
    }

    fn update_count_per_height<T>(
        &mut self,
        pool_section: &dyn PoolSection<T>,
        last_height: Height,
        new_height: Height,
    ) {
        macro_rules! update_count_per_height {
            ($artifact_name:ident) => {
                self.$artifact_name.update_count_per_height(
                    pool_section.$artifact_name(),
                    last_height,
                    new_height,
                );
            };
        }

        update_count_per_height!(random_beacon);
        update_count_per_height!(random_tape);
        update_count_per_height!(block_proposal);
        update_count_per_height!(notarization);
        update_count_per_height!(finalization);
        update_count_per_height!(random_beacon_share);
        update_count_per_height!(random_tape_share);
        update_count_per_height!(notarization_share);
        update_count_per_height!(finalization_share);
    }
}

pub struct ConsensusPoolImpl {
    node_id: NodeId,
    validated: Box<dyn InitializablePoolSection + Send + Sync>,
    unvalidated: Box<dyn MutablePoolSection<UnvalidatedConsensusArtifact> + Send + Sync>,
    validated_metrics: PoolMetrics,
    unvalidated_metrics: PoolMetrics,
    invalidated_artifacts: IntCounter,
    /// Block instants are recorded upon entering the validated pool. Instants
    /// below height h are purged whenever all validated or unvalidated
    /// artifacts are also purged below that height.
    block_instants: HeightIndexedInstants<CryptoHashOf<Block>>,
    /// Message instants are recorded upon entering the unvalidated pool.
    /// Currently the only messages we record are notarizations, random beacons
    /// and CUPs. Instants below height h are purged whenever all validated or
    /// unvalidated artifacts are also purged below that height.
    message_instants: HeightIndexedInstants<ConsensusMessageId>,

    time_source: Arc<dyn TimeSource>,
    cache: Arc<ConsensusCacheImpl>,
    backup: Option<Backup>,
    log: ReplicaLogger,
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
                    log,
                ),
            ) as Box<_>,
            #[cfg(target_os = "macos")]
            PersistentPoolBackend::RocksDB(config) => Box::new(
                crate::rocksdb_pool::PersistentHeightIndexedPool::new_consensus_pool(config, log),
            ) as Box<_>,
            #[allow(unreachable_patterns)]
            cfg => {
                unimplemented!("Configuration {:?} is not supported", cfg)
            }
        };

        UncachedConsensusPoolImpl {
            validated,
            unvalidated: Box::new(InMemoryPoolSection::new()),
        }
    }
}

impl ConsensusTime for UncachedConsensusPoolImpl {
    fn consensus_time(&self) -> Option<Time> {
        let block = self.finalized_block();
        if block.height() == Height::from(0) {
            None
        } else {
            Some(block.context.time)
        }
    }
}

impl ConsensusPoolCache for UncachedConsensusPoolImpl {
    fn finalized_block(&self) -> Block {
        get_highest_finalized_block(self, &self.catch_up_package())
    }

    fn catch_up_package(&self) -> CatchUpPackage {
        self.validated().highest_catch_up_package()
    }

    fn cup_as_protobuf(&self) -> pb::CatchUpPackage {
        self.validated().highest_catch_up_package_proto()
    }

    fn summary_block(&self) -> Block {
        let finalized_block = get_highest_finalized_block(self, &self.catch_up_package());
        let mut summary_block = self.catch_up_package().content.block.into_inner();
        update_summary_block(self, &mut summary_block, &finalized_block);
        summary_block
    }
}

impl ConsensusBlockCache for UncachedConsensusPoolImpl {
    fn finalized_chain(&self) -> Arc<dyn ConsensusBlockChain> {
        let summary_block = self.summary_block();
        let finalized_tip = self.finalized_block();
        Arc::new(ConsensusBlockChainImpl::new(
            self,
            &summary_block,
            &finalized_tip,
        ))
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

    fn as_block_cache(&self) -> &dyn ConsensusBlockCache {
        self
    }

    fn build_block_chain(&self, start: &Block, end: &Block) -> Arc<dyn ConsensusBlockChain> {
        Arc::new(ConsensusBlockChainImpl::new(self, start, end))
    }

    fn block_instant(&self, _hash: &CryptoHashOf<Block>) -> Option<Instant> {
        // The uncached consensus pool is only used temporarily for genesis init.
        // We are not inserting new artifacts in this pool, so we don't have any
        // recorded instants at this point.
        None
    }

    fn message_instant(&self, _id: &ConsensusMessageId) -> Option<Instant> {
        // The uncached consensus pool is only used temporarily for genesis init.
        // We are not inserting new artifacts in this pool, so we don't have any
        // recorded instants at this point.
        None
    }
}

impl ConsensusPoolImpl {
    /// Create a consensus pool from a given `config`, and initialize it with
    /// the given `catch_up_package`. If a catch-up package already exists in
    /// the validated pool, the one that is greater (with respect to
    /// height and registry version) will be used.
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        cup_proto: pb::CatchUpPackage,
        config: ArtifactPoolConfig,
        registry: ic_metrics::MetricsRegistry,
        log: ReplicaLogger,
        time_source: Arc<dyn TimeSource>,
    ) -> ConsensusPoolImpl {
        let mut pool = UncachedConsensusPoolImpl::new(config.clone(), log.clone());
        Self::init_genesis(cup_proto, pool.validated.as_mut());
        let mut pool = Self::from_uncached(
            node_id,
            pool,
            registry.clone(),
            log.clone(),
            time_source.clone(),
        );
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
                time_source,
            )
        });

        // Initial update to the metrics, such that they always report the state, even
        // when a subnet is halted.
        pool.validated_metrics.update(pool.validated.pool_section());
        pool.unvalidated_metrics
            .update(pool.unvalidated.pool_section());
        pool
    }

    fn init_genesis(
        cup_proto: pb::CatchUpPackage,
        pool_section: &mut dyn InitializablePoolSection,
    ) {
        let cup = CatchUpPackage::try_from(&cup_proto).expect("deserializing CUP failed");
        let should_insert = match pool_section.catch_up_package().get_highest() {
            Ok(existing) => CatchUpPackageParam::from(&cup) > CatchUpPackageParam::from(&existing),
            Err(_) => true,
        };

        if should_insert {
            let mut ops = PoolSectionOps::new();
            ops.insert(ValidatedConsensusArtifact {
                msg: cup.content.random_beacon.as_ref().clone().into_message(),
                timestamp: cup.content.block.as_ref().context.time,
            });
            pool_section.mutate(ops);
            pool_section.insert_cup_with_proto(cup_proto);
        }
    }

    /// Can be used to instantiate an empty pool without a CUP.
    pub fn from_uncached(
        node_id: NodeId,
        uncached: UncachedConsensusPoolImpl,
        registry: ic_metrics::MetricsRegistry,
        log: ReplicaLogger,
        time_source: Arc<dyn TimeSource>,
    ) -> ConsensusPoolImpl {
        let cache = Arc::new(ConsensusCacheImpl::new(&uncached));
        ConsensusPoolImpl {
            node_id,
            validated: uncached.validated,
            unvalidated: uncached.unvalidated,
            invalidated_artifacts: registry.int_counter(
                "consensus_invalidated_artifacts",
                "The number of invalidated consensus artifacts",
            ),
            validated_metrics: PoolMetrics::new(registry.clone(), POOL_TYPE_VALIDATED),
            unvalidated_metrics: PoolMetrics::new(registry, POOL_TYPE_UNVALIDATED),
            block_instants: HeightIndexedInstants::default(),
            message_instants: HeightIndexedInstants::default(),
            time_source,
            cache,
            backup: None,
            log,
        }
    }

    /// Get a copy of ConsensusPoolCache.
    pub fn get_cache(&self) -> Arc<dyn ConsensusPoolCache> {
        Arc::clone(&self.cache) as Arc<_>
    }

    /// Get a copy of ConsensusPoolCache.
    pub fn get_consensus_time(&self) -> Arc<dyn ConsensusTime> {
        Arc::clone(&self.cache) as Arc<_>
    }

    /// Get a copy of ConsensusBlockCache.
    pub fn get_block_cache(&self) -> Arc<dyn ConsensusBlockCache> {
        Arc::clone(&self.cache) as Arc<_>
    }

    /// Applying the given [`PoolSectionOps`] to the validated [`PoolSection`].
    /// Return [`ConsensusMessageId`]s of artifacts that were deleted during the mutation.
    fn apply_changes_validated(
        &mut self,
        ops: PoolSectionOps<ValidatedConsensusArtifact>,
    ) -> Vec<ConsensusMessageId> {
        if !ops.ops.is_empty() {
            let last_height = self.validated.pool_section().finalization().max_height();
            let purged = self.validated.mutate(ops);
            let new_height = self.validated.pool_section().finalization().max_height();

            self.validated_metrics.update(self.validated.pool_section());

            // Update the metrics if necessary.
            if let (Some(last_height), Some(new_height)) = (last_height, new_height) {
                if new_height != last_height {
                    self.validated_metrics.update_count_per_height(
                        self.validated.pool_section(),
                        last_height,
                        new_height,
                    );
                }
            }
            purged
        } else {
            Vec::new()
        }
    }

    /// Applying the given [`PoolSectionOps`] to the unvalidated [`PoolSection`].
    /// Return [`ConsensusMessageId`]s of artifacts that were deleted during the mutation.
    fn apply_changes_unvalidated(
        &mut self,
        ops: PoolSectionOps<UnvalidatedConsensusArtifact>,
    ) -> Vec<ConsensusMessageId> {
        if !ops.ops.is_empty() {
            let purged = self.unvalidated.mutate(ops);
            self.unvalidated_metrics
                .update(self.unvalidated.pool_section());
            purged
        } else {
            Vec::new()
        }
    }

    // Persists consensus artifacts required for backup validation. If the provided artifacts contain a new finalization,
    // the function traverses the blockchain backwards to the last available finalization and additionally persists all
    // block proposals with their notarizations that are now provably belong to the finalized chain.
    fn backup_artifacts(
        &self,
        backup: &Backup,
        latest_finalization_height: Height,
        mut artifacts_for_backup: Vec<ConsensusMessage>,
    ) {
        // Find the highest finalization among the new artifacts
        let new_finalization = artifacts_for_backup
            .iter()
            .filter_map(|artifact| {
                if let ConsensusMessage::Finalization(finalization) = artifact {
                    Some(finalization)
                } else {
                    None
                }
            })
            .max_by_key(|finalization| finalization.height());
        let find_proposal_by = |height, f: &dyn Fn(&BlockProposal) -> bool| {
            self.validated()
                .block_proposal()
                .get_by_height(height)
                .find(f)
        };

        let finalized_proposal = new_finalization.and_then(|finalization| {
            find_proposal_by(finalization.height(), &|proposal: &BlockProposal| {
                proposal.content.get_hash() == &finalization.content.block
            })
        });

        if let Some(finalized_proposal) = finalized_proposal {
            for proposal in self
                .as_cache()
                .chain_iterator(self, finalized_proposal.content.into_inner())
                .take_while(|block| block.height > latest_finalization_height)
                .filter_map(|block| {
                    find_proposal_by(block.height, &|proposal: &BlockProposal| {
                        proposal.content.as_ref() == &block
                    })
                })
            {
                if let Some(notarization) = self
                    .validated()
                    .notarization()
                    .get_by_height(proposal.content.height())
                    .find(|notarization| proposal.content.get_hash() == &notarization.content.block)
                {
                    artifacts_for_backup.push(ConsensusMessage::Notarization(notarization))
                }

                artifacts_for_backup.push(ConsensusMessage::BlockProposal(proposal));
            }
        }

        backup.store(artifacts_for_backup);
    }

    /// Record instant measurement for the given validated message, as long
    /// as the message type is relevant to us. Currently that includes block
    /// proposals, notarizations, random beacons, and CUPs.
    fn record_instant(&mut self, artifact: &ValidatedConsensusArtifact) {
        let now = self.time_source.get_instant();
        let msg = &artifact.msg;
        if let ConsensusMessage::BlockProposal(bp) = msg {
            let hash = bp.content.get_hash().clone();
            self.block_instants
                .insert(&hash, now, bp.content.get_value().height);
        }
        self.record_instant_unvalidated(msg);
    }

    /// Record instant measurement for the given message, for messages that
    /// are relevant to us, and don't require previous validation. Currently
    /// those are notarizations, random beacons and CUPs.
    fn record_instant_unvalidated(&mut self, msg: &ConsensusMessage) {
        let now = self.time_source.get_instant();
        if matches!(
            msg,
            ConsensusMessage::Notarization(_)
                | ConsensusMessage::RandomBeacon(_)
                | ConsensusMessage::CatchUpPackage(_)
        ) {
            let id = msg.get_id();
            self.message_instants.insert(&id, now, id.height);
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

    fn as_block_cache(&self) -> &dyn ConsensusBlockCache {
        self.cache.as_ref()
    }

    fn build_block_chain(&self, start: &Block, end: &Block) -> Arc<dyn ConsensusBlockChain> {
        Arc::new(ConsensusBlockChainImpl::new(self, start, end))
    }

    fn block_instant(&self, hash: &CryptoHashOf<Block>) -> Option<Instant> {
        self.block_instants.get(hash).copied()
    }

    fn message_instant(&self, id: &ConsensusMessageId) -> Option<Instant> {
        self.message_instants.get(id).copied()
    }
}

impl MutablePool<ConsensusMessage> for ConsensusPoolImpl {
    type Mutations = Mutations;

    fn insert(&mut self, unvalidated_artifact: UnvalidatedConsensusArtifact) {
        let mut ops = PoolSectionOps::new();
        self.record_instant_unvalidated(&unvalidated_artifact.message);
        ops.insert(unvalidated_artifact);
        self.apply_changes_unvalidated(ops);
    }

    fn remove(&mut self, id: &ConsensusMessageId) {
        let mut ops = PoolSectionOps::new();
        ops.remove(id.clone());
        self.apply_changes_unvalidated(ops);
    }

    fn apply(&mut self, change_set: Mutations) -> ArtifactTransmits<ConsensusMessage> {
        let changed = !change_set.is_empty();
        let updates = self.cache.prepare(&change_set);
        let mut unvalidated_ops = PoolSectionOps::new();
        let mut validated_ops = PoolSectionOps::new();
        let mut transmits = vec![];
        // DO NOT Add a default nop. Explicitly mention all cases.
        // This helps with keeping this readable and obvious what
        // change is causing tests to break.
        for change_action in change_set {
            match change_action {
                ChangeAction::AddToValidated(to_add) => {
                    self.record_instant(&to_add);
                    transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                        artifact: to_add.msg.clone(),
                        is_latency_sensitive: is_latency_sensitive(&to_add.msg),
                    }));
                    validated_ops.insert(to_add);
                }
                ChangeAction::RemoveFromValidated(to_remove) => {
                    validated_ops.remove(to_remove.get_id());
                }
                ChangeAction::MoveToValidated(to_move) => {
                    if !to_move.is_share() {
                        transmits.push(ArtifactTransmit::Deliver(ArtifactWithOpt {
                            artifact: to_move.clone(),
                            is_latency_sensitive: false,
                        }));
                    }
                    let msg_id = to_move.get_id();
                    let timestamp = self.unvalidated.get_timestamp(&msg_id).unwrap_or_else(|| {
                        panic!("Timestamp is not found for MoveToValidated: {:?}", to_move)
                    });
                    let validated = ValidatedConsensusArtifact {
                        msg: to_move,
                        timestamp,
                    };
                    self.record_instant(&validated);
                    unvalidated_ops.remove(msg_id);
                    validated_ops.insert(validated);
                }
                ChangeAction::RemoveFromUnvalidated(to_remove) => {
                    unvalidated_ops.remove(to_remove.get_id());
                }
                ChangeAction::PurgeValidatedBelow(height) => {
                    self.block_instants.clear(height);
                    self.message_instants.clear(height);
                    validated_ops.purge_below(height);
                }
                ChangeAction::PurgeValidatedOfTypeBelow(artifact_type, height) => {
                    validated_ops.purge_type_below(artifact_type, height);
                }
                ChangeAction::PurgeUnvalidatedBelow(height) => {
                    self.block_instants.clear(height);
                    self.message_instants.clear(height);
                    unvalidated_ops.purge_below(height);
                }
                ChangeAction::HandleInvalid(to_remove, error_message) => {
                    self.invalidated_artifacts.inc();
                    warn!(
                        self.log,
                        "Invalid consensus artifact ({}) at height {}: {:?}",
                        error_message,
                        to_remove.height(),
                        to_remove
                    );
                    unvalidated_ops.remove(to_remove.get_id());
                }
            }
        }

        let artifacts_for_backup = validated_ops
            .ops
            .iter()
            .filter_map(|op| match op {
                PoolSectionOp::Insert(artifact)
                    // When we prepare a list of artifacts for a backup, we first remove all
                    // block proposals and notarizations. We need to do this to avoid "polluting" the backup
                    // partition with non-finalized blocks, which are the largest artifacts.
                    if !matches!(&artifact.msg, &ConsensusMessage::BlockProposal(_))
                    && !matches!(&artifact.msg, &ConsensusMessage::Notarization(_)) =>
                {
                    Some(artifact.msg.clone())
                }
                _ => None,
            })
            .collect();
        let latest_finalization_height = self
            .validated()
            .finalization()
            .max_height()
            .unwrap_or_default();
        self.apply_changes_unvalidated(unvalidated_ops);
        transmits.extend(
            self.apply_changes_validated(validated_ops)
                .drain(..)
                .map(ArtifactTransmit::Abort),
        );

        if let Some(backup) = &self.backup {
            self.backup_artifacts(backup, latest_finalization_height, artifacts_for_backup);
        }

        if !updates.is_empty() {
            self.cache.update(self, updates);
        }

        ArtifactTransmits {
            transmits,
            poll_immediately: changed,
        }
    }
}

fn is_latency_sensitive(msg: &ConsensusMessage) -> bool {
    match msg {
        ConsensusMessage::Finalization(_) => true,
        ConsensusMessage::Notarization(_) => true,
        ConsensusMessage::RandomBeacon(_) => true,
        ConsensusMessage::RandomTape(_) => true,
        ConsensusMessage::FinalizationShare(_) => true,
        ConsensusMessage::NotarizationShare(_) => true,
        ConsensusMessage::RandomBeaconShare(_) => true,
        ConsensusMessage::RandomTapeShare(_) => true,
        ConsensusMessage::EquivocationProof(_) => true,
        // Might be big and is relayed and can cause excessive BW usage.
        ConsensusMessage::CatchUpPackage(_) => false,
        ConsensusMessage::CatchUpPackageShare(_) => true,
        ConsensusMessage::BlockProposal(prop) => prop.rank() == Rank(0),
    }
}

impl ValidatedPoolReader<ConsensusMessage> for ConsensusPoolImpl {
    fn get(&self, id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        self.validated.get(id)
    }

    fn get_all_validated(&self) -> Box<dyn Iterator<Item = ConsensusMessage> + '_> {
        let node_id = self.node_id;
        let max_catch_up_height = self
            .validated
            .catch_up_package()
            .height_range()
            .map(|x| x.max)
            .unwrap();
        // Since random beacon of previous height is required, min_random_beacon_height
        // should be one less than the normal min height.
        let min_random_beacon_height = max_catch_up_height;
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
        let random_tape_iterator = tape_range.map(Height::from).flat_map(move |h| {
            let mut tapes = self.validated.random_tape().get_by_height(h);
            if let Some(tape) = tapes.next() {
                vec![tape.into_message()]
            } else {
                self.validated
                    .random_tape_share()
                    .get_by_height(h)
                    .filter(|x| x.signature.signer == node_id)
                    .map(|x| x.into_message())
                    .collect()
            }
        });

        Box::new(
            self.validated
                .catch_up_package()
                .get_by_height_range(HeightRange {
                    min: max_catch_up_height,
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
                        .filter(move |x| x.signature.signer == node_id)
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
                        .filter(move |x| x.signature.signer == node_id)
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
                        .filter(move |x| x.signature.signer == node_id)
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

#[cfg(test)]
mod tests {
    use crate::backup::{BackupAge, PurgingError};

    use super::*;
    use ic_interfaces::p2p::consensus::UnvalidatedArtifact;
    use ic_interfaces::time_source::TimeSource;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::types::v1 as pb;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::{crypto::CryptoReturningOk, state_manager::FakeStateManager};
    use ic_test_utilities_consensus::{fake::*, make_genesis};
    use ic_test_utilities_registry::{setup_registry, SubnetRecordBuilder};
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        artifact::IdentifiableArtifact,
        batch::ValidationContext,
        consensus::{BlockProposal, RandomBeacon},
        crypto::{crypto_hash, CryptoHash, CryptoHashOf},
        time::UNIX_EPOCH,
        RegistryVersion, ReplicaVersion,
    };
    use prost::Message;
    use std::{collections::HashMap, convert::TryFrom, fs, io::Read, path::Path, sync::RwLock};

    fn new_from_cup_without_bytes(
        node_id: NodeId,
        subnet_id: SubnetId,
        catch_up_package: CatchUpPackage,
        config: ArtifactPoolConfig,
        registry: ic_metrics::MetricsRegistry,
        log: ReplicaLogger,
        time_source: Arc<dyn TimeSource>,
    ) -> ConsensusPoolImpl {
        ConsensusPoolImpl::new(
            node_id,
            subnet_id,
            (&catch_up_package).into(),
            config,
            registry,
            log,
            time_source,
        )
    }

    fn fake_block(height: Height, rank: Rank) -> Block {
        Block::new(
            CryptoHashOf::from(CryptoHash(vec![])),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(SummaryPayload::fake()),
            ),
            Height::from(height),
            rank,
            ValidationContext {
                registry_version: RegistryVersion::from(99),
                certified_height: Height::from(42),
                time: UNIX_EPOCH,
            },
        )
    }

    #[test]
    fn test_timestamp() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let time_0 = time_source.get_relative_time();
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
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
            pool.apply(changeset);

            // Check timestamp is carried over for msg_0.
            assert_eq!(pool.unvalidated().get_timestamp(&msg_id_0), None);
            assert_eq!(pool.validated().get_timestamp(&msg_id_0), Some(time_0));

            // Check timestamp is removed for msg_1.
            assert_eq!(pool.unvalidated().get_timestamp(&msg_id_1), None);
            assert_eq!(pool.validated().get_timestamp(&msg_id_1), None);
        })
    }

    #[test]
    fn test_artifacts_with_opt_are_created_for_aggregates() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
            );

            let random_beacon_1 = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(1),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ))
            .into_message();

            let random_beacon_2 = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(2),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ))
            .into_message();

            let random_beacon_3 = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(3),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ))
            .into_message();

            pool.insert(UnvalidatedArtifact {
                message: random_beacon_1,
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });

            pool.insert(UnvalidatedArtifact {
                message: random_beacon_2.clone(),
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });

            let changeset = vec![
                ChangeAction::MoveToValidated(random_beacon_2.clone()),
                ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                    msg: random_beacon_3.clone(),
                    timestamp: time_source.get_relative_time(),
                }),
            ];
            let result = pool.apply(changeset);
            assert_eq!(result.transmits.len(), 2);
            assert!(result.poll_immediately);
            assert!(matches!(
                &result.transmits[0], ArtifactTransmit::Deliver(x) if x.artifact.id() == random_beacon_2.get_id()));
            assert!(matches!(
                &result.transmits[1], ArtifactTransmit::Deliver(x) if x.artifact.id() == random_beacon_3.get_id()));

            let result = pool.apply(vec![ChangeAction::PurgeValidatedBelow(Height::from(3))]);
            assert!(!result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Deliver(_))));
            // purging genesis CUP & beacon + validated beacon at height 2
            assert_eq!(result.transmits.len(), 3);
            assert!(result.transmits.iter().any(
                |x| matches!(x, ArtifactTransmit::Abort(id) if *id == random_beacon_2.get_id())
            ));
            assert!(result.poll_immediately);

            let result = pool.apply(vec![ChangeAction::PurgeUnvalidatedBelow(Height::from(3))]);
            assert_eq!(result.transmits.len(), 0);
            assert!(result.poll_immediately);

            let result = pool.apply(vec![]);
            assert!(!result.poll_immediately);
        })
    }

    #[test]
    fn test_shares_are_not_relayed() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
            );

            let random_beacon = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(1),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ));

            let random_beacon_share_1 =
                RandomBeaconShare::fake(&random_beacon, node_test_id(1)).into_message();

            let random_beacon_share_2 =
                RandomBeaconShare::fake(&random_beacon, node_test_id(2)).into_message();

            let random_beacon_share_3 =
                RandomBeaconShare::fake(&random_beacon, node_test_id(3)).into_message();

            pool.insert(UnvalidatedArtifact {
                message: random_beacon_share_1,
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });

            pool.insert(UnvalidatedArtifact {
                message: random_beacon_share_2.clone(),
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });

            let changeset = vec![
                ChangeAction::MoveToValidated(random_beacon_share_2.clone()),
                ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                    msg: random_beacon_share_3.clone(),
                    timestamp: time_source.get_relative_time(),
                }),
            ];
            let result = pool.apply(changeset);
            // share 3 should be added to the validated pool and create an advert
            // share 2 should be moved to the validated pool and not create an advert
            // share 1 should remain in the unvalidated pool
            assert_eq!(result.transmits.len(), 1);
            assert!(result.poll_immediately);
            assert!(matches!(
                &result.transmits[0], ArtifactTransmit::Deliver(x) if x.artifact.id() == random_beacon_share_3.get_id()
            ));

            let result = pool.apply(vec![ChangeAction::PurgeValidatedBelow(Height::from(3))]);
            assert!(!result
                .transmits
                .iter()
                .any(|x| matches!(x, ArtifactTransmit::Deliver(_))));
            // purging genesis CUP & beacon + 2 validated beacon shares
            assert_eq!(result.transmits.len(), 4);
            assert!(result.transmits.iter().any(|x| matches!(x, ArtifactTransmit::Abort(id) if *id == random_beacon_share_2.get_id())));
            assert!(result.transmits.iter().any(|x| matches!(x, ArtifactTransmit::Abort(id) if *id == random_beacon_share_3.get_id())));
            assert!(result.poll_immediately);
        })
    }

    #[test]
    fn test_insert_remove() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
            );

            let random_beacon = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(1),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ));
            let id = random_beacon.get_id();

            pool.insert(UnvalidatedArtifact {
                message: ConsensusMessage::RandomBeacon(random_beacon),
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });
            assert!(pool.unvalidated.contains(&id));

            pool.remove(&id);
            assert!(!pool.unvalidated.contains(&id));
        });
    }

    #[test]
    fn test_get_all_validated() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let node = node_test_id(3);
            let mut pool = new_from_cup_without_bytes(
                node,
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
            );

            let height_offset = 5_000_000_000;

            let fake_proposal = |height: Height, node_id: NodeId| {
                BlockProposal::fake(fake_block(height, Rank(0)), node_id)
                    .into_message()
                    .into_message()
            };

            let fake_finalization = |height: Height| {
                Finalization::fake(FinalizationContent {
                    version: ReplicaVersion::default(),
                    height,
                    block: crypto_hash(&fake_block(height, Rank(0))),
                })
                .into_message()
            };

            let fake_finalization_share = |height: Height, node_id: NodeId| {
                FinalizationShare::fake(&fake_block(height, Rank(0)), node_id).into_message()
            };

            let fake_notarization = |height: Height| {
                Notarization::fake(NotarizationContent {
                    version: ReplicaVersion::default(),
                    height,
                    block: crypto_hash(&fake_block(height, Rank(0))),
                })
                .into_message()
            };

            let fake_notarization_share = |height: Height, node_id: NodeId| {
                NotarizationShare::fake(&fake_block(height, Rank(0)), node_id).into_message()
            };

            let fake_beacon = |height: Height| {
                RandomBeacon::fake(RandomBeaconContent {
                    version: ReplicaVersion::default(),
                    height,
                    parent: CryptoHashOf::from(CryptoHash(vec![])),
                })
                .into_message()
            };

            let fake_beacon_share = |height: Height, node_id: NodeId| {
                RandomBeaconShare::fake(
                    &fake_beacon(height.decrement()).try_into().unwrap(),
                    node_id,
                )
                .into_message()
            };

            let fake_tape = |height: Height| {
                RandomTape::fake(RandomTapeContent {
                    version: ReplicaVersion::default(),
                    height,
                })
                .into_message()
            };

            let fake_tape_share = |height: Height, node_id: NodeId| {
                RandomTapeShare::fake(height, node_id).into_message()
            };

            // Create shares from 5 nodes for 20 heights, only add aggregates below height 15.
            let mut messages = Vec::new();
            for h in 1..=20 {
                let height = Height::from(height_offset + h);
                for i in 1..=5 {
                    let node_id = node_test_id(i);
                    messages.extend([
                        fake_proposal(height, node_id),
                        fake_finalization_share(height, node_id),
                        fake_notarization_share(height, node_id),
                        fake_beacon_share(height, node_id),
                        fake_tape_share(height, node_id),
                    ]);
                }
                if h <= 15 {
                    messages.extend([
                        fake_finalization(height),
                        fake_notarization(height),
                        fake_beacon(height),
                        fake_tape(height),
                    ]);
                }
            }
            messages.push(
                CatchUpPackage::fake(CatchUpContent::new(
                    HashedBlock::new(
                        crypto_hash,
                        fake_block(Height::from(height_offset), Rank(0)),
                    ),
                    HashedRandomBeacon::new(
                        crypto_hash,
                        RandomBeacon::fake(RandomBeaconContent {
                            version: ReplicaVersion::default(),
                            height: Height::from(height_offset),
                            parent: CryptoHashOf::from(CryptoHash(vec![])),
                        }),
                    ),
                    CryptoHashOf::from(CryptoHash(vec![])),
                    None,
                ))
                .into_message(),
            );

            pool.apply(
                messages
                    .into_iter()
                    .map(|msg| {
                        ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                            msg,
                            timestamp: time_source.get_relative_time(),
                        })
                    })
                    .collect(),
            );

            let get_signer = |m: &ConsensusMessage| match m {
                ConsensusMessage::RandomBeaconShare(x) => x.signature.signer,
                ConsensusMessage::RandomTapeShare(x) => x.signature.signer,
                ConsensusMessage::NotarizationShare(x) => x.signature.signer,
                ConsensusMessage::FinalizationShare(x) => x.signature.signer,
                ConsensusMessage::CatchUpPackageShare(x) => x.signature.signer,
                _ => panic!("No signer for aggregate artifacts"),
            };

            pool.get_all_validated().for_each(|m| {
                if m.height().get() <= height_offset + 15 {
                    assert!(!m.is_share());
                }
                if m.is_share() {
                    assert_eq!(get_signer(&m), node);
                }
            });

            assert_eq!(
                pool.get_all_validated().count(),
                // 1 CUP, 15 heights of aggregates, 5 heights of shares, 20 heights of proposals
                1 + 15 * 4 + 5 * 4 + 20 * 5
            );
        });
    }

    #[test]
    fn test_metrics() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::global(),
                no_op_logger(),
                time_source.clone(),
            );

            // creates a fake block proposal for the given block
            let fake_block_proposal = |block: &Block| {
                ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                    msg: BlockProposal::fake(block.clone(), node_test_id(333)).into_message(),
                    timestamp: time_source.get_relative_time(),
                })
            };

            // creates a fake notarization for the given block
            let fake_notarization = |block: &Block| {
                ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                    msg: Notarization::fake(NotarizationContent::new(
                        block.height(),
                        ic_types::crypto::crypto_hash(block),
                    ))
                    .into_message(),
                    timestamp: time_source.get_relative_time(),
                })
            };

            // creates a fake finalization for the given block
            let fake_finalization = |block: &Block| {
                ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                    msg: Finalization::fake(FinalizationContent::new(
                        block.height(),
                        ic_types::crypto::crypto_hash(block),
                    ))
                    .into_message(),
                    timestamp: time_source.get_relative_time(),
                })
            };

            // extracts the notarization metric from the registry
            let get_metric = || {
                prometheus::default_registry()
                .gather()
                .iter()
                .find(|m| m.get_name() == "artifact_pool_consensus_count_per_height")
                .expect("articact_pool_consensus_count_per_heigfht metric not registered")
                .get_metric()
                .iter()
                .find(|m|
                    m.get_label().iter().any(|label| {
                        label.get_name() == "pool_type" && label.get_value() == "validated"
                    }) &&
                    m.get_label().iter().any(|label| {
                        label.get_name() == "type" && label.get_value() == "notarization"
                    }))
                .expect(
                    "metric with pool_type = unvalidated and type = notarization not registered",
                )
                .get_histogram()
                .clone()
            };

            //
            // Height = 3
            //
            let block = fake_block(Height::new(3), Rank(0));

            pool.apply(vec![
                fake_block_proposal(&block),
                fake_notarization(&block),
                fake_finalization(&block),
            ]);

            let metric = get_metric();
            assert_eq!(metric.get_sample_count(), 0_u64);
            assert_eq!(metric.get_sample_sum(), 0_f64);

            //
            // Height = 4
            //
            let block1 = fake_block(Height::new(4), Rank(0));
            let block2 = fake_block(Height::new(4), Rank(1));

            pool.apply(vec![
                fake_block_proposal(&block1),
                fake_notarization(&block1),
                fake_block_proposal(&block2),
                fake_notarization(&block2),
                fake_finalization(&block2),
            ]);

            let metric = get_metric();
            assert_eq!(metric.get_sample_count(), 1_u64);
            assert_eq!(metric.get_sample_sum(), 1_f64);

            //
            // Height = 5
            //
            let block = fake_block(Height::new(5), Rank(0));

            pool.apply(vec![
                fake_block_proposal(&block),
                fake_notarization(&block),
                fake_finalization(&block),
            ]);

            let metric = get_metric();
            assert_eq!(metric.get_sample_count(), 2_u64);
            assert_eq!(metric.get_sample_sum(), 3_f64);
        });
    }

    #[test]
    // We create multiple artifacts for multiple heights, check that all of them are
    // written to the disk and can be restored.
    fn test_backup() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let backup_dir = tempfile::Builder::new().tempdir().unwrap();
            let subnet_id = subnet_test_id(0);
            let root_path = backup_dir
                .path()
                .join(subnet_id.to_string())
                .join(ic_types::ReplicaVersion::default().to_string());
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_id,
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
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
                time_source.clone(),
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

            // height 3, non-final
            let block = Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(SummaryPayload::fake()),
                ),
                Height::from(3),
                Rank(46),
                ValidationContext {
                    registry_version: RegistryVersion::from(98),
                    certified_height: Height::from(41),
                    time: UNIX_EPOCH,
                },
            );
            let proposal3 = BlockProposal::fake(block, node_test_id(333));

            // height 3, final
            let block = Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(SummaryPayload::fake()),
                ),
                Height::from(3),
                Rank(46),
                ValidationContext {
                    registry_version: RegistryVersion::from(101),
                    certified_height: Height::from(42),
                    time: UNIX_EPOCH,
                },
            );
            let proposal3_final = BlockProposal::fake(block.clone(), node_test_id(333));
            let notarization3 = Notarization::fake(NotarizationContent::new(
                Height::from(3),
                ic_types::crypto::crypto_hash(&block),
            ));

            let block = Block::new(
                ic_types::crypto::crypto_hash(&block),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(SummaryPayload::fake()),
                ),
                Height::from(4),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(99),
                    certified_height: Height::from(42),
                    time: UNIX_EPOCH,
                },
            );
            let finalization_at_4 = Finalization::fake(FinalizationContent::new(
                Height::from(4),
                ic_types::crypto::crypto_hash(&block),
            ));
            let proposal = BlockProposal::fake(block, node_test_id(333));

            // non finalized one
            let block = Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(SummaryPayload::fake()),
                ),
                Height::from(4),
                Rank(46),
                ValidationContext {
                    registry_version: RegistryVersion::from(98),
                    certified_height: Height::from(41),
                    time: UNIX_EPOCH,
                },
            );
            let proposal_non_final = BlockProposal::fake(block, node_test_id(333));

            let genesis_cup = make_genesis(ic_types::consensus::dkg::Summary::fake());
            let mut cup = genesis_cup.clone();
            cup.content.random_beacon = hashed::Hashed::new(
                ic_types::crypto::crypto_hash,
                RandomBeacon::fake(RandomBeaconContent::new(
                    Height::from(4),
                    CryptoHashOf::from(CryptoHash(Vec::new())),
                )),
            );

            let changeset = vec![
                random_beacon.clone().into_message(),
                random_tape.clone().into_message(),
                finalization.clone().into_message(),
                finalization_at_4.into_message(),
                notarization.clone().into_message(),
                proposal.clone().into_message(),
                proposal_non_final.clone().into_message(),
                proposal3.clone().into_message(),
                notarization3.clone().into_message(),
                proposal3_final.clone().into_message(),
                cup.clone().into_message(),
            ]
            .into_iter()
            .map(|msg| {
                ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                    msg,
                    timestamp: time_source.get_relative_time(),
                })
            })
            .collect();

            pool.apply(changeset);
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

            let notarization_path = path.join("2").join("notarization.bin");
            assert!(
                path.join("2").join("random_tape.bin").exists(),
                "random tape at height 2 was backed up"
            );
            // notarization at height 2 was not backed up because this height is not
            // finalized
            assert!(!notarization_path.exists());
            assert_eq!(
                fs::read_dir(path.join("2")).unwrap().count(),
                1,
                "only one artifact for height 2 was backed up"
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
            // Check backup for height 3
            let finalization_path = path.join("3").join("finalization.bin");
            assert!(
                finalization_path.exists(),
                "finalization at height 3 was backed up",
            );
            assert_eq!(
                fs::read_dir(path.join("3")).unwrap().count(),
                3,
                "only three artifact for height 3 were backed up"
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
            let proposal_path = path.join("3").join("block_proposalbin");
            assert!(
                !proposal_path.exists(),
                "non-final proposal wasn't backed up"
            );

            let proposal_path = path.join("3").join("block_proposal.bin");
            assert!(proposal_path.exists(), "final proposal was backed up");

            let notarization_path = path.join("3").join("notarization.bin");
            assert!(
                notarization_path.exists(),
                "notarization at height 3 was backed up",
            );
            let mut file = fs::File::open(notarization_path).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let restored =
                Notarization::try_from(pb::Notarization::decode(buffer.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(
                notarization3, restored,
                "restored notarization is identical with the original one"
            );

            // Check backup for height 4
            assert!(
                path.join("4").join("catch_up_package.bin").exists(),
                "catch-up package at height 4 was backed up"
            );
            let proposal_path = path.join("4").join("block_proposal.bin");
            assert!(
                proposal_path.exists(),
                "block proposal at height 4 was backed up"
            );
            assert_eq!(
                fs::read_dir(path.join("4")).unwrap().count(),
                3,
                "three artifacts for height 4 were backed up"
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
            pool.apply(Vec::new());
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
            pool.apply(Vec::new());
            pool.backup.as_ref().unwrap().sync_purging();
            assert!(!path.exists());
        })
    }

    #[test]
    fn test_backup_purging() {
        struct FakeAge {
            // Mapping names of directories containing artifacts to their emulated age.
            map: Arc<RwLock<HashMap<String, Duration>>>,
        }

        impl BackupAge for FakeAge {
            fn get_elapsed_time(&self, path: &Path) -> Result<Duration, PurgingError> {
                // Fake age of an artifact is determined through map look up. Panics on non-existent keys.
                let name = path
                    .file_name()
                    .map(|os| os.to_os_string().into_string().unwrap())
                    .unwrap();
                let m = self.map.read().unwrap();
                let age = m
                    .get(&name)
                    .unwrap_or_else(|| panic!("No age entry found for key path: {:?}", path));
                Ok(*age)
            }
        }

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let backup_dir = tempfile::Builder::new().tempdir().unwrap();
            let subnet_id = subnet_test_id(0);
            let path = backup_dir.path().join(format!("{:?}", subnet_id));
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_id,
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
            );

            let map: Arc<RwLock<HashMap<String, Duration>>> = Default::default();

            // Insert a list of directory names into the fake age map.
            let insert_dirs = |v: &[&str]| {
                let mut m = map.write().unwrap();
                for h in v {
                    m.insert(h.to_string(), Duration::ZERO);
                }
            };

            // Increase the age of all artifacts currently stored in the map by the given duration
            let add_age = |d: Duration| {
                let mut m = map.write().unwrap();
                m.iter_mut().for_each(|(_, age)| {
                    *age += d;
                })
            };

            let purging_interval = Duration::from_millis(3000);
            pool.backup = Some(Backup::new_with_age_func(
                &pool,
                backup_dir.path().into(),
                backup_dir.path().join(format!("{:?}", subnet_id)),
                // Artifact retention time
                Duration::from_millis(2700),
                purging_interval,
                MetricsRegistry::new(),
                no_op_logger(),
                Box::new(FakeAge { map: map.clone() }),
                time_source.clone(),
            ));

            let random_beacon = RandomBeacon::fake(RandomBeaconContent::new(
                Height::from(1),
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ));
            let random_tape = RandomTape::fake(RandomTapeContent::new(Height::from(2)));
            let random_tape3 = RandomTape::fake(RandomTapeContent::new(Height::from(3)));
            let notarization = Notarization::fake(NotarizationContent::new(
                Height::from(3),
                CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
            ));
            let block = Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(SummaryPayload::fake()),
                ),
                Height::from(4),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(99),
                    certified_height: Height::from(42),
                    time: UNIX_EPOCH,
                },
            );
            let finalization = Finalization::fake(FinalizationContent::new(
                Height::from(4),
                ic_types::crypto::crypto_hash(&block),
            ));
            let proposal = BlockProposal::fake(block, node_test_id(333));

            let changeset = vec![random_beacon.into_message(), random_tape.into_message()]
                .into_iter()
                .map(|msg| {
                    ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                        msg,
                        timestamp: time_source.get_relative_time(),
                    })
                })
                .collect();

            // Apply changes
            pool.apply(changeset);
            // sync
            pool.backup.as_ref().unwrap().sync_backup();

            let group_path = &path.join("0");
            // We expect 3 folders for heights 0 to 2.
            assert_eq!(fs::read_dir(group_path).unwrap().count(), 3);
            insert_dirs(&[&subnet_id.to_string(), "0", "1", "2"]);

            // Let's sleep so that the previous heights are close to being purged.
            // Instead of actually sleeping, we simply increase the emulated age of artifacts.
            let sleep_time = purging_interval / 10 * 8;
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();
            add_age(sleep_time);

            // Now add new artifacts
            let changeset = vec![
                notarization.into_message(),
                random_tape3.into_message(),
                proposal.into_message(),
                finalization.into_message(),
            ]
            .into_iter()
            .map(|msg| {
                ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                    msg,
                    timestamp: time_source.get_relative_time(),
                })
            })
            .collect();

            pool.apply(changeset);
            // sync
            pool.backup.as_ref().unwrap().sync_backup();

            // We expect 5 folders for heights 0 to 4.
            assert_eq!(fs::read_dir(group_path).unwrap().count(), 5);
            insert_dirs(&["3", "4"]);

            // We sleep just enough so that purging is overdue and the oldest artifacts are
            // approximately 1 purging interval old.
            let sleep_time = purging_interval / 10 * 3;
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();
            add_age(sleep_time);

            // Trigger the purging.
            pool.apply(Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            // We expect only 2 folders to survive the purging: 3, 4
            assert_eq!(fs::read_dir(group_path).unwrap().count(), 2);
            assert!(group_path.join("3").exists());
            assert!(group_path.join("4").exists());

            let sleep_time = purging_interval + purging_interval / 10 * 3;
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();
            add_age(sleep_time);

            // Trigger the purging.
            pool.apply(Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            // We deleted all artifacts, but the group folder was updated by this and needs
            // to age now.
            assert!(group_path.exists());
            assert_eq!(fs::read_dir(group_path).unwrap().count(), 0);

            let sleep_time = purging_interval + purging_interval / 10 * 3;
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();
            add_age(sleep_time);

            // Trigger the purging.
            pool.apply(Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            //print_time_elapsed(&test_start_time, &(purging_interval / 10 * 37));
            // The group folder expired and was deleted.
            assert!(!group_path.exists());
            assert_eq!(fs::read_dir(&path).unwrap().count(), 0);

            // We wait more and make sure the subnet folder is purged.
            let sleep_time = purging_interval + purging_interval / 10 * 3;
            time_source
                .set_time(time_source.get_relative_time() + sleep_time)
                .unwrap();
            add_age(sleep_time);

            // Trigger the purging.
            pool.apply(Vec::new());
            // sync
            pool.backup.as_ref().unwrap().sync_purging();

            // The subnet_id folder expired and was deleted.
            assert!(!path.exists());
            assert_eq!(fs::read_dir(&backup_dir).unwrap().count(), 0);
        })
    }

    #[test]
    fn test_block_chain_iterator() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let subnet_id = subnet_test_id(1);
            let committee = vec![node_test_id(0)];
            let dkg_interval_length = 5;
            let subnet_records = vec![(
                1,
                SubnetRecordBuilder::from(&committee)
                    .with_dkg_interval_length(dkg_interval_length)
                    .build(),
            )];
            let registry = setup_registry(subnet_id, subnet_records);
            let state_manager = FakeStateManager::new();
            let state_manager = Arc::new(state_manager);
            let mut pool = TestConsensusPool::new(
                node_test_id(0),
                subnet_id,
                pool_config,
                time_source,
                registry,
                Arc::new(CryptoReturningOk::default()),
                state_manager,
                None,
            );

            // Only genesis to start with
            check_iterator(&pool, pool.as_cache().finalized_block(), vec![0]);

            // Two finalized rounds added
            assert_eq!(pool.advance_round_normal_operation_n(2), Height::from(2));
            check_iterator(&pool, pool.as_cache().finalized_block(), vec![2, 1, 0]);

            // Two notarized rounds added
            pool.insert_validated(pool.make_next_beacon());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            pool.notarize(&block);

            pool.insert_validated(pool.make_next_beacon());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            pool.notarize(&block);
            check_iterator(&pool, block.clone().into(), vec![4, 3, 2, 1, 0]);

            pool.finalize(&block);
            pool.insert_validated(pool.make_next_tape());
            pool.insert_validated(pool.make_next_tape());
            check_iterator(&pool, block.into(), vec![4, 3, 2, 1, 0]);

            // Next summary interval starts(height = 6), iterator should stop at the summary block
            assert_eq!(pool.advance_round_normal_operation_n(3), Height::from(7));
            check_iterator(&pool, pool.as_cache().finalized_block(), vec![7, 6]);

            // Start from CUP height
            check_iterator(
                &pool,
                pool.as_cache()
                    .catch_up_package()
                    .content
                    .block
                    .into_inner(),
                vec![6],
            );
        })
    }

    #[test]
    fn test_recording_instants() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let mut pool = new_from_cup_without_bytes(
                node_test_id(0),
                subnet_test_id(0),
                make_genesis(ic_types::consensus::dkg::Summary::fake()),
                pool_config,
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
                time_source.clone(),
            );

            let height = Height::from(5_000_000_000);
            let cup = CatchUpPackage::fake(CatchUpContent::new(
                HashedBlock::new(crypto_hash, fake_block(height, Rank(0))),
                HashedRandomBeacon::new(
                    crypto_hash,
                    RandomBeacon::fake(RandomBeaconContent {
                        version: ReplicaVersion::default(),
                        height,
                        parent: CryptoHashOf::from(CryptoHash(vec![])),
                    }),
                ),
                CryptoHashOf::from(CryptoHash(vec![])),
                None,
            ));
            let notarization = Notarization::fake(NotarizationContent {
                version: ReplicaVersion::default(),
                height,
                block: crypto_hash(&fake_block(height, Rank(0))),
            });
            let random_beacon = RandomBeacon::fake(RandomBeaconContent::new(
                height,
                CryptoHashOf::from(CryptoHash(Vec::new())),
            ));
            let cup_id = cup.get_id();
            let notarization_id = notarization.get_id();
            let random_beacon_id = random_beacon.get_id();
            pool.insert(UnvalidatedArtifact {
                message: ConsensusMessage::CatchUpPackage(cup),
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });
            pool.insert(UnvalidatedArtifact {
                message: ConsensusMessage::Notarization(notarization),
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });
            pool.insert(UnvalidatedArtifact {
                message: ConsensusMessage::RandomBeacon(random_beacon),
                peer_id: node_test_id(0),
                timestamp: time_source.get_relative_time(),
            });
            assert!(pool.message_instant(&cup_id).is_some());
            assert!(pool.message_instant(&notarization_id).is_some());
            assert!(pool.message_instant(&random_beacon_id).is_some());

            // Check that purging of instants respects PurgeValidatedBelow semantics
            pool.apply(vec![ChangeAction::PurgeValidatedBelow(height)]);
            assert!(pool.message_instant(&cup_id).is_some());
            assert!(pool.message_instant(&notarization_id).is_some());
            assert!(pool.message_instant(&random_beacon_id).is_some());
            pool.apply(vec![ChangeAction::PurgeValidatedBelow(height.increment())]);
            assert!(pool.message_instant(&cup_id).is_none());
            assert!(pool.message_instant(&notarization_id).is_none());
            assert!(pool.message_instant(&random_beacon_id).is_none());
        });
    }

    // Verifies the iterator output, starting from the given block
    fn check_iterator(pool: &dyn ConsensusPool, from: Block, expected_heights: Vec<u64>) {
        let blocks = pool
            .as_cache()
            .chain_iterator(pool, from)
            .collect::<Vec<_>>();
        assert_eq!(blocks.len(), expected_heights.len());

        for (block, expected_height) in blocks.iter().zip(expected_heights.iter()) {
            assert_eq!(block.height(), Height::from(*expected_height));
        }
    }
}
