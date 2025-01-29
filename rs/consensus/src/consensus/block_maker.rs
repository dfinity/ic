#![deny(missing_docs)]
use crate::{
    consensus::{
        metrics::BlockMakerMetrics,
        status::{self, Status},
        ConsensusCrypto,
    },
    idkg::{self, metrics::IDkgPayloadMetrics},
};
use ic_consensus_dkg::payload_builder::create_payload as create_dkg_payload;
use ic_consensus_utils::{
    find_lowest_ranked_non_disqualified_proposals, get_notarization_delay_settings,
    get_subnet_record, membership::Membership, pool_reader::PoolReader,
};
use ic_interfaces::{
    consensus::PayloadBuilder, dkg::DkgPool, idkg::IDkgPool, time_source::TimeSource,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{debug, error, trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::{
        block_maker::SubnetRecords,
        dkg::{self, DkgDataPayload},
        hashed, Block, BlockMetadata, BlockPayload, BlockProposal, DataPayload, HasHeight, HasRank,
        HashedBlock, Payload, RandomBeacon, Rank, SummaryPayload,
    },
    replica_config::ReplicaConfig,
    time::current_time,
    CountBytes, Height, NodeId, RegistryVersion, SubnetId,
};
use num_traits::ops::saturating::SaturatingSub;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

pub(crate) fn subnet_records_for_registry_version(
    block_maker: &BlockMaker,
    membership_record: RegistryVersion,
    context_record: RegistryVersion,
) -> Option<SubnetRecords> {
    Some(SubnetRecords {
        membership_version: get_subnet_record(
            block_maker.registry_client.as_ref(),
            block_maker.replica_config.subnet_id,
            membership_record,
            &block_maker.log,
        )
        .ok()?,
        context_version: get_subnet_record(
            block_maker.registry_client.as_ref(),
            block_maker.replica_config.subnet_id,
            context_record,
            &block_maker.log,
        )
        .ok()?,
    })
}

/// A consensus subcomponent that is responsible for creating block proposals.
pub struct BlockMaker {
    time_source: Arc<dyn TimeSource>,
    pub(crate) replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    pub(crate) membership: Arc<Membership>,
    pub(crate) crypto: Arc<dyn ConsensusCrypto>,
    payload_builder: Arc<dyn PayloadBuilder>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    idkg_pool: Arc<RwLock<dyn IDkgPool>>,
    pub(crate) state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics: BlockMakerMetrics,
    idkg_payload_metrics: IDkgPayloadMetrics,
    pub(crate) log: ReplicaLogger,
    // The minimal age of the registry version we want to use for the validation context of a new
    // block. The older is the version, the higher is the probability, that it's universally
    // available across the subnet.
    stable_registry_version_age: Duration,
}

impl BlockMaker {
    /// Construct a [BlockMaker] from its dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time_source: Arc<dyn TimeSource>,
        replica_config: ReplicaConfig,
        registry_client: Arc<dyn RegistryClient>,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        payload_builder: Arc<dyn PayloadBuilder>,
        dkg_pool: Arc<RwLock<dyn DkgPool>>,
        idkg_pool: Arc<RwLock<dyn IDkgPool>>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        stable_registry_version_age: Duration,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            time_source,
            replica_config,
            registry_client,
            membership,
            crypto,
            payload_builder,
            dkg_pool,
            idkg_pool,
            state_manager,
            log,
            metrics: BlockMakerMetrics::new(metrics_registry.clone()),
            idkg_payload_metrics: IDkgPayloadMetrics::new(metrics_registry),
            stable_registry_version_age,
        }
    }

    /// If a block should be proposed, propose it.
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Option<BlockProposal> {
        trace!(self.log, "on_state_change");
        let my_node_id = self.replica_config.node_id;
        let (beacon, parent) = get_dependencies(pool)?;
        let height = beacon.content.height.increment();
        match self
            .membership
            .get_block_maker_rank(height, &beacon, my_node_id)
        {
            Ok(Some(rank)) => {
                if !already_proposed(pool, height, my_node_id)
                    && !self.is_better_block_proposal_available(pool, height, rank)
                    && is_time_to_make_block(
                        &self.log,
                        self.registry_client.as_ref(),
                        self.replica_config.subnet_id,
                        pool,
                        parent.get_value().clone(),
                        height,
                        rank,
                        self.time_source.as_ref(),
                        Some(&self.metrics),
                    )
                {
                    self.propose_block(pool, rank, parent)
                        .inspect(|block| self.log_block(block))
                } else {
                    None
                }
            }
            Ok(None) => {
                // this replica is not elected as block maker this round
                None
            }
            Err(err) => {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "Not proposing a block due to `get_block_maker_rank` error {:?}", err
                );
                None
            }
        }
    }

    /// Return true if the validated pool contains a better (lower ranked & not
    /// disqualified) block proposal than the given rank, for the given height.
    fn is_better_block_proposal_available(
        &self,
        pool: &PoolReader<'_>,
        height: Height,
        rank: Rank,
    ) -> bool {
        if let Some(block) = find_lowest_ranked_non_disqualified_proposals(pool, height).first() {
            return block.rank() < rank;
        }
        false
    }

    /// Construct a block proposal
    pub(crate) fn propose_block(
        &self,
        pool: &PoolReader<'_>,
        rank: Rank,
        parent: HashedBlock,
    ) -> Option<BlockProposal> {
        let height = parent.height().increment();
        let certified_height = self.state_manager.latest_certified_height();

        // Note that we will skip blockmaking if registry versions or replica_versions
        // are missing or temporarily not retrievable.
        //
        // The current membership registry version (= stable registry version agreed on
        // in the summary block initiating the previous DKG interval), determines subnet
        // membership (in terms of the notarization committee) of the interval beginning
        // with this block (inclusively).
        let registry_version = pool.registry_version(height).or_else(|| {
            warn!(
                self.log,
                "Couldn't determine the registry version for height {:?}.", height
            );
            None
        })?;

        // The stable registry version to be agreed on in this block. If this is a summary
        // block, this version will be the new membership version of the next dkg interval.
        let stable_registry_version = self.get_stable_registry_version(parent.as_ref())?;
        // Get the subnet records that are relevant to making a block
        let subnet_records =
            subnet_records_for_registry_version(self, registry_version, stable_registry_version)?;

        // The monotonic_block_increment is used as the minimum timestamp increment over
        // the parent for block proposals. Technically we only need this delta to be 1ns
        // to fulfil the requirement of strict monotonicity.
        //
        // The idea behind setting this value to the initial_notary_delay is that when
        // replicas' clocks fall behind, they'll still be incrementing the block time at
        // a degraded, but reasonable rate, instead of the time falling flat. We add 1ns
        // to the initial_notary_delay to ensure the delta is always > 0.
        let monotonic_block_increment = get_notarization_delay_settings(
            &self.log,
            &*self.registry_client,
            self.replica_config.subnet_id,
            registry_version,
        )
        .initial_notary_delay
            + Duration::from_nanos(1);

        // If we have previously tried to make a payload but got an error at the given
        // height, We should try again with the same context. Otherwise create a
        // new context.
        let context = ValidationContext {
            certified_height,
            // To ensure that other replicas can validate our block proposal, we need to use a
            // registry version that is present on most replicas. But since every registry
            // version can become available to different replicas at different times, we should
            // not use the latest one. Instead, we pick an older version we consider "stable",
            // the one which has reached most replicas by now.
            registry_version: stable_registry_version,
            // Below we skip proposing the block if this context is behind the parent's context.
            // We set the time so that block making is not skipped due to local time being
            // behind the network time.
            // We also enforce strictly monotonic increase of timestamp by a non-negative
            // delta over the parent. It's important that (parent + delta) is not greater
            // than local time, assuming the clocks are perfectly in-sync. We choose
            // `delta = initial_notary_delay + 1ns`, because all nodes have to wait at least
            // `initial_notary_delay` time to notarize (and therefore propose subsequent)
            // blocks. The additional 1ns makes no practical difference in that regard.
            time: std::cmp::max(
                self.time_source.get_relative_time(),
                parent.as_ref().context.time + monotonic_block_increment,
            ),
        };

        if !context.greater(&parent.as_ref().context) {
            // The values in our validation context are not strictly monotonically
            // increasing the values included in the parent block by at least
            // monotonic_block_increment. To avoid proposing an invalid block, we simply
            // do not propose a block now.
            warn!(
                every_n_seconds => 5,
                self.log,
                "Cannot propose block as the locally available validation context is \
                smaller than the parent validation context (locally available={:?}, \
                parent context={:?})",
                context,
                &parent.as_ref().context
            );
            return None;
        }

        self.construct_block_proposal(
            pool,
            context,
            parent,
            height,
            certified_height,
            rank,
            registry_version,
            &subnet_records,
        )
    }

    /// Construct a block proposal with specified validation context, parent
    /// block, rank, and batch payload. This function completes the block by
    /// adding a DKG payload and signs the block to obtain a block proposal.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn construct_block_proposal(
        &self,
        pool: &PoolReader<'_>,
        context: ValidationContext,
        parent: HashedBlock,
        height: Height,
        certified_height: Height,
        rank: Rank,
        registry_version: RegistryVersion,
        subnet_records: &SubnetRecords,
    ) -> Option<BlockProposal> {
        let max_dealings_per_block =
            subnet_records.membership_version.dkg_dealings_per_block as usize;

        let dkg_payload = create_dkg_payload(
            self.replica_config.subnet_id,
            &*self.registry_client,
            &*self.crypto,
            pool,
            Arc::clone(&self.dkg_pool),
            parent.as_ref(),
            &*self.state_manager,
            &context,
            self.log.clone(),
            max_dealings_per_block,
        )
        .map_err(|err| warn!(self.log, "Payload construction has failed: {:?}", err))
        .ok()?;

        let payload = Payload::new(
            ic_types::crypto::crypto_hash,
            match dkg_payload {
                dkg::Payload::Summary(summary) => {
                    // Summary block does not have batch payload.
                    self.metrics.report_byte_estimate_metrics(0, 0);
                    let idkg_summary = idkg::create_summary_payload(
                        self.replica_config.subnet_id,
                        &*self.registry_client,
                        pool,
                        &context,
                        parent.as_ref(),
                        Some(&self.idkg_payload_metrics),
                        &self.log,
                    )
                    .map_err(|err| warn!(self.log, "Payload construction has failed: {:?}", err))
                    .ok()
                    .flatten();

                    BlockPayload::Summary(SummaryPayload {
                        dkg: summary,
                        idkg: idkg_summary,
                    })
                }
                dkg::Payload::Data(dkg) => {
                    let (batch_payload, dkg, idkg_data) = match status::get_status(
                        height,
                        self.registry_client.as_ref(),
                        self.replica_config.subnet_id,
                        pool,
                        &self.log,
                    )? {
                        // Don't propose any block if the replica is halted.
                        Status::Halted => {
                            return None;
                        }
                        // Use empty payload and empty DKG dealings if the replica is halting.
                        Status::Halting => (
                            BatchPayload::default(),
                            DkgDataPayload::new_empty(dkg.start_height),
                            /*idkg_data=*/ None,
                        ),
                        Status::Running => {
                            let batch_payload = self.build_batch_payload(
                                pool,
                                height,
                                certified_height,
                                &context,
                                parent.as_ref(),
                                subnet_records,
                            );

                            let idkg_data = idkg::create_data_payload(
                                self.replica_config.subnet_id,
                                &*self.registry_client,
                                &*self.crypto,
                                pool,
                                self.idkg_pool.clone(),
                                &*self.state_manager,
                                &context,
                                parent.as_ref(),
                                &self.idkg_payload_metrics,
                                &self.log,
                            )
                            .map_err(|err| {
                                warn!(self.log, "Payload construction has failed: {:?}", err)
                            })
                            .ok()
                            .flatten();

                            (batch_payload, dkg, idkg_data)
                        }
                    };

                    self.metrics.report_byte_estimate_metrics(
                        batch_payload.xnet.size_bytes(),
                        batch_payload.ingress.count_bytes(),
                    );

                    BlockPayload::Data(DataPayload {
                        batch: batch_payload,
                        dkg,
                        idkg: idkg_data,
                    })
                }
            },
        );
        let block = Block::new(parent.get_hash().clone(), payload, height, rank, context);
        let hashed_block = hashed::Hashed::new(ic_types::crypto::crypto_hash, block);
        let metadata = BlockMetadata::from_block(&hashed_block, self.replica_config.subnet_id);
        match self
            .crypto
            .sign(&metadata, self.replica_config.node_id, registry_version)
        {
            Ok(signature) => Some(BlockProposal {
                signature,
                content: hashed_block,
            }),
            Err(err) => {
                error!(self.log, "Couldn't create a signature: {:?}", err);
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_batch_payload(
        &self,
        pool: &PoolReader<'_>,
        height: Height,
        certified_height: Height,
        context: &ValidationContext,
        parent: &Block,
        subnet_records: &SubnetRecords,
    ) -> BatchPayload {
        let past_payloads =
            pool.get_payloads_from_height(certified_height.increment(), parent.clone());
        let payload =
            self.payload_builder
                .get_payload(height, &past_payloads, context, subnet_records);

        self.metrics
            .get_payload_calls
            .with_label_values(&["success"])
            .inc();

        payload
    }

    /// Log an entry for the proposed block and each of its ingress messages
    fn log_block(&self, block: &BlockProposal) {
        let block_log_entry = block.content.log_entry();
        debug!(
            self.log,
            "block_proposal";
            block => block_log_entry
        );
        let empty_batch = BatchPayload::default();
        let batch = if block.as_ref().payload.is_summary() {
            &empty_batch
        } else {
            &block.as_ref().payload.as_ref().as_data().batch
        };

        for message_id in batch.ingress.message_ids() {
            debug!(
                self.log,
                "ingress_message_insert_into_block";
                ingress_message.message_id => message_id.to_string(),
                block.hash => format!("{:?}", block.content.get_hash()),
            );
        }
    }

    // Returns the registry version received from the NNS some specified amount of
    // time ago. If the parent's context references higher version which is already
    // available locally, we use that version.
    pub(crate) fn get_stable_registry_version(&self, parent: &Block) -> Option<RegistryVersion> {
        let parents_version = parent.context.registry_version;
        let latest_version = self.registry_client.get_latest_version();
        // Check if there is a stable version that we can bump up to.
        for v in (parents_version.get()..=latest_version.get()).rev() {
            let version = RegistryVersion::from(v);
            let version_timestamp = self.registry_client.get_version_timestamp(version)?;
            if version_timestamp + self.stable_registry_version_age <= current_time() {
                return Some(version);
            }
        }
        // If parent's version is locally available, return that.
        if parents_version <= latest_version {
            return Some(parents_version);
        }
        None
    }
}

/// Return the parent random beacon and block of the latest round for which
/// this node might propose a block.
/// Return None otherwise.
pub(crate) fn get_dependencies(pool: &PoolReader<'_>) -> Option<(RandomBeacon, HashedBlock)> {
    let notarized_height = pool.get_notarized_height();
    let beacon = pool.get_random_beacon(notarized_height)?;
    let parent = pool
        .get_notarized_blocks(notarized_height)
        .min_by(|block1, block2| block1.rank().cmp(&block2.rank()))?;
    Some((beacon, parent))
}

/// Return true if this node has already made a proposal at the given height.
pub(crate) fn already_proposed(pool: &PoolReader<'_>, h: Height, this_node: NodeId) -> bool {
    pool.pool()
        .validated()
        .block_proposal()
        .get_by_height(h)
        .any(|p| p.signature.signer == this_node)
}

// To protect ourselves against the scenario where malicious peers somehow manage to consistently
// delay the notarization of blocks from honest peers and force their blocks to be notarized first,
// we give rank-0 block makers more time for their blocks to be notarized, before moving on to
// higher rank blocks, when too many rank-0 blocks have been already notarized. This should
// increase the chance that honest replicas get their blocks finalized in the aforementioned
// scenario.
// Notes:
// 1) if we assume that the "dynamic delay" is never triggered, then we expect the chain
//    quality (defined as the fraction of blocks proposed by honest nodes which were eventually
//    finalized) to be at least 33%: if we look at any random height `h`, then we expect
//    around 10 rank-0 blocks to be proposed by malicious nodes (assuming f = n/3) in the past
//    30 rounds, and at most 10 non-rank-0 blocks from malicious nodes to be finalized, thus we
//    expect at least 10 blocks from honest replica to be finalized in the last 30 rounds.
// 2) `DYNAMIC_DELAY_LOOK_BACK_DISTANCE` cannot be too large for performance reasons.
// 3) `DYNAMIC_DELAY_MAX_NON_RANK_0_BLOCKS` cannot be too small, otherwise the condition could be
//    triggered too easily, and lead to average round duration of more than 3s (due to 1/3 of the
//    blocks arriving after 9s or later)
const DYNAMIC_DELAY_LOOK_BACK_DISTANCE: Height = Height::new(29);
const DYNAMIC_DELAY_MAX_NON_RANK_0_BLOCKS: usize = 10;

fn count_non_rank_0_blocks(pool: &PoolReader, block: Block) -> usize {
    let max_height = block.height();
    let min_height = max_height.saturating_sub(&DYNAMIC_DELAY_LOOK_BACK_DISTANCE);
    pool.get_range(block, min_height, max_height)
        .filter(|block| block.rank > Rank(0))
        .count()
}

/// Calculate the required delay for block making based on the block maker's
/// rank and the number of non-0-rank blocks in its ancestry.
pub(super) fn get_block_maker_delay(
    log: &ReplicaLogger,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    parent: Block,
    registry_version: RegistryVersion,
    rank: Rank,
    metrics: Option<&BlockMakerMetrics>,
) -> Duration {
    let settings =
        get_notarization_delay_settings(log, registry_client, subnet_id, registry_version);
    // If this is not a Rank-0 block maker, check how many non-rank-0 blocks have been notarized in
    // the past, and increase the delay if there have been too many.
    let dynamic_delay = if rank > Rank(0)
        && count_non_rank_0_blocks(pool, parent) > DYNAMIC_DELAY_MAX_NON_RANK_0_BLOCKS
    {
        if let Some(metrics) = metrics {
            metrics.dynamic_delay_triggered.inc();
        }
        settings.unit_delay
    } else {
        Duration::ZERO
    };

    settings.unit_delay * rank.0 as u32 + dynamic_delay
}

/// Return true if the time since round start is greater than the required block
/// maker delay for the given rank.
pub(super) fn is_time_to_make_block(
    log: &ReplicaLogger,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    parent: Block,
    height: Height,
    rank: Rank,
    time_source: &dyn TimeSource,
    metrics: Option<&BlockMakerMetrics>,
) -> bool {
    let Some(registry_version) = pool.registry_version(height) else {
        return false;
    };
    let block_maker_delay = get_block_maker_delay(
        log,
        registry_client,
        subnet_id,
        pool,
        parent,
        registry_version,
        rank,
        metrics,
    );

    // If the relative time indicates that not enough time has passed, we fall
    // back to the the monotonic round start time. We do this to safeguard
    // against a stalled relative clock.
    pool.get_round_start_time(height)
        .is_some_and(|start_time| time_source.get_relative_time() >= start_time + block_maker_delay)
        || pool
            .get_round_start_instant(height, time_source.get_origin_instant())
            .is_some_and(|start_instant| {
                time_source.get_instant() >= start_instant + block_maker_delay
            })
}

#[cfg(test)]
mod tests {
    use crate::idkg::test_utils::create_idkg_pool;

    use super::*;
    use ic_consensus_mocks::{dependencies_with_subnet_params, Dependencies, MockPayloadBuilder};
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::{dkg, HasHeight, HasVersion},
        crypto::CryptoHash,
        *,
    };
    use rstest::rstest;
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_block_maker() {
        let subnet_id = subnet_test_id(0);
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let node_ids: Vec<_> = (0..13).map(node_test_id).collect();
            let dkg_interval_length = 300;
            let Dependencies {
                mut pool,
                membership,
                registry,
                crypto,
                time_source,
                replica_config,
                state_manager,
                dkg_pool,
                idkg_pool,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_id,
                vec![
                    (
                        1,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .build(),
                    ),
                    (
                        10,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .build(),
                    ),
                ],
            );

            pool.advance_round_normal_operation_n(4);

            let payload_builder = MockPayloadBuilder::new();
            let certified_height = Height::from(1);
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config.clone(),
                Arc::clone(&registry) as Arc<dyn RegistryClient>,
                membership.clone(),
                crypto.clone(),
                Arc::new(payload_builder),
                dkg_pool.clone(),
                idkg_pool.clone(),
                state_manager.clone(),
                Duration::from_millis(0),
                MetricsRegistry::new(),
                no_op_logger(),
            );

            // Check first block is created immediately because rank 1 has to wait.
            let run_block_maker = || {
                let reader = PoolReader::new(&pool);
                block_maker.on_state_change(&reader)
            };
            assert!(run_block_maker().is_none());

            // Check that block creation works properly.
            pool.advance_round_normal_operation_n(4);

            let mut payload_builder = MockPayloadBuilder::new();
            let start = pool.validated().block_proposal().get_highest().unwrap();
            let next_height = start.height().increment();
            let start_hash = start.content.get_hash();
            let expected_payloads = PoolReader::new(&pool)
                .get_payloads_from_height(certified_height.increment(), start.as_ref().clone());
            let returned_payload =
                dkg::Payload::Data(dkg::DkgDataPayload::new_empty(Height::from(0)));
            let pool_reader = PoolReader::new(&pool);
            let expected_time = expected_payloads[0].1
                + get_block_maker_delay(
                    &no_op_logger(),
                    registry.as_ref(),
                    subnet_id,
                    &pool_reader,
                    start.as_ref().clone(),
                    RegistryVersion::from(10),
                    Rank(4),
                    /*metrics=*/ None,
                );
            let expected_context = ValidationContext {
                certified_height,
                registry_version: RegistryVersion::from(10),
                time: expected_time,
            };
            let matches_expected_payloads =
                move |payloads: &[(Height, Time, Payload)]| payloads == &*expected_payloads;
            let expected_block = Block::new(
                start_hash.clone(),
                Payload::new(ic_types::crypto::crypto_hash, returned_payload.into()),
                next_height,
                Rank(4),
                expected_context.clone(),
            );

            payload_builder
                .expect_get_payload()
                .withf(move |_, payloads, context, _| {
                    matches_expected_payloads(payloads) && context == &expected_context
                })
                .return_const(BatchPayload::default());

            let pool_reader = PoolReader::new(&pool);
            let replica_config = ReplicaConfig {
                node_id: (0..13)
                    .map(node_test_id)
                    .find(|node_id| {
                        let h = pool_reader.get_notarized_height();
                        let prev_beacon = pool_reader.get_random_beacon(h).unwrap();
                        membership.get_block_maker_rank(h.increment(), &prev_beacon, *node_id)
                            == Ok(Some(Rank(4)))
                    })
                    .unwrap(),
                subnet_id: replica_config.subnet_id,
            };

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config,
                registry.clone(),
                membership,
                Arc::clone(&crypto) as Arc<_>,
                Arc::new(payload_builder),
                dkg_pool,
                idkg_pool,
                state_manager,
                Duration::from_millis(0),
                MetricsRegistry::new(),
                no_op_logger(),
            );
            let run_block_maker = || {
                let reader = PoolReader::new(&pool);
                block_maker.on_state_change(&reader)
            };

            // kick start another round
            assert!(run_block_maker().is_none());

            time_source.set_time(expected_time).unwrap();
            if let Some(proposal) = run_block_maker() {
                assert_eq!(proposal.as_ref(), &expected_block);
            } else {
                panic!("Expected a new block proposal");
            }

            // insert a rank 0 block for the current round
            let next_block = pool.make_next_block();
            // ensure that `make_next_block` creates a rank 0 block
            assert_eq!(next_block.rank(), Rank(0));
            pool.insert_validated(pool.make_next_block());

            let run_block_maker = || {
                let reader = PoolReader::new(&pool);
                block_maker.on_state_change(&reader)
            };

            // check that the block maker does not create a block, as a lower ranked block
            // is already available.
            assert!(run_block_maker().is_none());
        })
    }

    // We expect block maker to correctly detect version change and start making only empty blocks.
    #[test]
    fn test_halting_due_to_protocol_upgrade() {
        test_halting(
            ReplicaVersion::try_from("0xBEEF").unwrap(),
            /*halt_at_cup_height=*/ false,
        )
    }

    // We expect block maker to correctly detect that the registry instructs it to halt and start
    // making only empty blocks.
    #[test]
    fn test_halting_due_to_registry_instruction() {
        test_halting(ReplicaVersion::default(), /*halt_at_cup_height=*/ true)
    }

    fn test_halting(replica_version: ReplicaVersion, halt_at_cup_height: bool) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let dkg_interval_length = 3;
            let node_ids = [node_test_id(0)];
            let Dependencies {
                mut pool,
                registry,
                crypto,
                time_source,
                replica_config,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config.clone(),
                subnet_test_id(0),
                vec![
                    (
                        1,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .build(),
                    ),
                    (
                        10,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .with_replica_version(replica_version.as_ref())
                            .with_halt_at_cup_height(halt_at_cup_height)
                            .build(),
                    ),
                ],
            );
            let dkg_pool = Arc::new(RwLock::new(ic_artifact_pool::dkg_pool::DkgPoolImpl::new(
                MetricsRegistry::new(),
                no_op_logger(),
            )));
            let idkg_pool = Arc::new(RwLock::new(create_idkg_pool(
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            )));

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));
            let certified_height = Height::from(1);
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);
            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                    Height::new(0),
                    Arc::new(ic_test_utilities_state::get_initial_state(0, 0)),
                )));

            let mut payload_builder = MockPayloadBuilder::new();
            payload_builder
                .expect_get_payload()
                .return_const(BatchPayload::default());
            let membership =
                Membership::new(pool.get_cache(), registry.clone(), replica_config.subnet_id);
            let membership = Arc::new(membership);

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config.clone(),
                Arc::clone(&registry) as Arc<dyn RegistryClient>,
                membership.clone(),
                crypto.clone(),
                Arc::new(payload_builder),
                dkg_pool.clone(),
                idkg_pool.clone(),
                state_manager.clone(),
                Duration::from_millis(0),
                MetricsRegistry::new(),
                no_op_logger(),
            );

            // Skip the first DKG interval
            pool.advance_round_normal_operation_n(dkg_interval_length);

            let proposal = block_maker.on_state_change(&PoolReader::new(&pool));
            assert!(proposal.is_some());
            let mut proposal = proposal.unwrap();
            let block = proposal.content.as_mut();
            assert!(block.payload.is_summary());
            pool.advance_round_with_block(&proposal);
            pool.insert_validated(pool.make_catch_up_package(proposal.height()));

            // Skip the second DKG interval
            pool.advance_round_normal_operation_n(dkg_interval_length);
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(dkg_interval_length * 2)),
                Some(RegistryVersion::from(1))
            );

            // 2. Make CUP block at next start block

            // We do not anticipate payload builder to be called since we will be making
            // empty blocks (including the next CUP block).
            let payload_builder = MockPayloadBuilder::new();

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config,
                Arc::clone(&registry) as Arc<dyn RegistryClient>,
                membership,
                crypto,
                Arc::new(payload_builder),
                dkg_pool,
                idkg_pool,
                state_manager,
                Duration::from_millis(0),
                MetricsRegistry::new(),
                no_op_logger(),
            );

            // Check CUP block is made.
            let proposal = block_maker.on_state_change(&PoolReader::new(&pool));
            assert!(proposal.is_some());
            let cup_proposal = proposal.unwrap();
            let block = cup_proposal.content.as_ref();
            assert!(block.payload.is_summary());
            assert_eq!(block.context.registry_version, RegistryVersion::from(10));

            // only notarized but not finalize this CUP block.
            pool.insert_validated(cup_proposal.clone());
            pool.insert_validated(pool.make_next_beacon());
            pool.notarize(&cup_proposal);

            // 3. Make one more block, payload builder should not have been called.
            let proposal = block_maker.on_state_change(&PoolReader::new(&pool));
            assert!(proposal.is_some());
            let proposal = proposal.unwrap();
            let block = proposal.content.as_ref();
            // blocks still uses default version, not the new version.
            assert_eq!(block.version(), &ReplicaVersion::default());
            // registry version 10 becomes effective.
            assert_eq!(
                PoolReader::new(&pool).registry_version(proposal.height()),
                Some(RegistryVersion::from(10))
            );
        })
    }

    #[test]
    fn test_stable_registry_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let dkg_interval_length = 3;
            let node_ids = [node_test_id(0)];
            let record = SubnetRecordBuilder::from(&node_ids)
                .with_dkg_interval_length(dkg_interval_length)
                .build();
            let subnet_id = subnet_test_id(0);
            let Dependencies {
                registry,
                crypto,
                pool,
                time_source,
                replica_config,
                state_manager,
                registry_data_provider,
                dkg_pool,
                idkg_pool,
                ..
            } = dependencies_with_subnet_params(pool_config, subnet_id, vec![(1, record.clone())]);

            let mut payload_builder = MockPayloadBuilder::new();
            payload_builder
                .expect_get_payload()
                .return_const(BatchPayload::default());
            let membership = Arc::new(Membership::new(
                pool.get_cache(),
                registry.clone(),
                replica_config.subnet_id,
            ));

            let mut block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config,
                Arc::clone(&registry) as Arc<dyn RegistryClient>,
                membership,
                crypto,
                Arc::new(payload_builder),
                dkg_pool,
                idkg_pool,
                state_manager,
                Duration::from_millis(0),
                MetricsRegistry::new(),
                no_op_logger(),
            );

            let delay = Duration::from_millis(1000);

            // We add a new version every `delay` ms.
            std::thread::sleep(delay);
            add_subnet_record(&registry_data_provider, 2, subnet_id, record.clone());
            registry.update_to_latest_version();
            std::thread::sleep(delay);
            add_subnet_record(&registry_data_provider, 3, subnet_id, record.clone());
            registry.update_to_latest_version();
            std::thread::sleep(delay);
            add_subnet_record(&registry_data_provider, 4, subnet_id, record);
            registry.update_to_latest_version();

            // Make sure the latest version is the highest we added.
            assert_eq!(registry.get_latest_version(), RegistryVersion::from(4));

            // Now we just request versions at every interval of the previously added
            // version. To avoid hitting the boundaries, we use a little offset.
            let offset = delay / 10 * 3;
            let mut parent = pool.get_cache().finalized_block();
            block_maker.stable_registry_version_age = offset;
            assert_eq!(
                block_maker.get_stable_registry_version(&parent).unwrap(),
                RegistryVersion::from(3)
            );
            block_maker.stable_registry_version_age = offset + delay;
            assert_eq!(
                block_maker.get_stable_registry_version(&parent).unwrap(),
                RegistryVersion::from(2)
            );
            block_maker.stable_registry_version_age = offset + delay * 2;
            assert_eq!(
                block_maker.get_stable_registry_version(&parent).unwrap(),
                RegistryVersion::from(1)
            );
            // Now let's test if parent's version is used
            parent.context.registry_version = RegistryVersion::from(2);
            assert_eq!(
                block_maker.get_stable_registry_version(&parent).unwrap(),
                RegistryVersion::from(2)
            );
        })
    }

    #[rstest]
    #[case(Rank(0), Duration::from_secs(1), Duration::from_secs(0))]
    #[case(Rank(1), Duration::from_secs(7), Duration::from_secs(7 + 7))]
    #[case(Rank(2), Duration::from_secs(3), Duration::from_secs(2 * 3 + 3))]
    fn get_block_maker_delay_many_non_rank_0_blocks(
        #[case] rank: Rank,
        #[case] unit_delay: Duration,
        #[case] expected_block_maker_delay: Duration,
    ) {
        // there should be 11 non-rank-0 blocks in the past 30 heights
        let initial = std::iter::repeat(Rank(1)).take(5);
        let mid = std::iter::repeat(Rank(0)).take(19);
        let terminal = std::iter::repeat(Rank(2)).take(8);

        let ranks: Vec<Rank> = initial.chain(mid).chain(terminal).collect();

        assert_eq!(
            block_maker_delay_test_case(&ranks, rank, unit_delay,),
            expected_block_maker_delay,
        );
    }

    #[rstest]
    #[case(Rank(0), Duration::from_secs(2), Duration::from_secs(0))]
    #[case(Rank(1), Duration::from_secs(4), Duration::from_secs(4))]
    #[case(Rank(2), Duration::from_secs(6), Duration::from_secs(2 * 6))]
    fn get_block_maker_delay_few_non_rank_0_blocks(
        #[case] rank: Rank,
        #[case] unit_delay: Duration,
        #[case] expected_block_maker_delay: Duration,
    ) {
        // there should be 10 non-rank-0 blocks in the past 30 heights
        let initial = std::iter::repeat(Rank(1)).take(5);
        let mid = std::iter::repeat(Rank(0)).take(20);
        let terminal = std::iter::repeat(Rank(2)).take(8);

        let ranks: Vec<Rank> = initial.chain(mid).chain(terminal).collect();

        assert_eq!(
            block_maker_delay_test_case(&ranks, rank, unit_delay,),
            expected_block_maker_delay,
        );
    }

    #[test]
    fn get_block_maker_delay_short_chain_many_non_rank_0_blocks_test() {
        let previous_ranks = std::iter::repeat(Rank(1)).take(11).collect::<Vec<_>>();
        assert_eq!(
            block_maker_delay_test_case(
                &previous_ranks,
                Rank(1),
                /*unit_delay*/ Duration::from_secs(1)
            ),
            Duration::from_secs(2),
        );
    }

    #[test]
    fn get_block_maker_delay_short_chain_few_non_rank_0_blocks_test() {
        assert_eq!(
            block_maker_delay_test_case(
                &[Rank(0), Rank(1), Rank(1), Rank(1), Rank(1), Rank(1)],
                Rank(1),
                /*unit_delay*/ Duration::from_secs(1)
            ),
            Duration::from_secs(1),
        );
    }

    fn block_maker_delay_test_case(
        past_block_ranks: &[Rank],
        block_maker_rank: Rank,
        unit_delay: Duration,
    ) -> Duration {
        let subnet_id = subnet_test_id(0);
        let node_ids: Vec<_> = (0..100).map(node_test_id).collect();
        let registry_version = 1;

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool, registry, ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_id,
                vec![(
                    registry_version,
                    SubnetRecordBuilder::from(&node_ids)
                        .with_unit_delay(unit_delay)
                        .build(),
                )],
            );

            for rank in past_block_ranks {
                pool.advance_round_with_block(&pool.make_next_block_with_rank(*rank));
            }

            let parent = pool.latest_notarized_blocks().next().unwrap();

            let pool_reader = PoolReader::new(&pool);

            get_block_maker_delay(
                &no_op_logger(),
                registry.as_ref(),
                subnet_id,
                &pool_reader,
                parent,
                RegistryVersion::from(registry_version),
                block_maker_rank,
                /*metrics=*/ None,
            )
        })
    }
}
