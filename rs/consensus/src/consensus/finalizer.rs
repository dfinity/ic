//! In the internet computer consensus protocol, parties may propose blocks in
//! the form of block proposals. A participant can "notarize" any proposals they
//! think are valid in a round by producing a notarization share for the
//! proposal. Once enough participants have produced a notarization share for
//! the same block proposal, these shares can be aggregated into a complete
//! notarization for the proposal. The notarized proposal then becomes a
//! candidate to extend the blockchain.
//!
//! As there can be multiple such notarized proposals, parties need to agree
//! on a single one to be considered canonical for each round. We call this
//! process finalization.
//!
//! If a single proposal has been notarized in the previous round and if a
//! participant produced at most one notarization share for that round, this
//! participant produces a finalization share for the notarized proposal.
//! Once enough finalization shares are produced, the shares can be aggregated
//! into a complete finalization, at which point the block and its ancestors
//! become finalized.
use crate::consensus::{
    batch_delivery::deliver_batches_for_finalizer,
    metrics::{BatchStats, BlockStats, FinalizerMetrics},
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto,
    membership::Membership,
    pool_reader::PoolReader,
    recovery::{RecoveryStatus, RecoveryTarget, get_recovery_status, recovery_target},
};
use ic_interfaces::{
    certification::CertificationPool,
    ingress_manager::IngressSelector,
    messaging::{MessageRouting, MessageRoutingError},
    time_source::system_time_now,
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, debug, info, trace, warn};
use ic_metrics::MetricsRegistry;
use ic_types::{
    Height, Randomness,
    batch::{Batch, BatchContent},
    consensus::{
        FinalizationContent, FinalizationShare, HasVersion, HashedBlock, get_faults_tolerated,
    },
    replica_config::ReplicaConfig,
};
use std::{
    cell::RefCell,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

pub(crate) struct Finalizer {
    replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    membership: Arc<Membership>,
    pub(crate) crypto: Arc<dyn ConsensusCrypto>,
    message_routing: Arc<dyn MessageRouting>,
    ingress_selector: Arc<dyn IngressSelector>,
    certification_pool: Arc<RwLock<dyn CertificationPool + Send + Sync>>,
    log: ReplicaLogger,
    metrics: FinalizerMetrics,
    prev_finalized_height: RefCell<Height>,
    last_batch_delivered_at: RefCell<Option<Instant>>,
}

impl Finalizer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replica_config: ReplicaConfig,
        registry_client: Arc<dyn RegistryClient>,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        message_routing: Arc<dyn MessageRouting>,
        ingress_selector: Arc<dyn IngressSelector>,
        certification_pool: Arc<RwLock<dyn CertificationPool + Send + Sync>>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        Self {
            replica_config,
            registry_client,
            membership,
            crypto,
            message_routing,
            ingress_selector,
            certification_pool,
            log,
            metrics: FinalizerMetrics::new(metrics_registry),
            prev_finalized_height: RefCell::new(Height::from(0)),
            last_batch_delivered_at: RefCell::new(None),
        }
    }

    /// Attempt to:
    /// * deliver finalized blocks (as `Batch`s) via `Messaging`
    /// * publish finalization shares for relevant rounds
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Vec<FinalizationShare> {
        trace!(self.log, "on_state_change");
        let notarized_height = pool.get_notarized_height();
        let finalized_height = pool.get_finalized_height();

        let h = self.message_routing.expected_batch_height();
        if *self.prev_finalized_height.borrow() < finalized_height {
            debug!(
                self.log,
                "finalized_height {:?} expected_batch_height {:?}", finalized_height, h,
            );
            *self.prev_finalized_height.borrow_mut() = finalized_height;
        }

        // If an automated recovery is pending, batch delivery is capped at the recovery target,
        // and one `CheckpointingWithoutExecution` batch is delivered right above it.
        match self.pending_recovery_target(pool) {
            None => {
                // Try to deliver finalized batches to messaging
                let _ = deliver_batches_for_finalizer(
                    &*self.message_routing,
                    &self.membership,
                    pool,
                    &*self.registry_client,
                    &self.log,
                    self.replica_config.node_id,
                    self.replica_config.subnet_id,
                    /*max_batch_height_to_deliver=*/ None,
                    /*deliver_while_halting=*/ false,
                    |result, block_stats, batch_stats| {
                        self.process_batch_delivery_result(result, block_stats, batch_stats)
                    },
                );
            }
            Some(Some(target)) => {
                // Try to deliver finalized batches up to the recovery target. The recovery halts
                // the subnet (see `status::should_halt`), so batches up to the target must be
                // delivered even while halting — in particular when they are replayed from the
                // consensus pool after a restart.
                let _ = deliver_batches_for_finalizer(
                    &*self.message_routing,
                    &self.membership,
                    pool,
                    &*self.registry_client,
                    &self.log,
                    self.replica_config.node_id,
                    self.replica_config.subnet_id,
                    /*max_batch_height_to_deliver=*/ Some(target.height),
                    /*deliver_while_halting=*/ true,
                    |result, block_stats, batch_stats| {
                        self.process_batch_delivery_result(result, block_stats, batch_stats)
                    },
                );

                self.maybe_deliver_checkpointing_batch(pool, &target);
            }
            // A recovery is pending, but the target is unknown (yet): deliver nothing.
            Some(None) => {}
        }

        // Try to finalize rounds from finalized_height + 1 up to (and including)
        // notarized_height
        (finalized_height.increment().get()..=notarized_height.get())
            .filter_map(|h| self.finalize_height(pool, Height::from(h)))
            .collect()
    }

    /// Returns `None` if no automated recovery is pending, `Some(None)` if a recovery is pending
    /// but the target can't be determined (yet), and `Some(Some(target))` otherwise.
    ///
    /// The target is the highest state supported by `f + 1` validated certification shares of
    /// distinct signers (or by a full certification): at least one *honest* node executed that
    /// state, so it is safe to recover to it. It is also necessary: if we recovered to a lower
    /// height, up to `f` malicious nodes could later complete a full certification on top of the
    /// `f + 1` honest shares, leaving the recovered subnet behind a certified state.
    fn pending_recovery_target(&self, pool: &PoolReader<'_>) -> Option<Option<RecoveryTarget>> {
        let watermark_version = pool
            .get_highest_catch_up_package()
            .content
            .registry_version();

        match get_recovery_status(
            self.registry_client.as_ref(),
            self.replica_config.subnet_id,
            watermark_version,
        ) {
            Ok(RecoveryStatus::NotScheduled) => None,
            Ok(RecoveryStatus::Scheduled { .. }) => Some(self.recovery_target(pool)),
            Err(err) => {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "Couldn't determine the automated recovery status: {err}"
                );

                None
            }
        }
    }

    /// Computes the recovery target from the certification pool, see
    /// [`pending_recovery_target`].
    fn recovery_target(&self, pool: &PoolReader<'_>) -> Option<RecoveryTarget> {
        let nodes = self
            .membership
            .get_nodes(pool.get_catch_up_height())
            .map_err(|err| {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "Couldn't determine the subnet members to compute the recovery target: {err:?}"
                )
            })
            .ok()?;

        let target = recovery_target(
            &*self.certification_pool.read().unwrap(),
            get_faults_tolerated(nodes.len()),
        );

        match &target {
            None => {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "A recovery is pending, but no state is supported by f + 1 certification \
                    shares yet; delivering no batches"
                );
            }
            Some(target) if target.ambiguous => {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "Multiple state hashes are supported by f + 1 certification shares at the \
                    recovery target height {}; the recovery may not converge",
                    target.height,
                );
            }
            Some(target) => {
                info!(
                    every_n_seconds => 30,
                    self.log,
                    "A recovery is pending; delivering batches up to the recovery target {} \
                    with state hash {:?}",
                    target.height,
                    target.hash,
                );
            }
        }

        target
    }

    /// If the batch right above the recovery target is the next expected batch, deliver it as a
    /// `Checkpointing` batch: a batch which creates a checkpoint without inducting, executing or
    /// routing any messages. The recovery CUP references the (full) hash of this checkpoint.
    ///
    /// The delivery is structurally idempotent: once message routing has processed the batch (or
    /// after a restart from the created checkpoint), the expected batch height moves past the
    /// checkpointing height and nothing is delivered anymore.
    ///
    /// Note that nodes which already delivered batches beyond the target before observing the
    /// recovery ("overshot") never deliver the checkpointing batch — they can't checkpoint at the
    /// target anymore and instead rely on state sync once the recovery CUP is aggregated. After a
    /// restart, batch replay restarts from the last persisted checkpoint, which is usually below
    /// the target, and re-enters this path.
    fn maybe_deliver_checkpointing_batch(&self, pool: &PoolReader<'_>, target: &RecoveryTarget) {
        let checkpoint_height = target.height.increment();
        if self.message_routing.expected_batch_height() != checkpoint_height {
            return;
        }

        // All fields must be derived deterministically from the finalized block at the target
        // height, so that all nodes create the exact same checkpoint.
        let Some(block) = pool.get_finalized_block(target.height) else {
            warn!(
                every_n_seconds => 30,
                self.log,
                "Can't deliver the checkpointing batch at height {checkpoint_height} because \
                there is no finalized block at the recovery target height"
            );

            return;
        };

        let batch = Batch {
            batch_number: checkpoint_height,
            batch_summary: None,
            content: BatchContent::CheckpointingWithoutExecution,
            // Checkpointing rounds don't execute anything, so the randomness is irrelevant; it
            // must only be identical on all nodes.
            randomness: Randomness::from([0_u8; 32]),
            registry_version: block.context.registry_version,
            // The batch time must be strictly greater than the previous batch's.
            time: block.context.time + Duration::from_nanos(1),
            // This batch is not derived from a block created by a block maker.
            blockmaker_metrics: None,
            replica_version: block.version().clone(),
        };

        match self.message_routing.deliver_batch(batch) {
            Ok(()) => {
                info!(
                    self.log,
                    "Delivered the checkpointing batch at height {checkpoint_height} above the \
                    recovery target"
                );
            }
            Err(err) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "Couldn't deliver the checkpointing batch at height {checkpoint_height}: \
                    {err:?}"
                );
            }
        }
    }

    /// Write logs, report metrics depending on the batch deliver result.
    fn process_batch_delivery_result(
        &self,
        result: &Result<(), MessageRoutingError>,
        block_stats: BlockStats,
        batch_stats: BatchStats,
    ) {
        match result {
            Ok(()) => {
                let now = Instant::now();
                if let Some(last_batch_delivered_at) = *self.last_batch_delivered_at.borrow() {
                    self.metrics
                        .batch_delivery_interval
                        .observe(now.duration_since(last_batch_delivered_at).as_secs_f64());
                }
                self.last_batch_delivered_at.borrow_mut().replace(now);
                // Batch creation time is essentially wall time (on some replica), so the median
                // duration across the subnet is meaningful.
                self.metrics.batch_delivery_latency.observe(
                    system_time_now()
                        .saturating_duration_since(block_stats.block_time)
                        .as_secs_f64(),
                );

                self.metrics.process(&block_stats, &batch_stats);

                for ingress in batch_stats.ingress_ids.iter() {
                    debug!(
                        self.log,
                        "ingress_message_delivered";
                        ingress_message.message_id => format!("{}", ingress),
                    );
                }
                self.ingress_selector
                    .request_purge_finalized_messages(batch_stats.ingress_ids);
            }
            Err(MessageRoutingError::QueueIsFull) => {
                self.metrics
                    .batches_delivered
                    .with_label_values(&["MessageRoutingError::QueueIsFull"])
                    .inc();
            }
            Err(MessageRoutingError::Ignored { .. }) => {
                unreachable!("Unexpected error on a valid batch number");
            }
        }
    }

    /// Attempt to find a notarized block at the given height that this node
    /// can publish a finalization share for. A block is only returned if:
    /// * This replica is a notary at height `h`
    /// * This replica has not created a finalization share for height `h` yet
    /// * This replica has exactly one fully notarized block at height `h`
    /// * This replica has not created a notarization share for height `h` on
    ///   any block other than the single fully notarized block at height `h`
    ///
    /// In this case, the single notarized block is returned. Otherwise,
    /// return `None`
    fn pick_block_to_finality_sign(&self, pool: &PoolReader<'_>, h: Height) -> Option<HashedBlock> {
        let me = self.replica_config.node_id;
        let previous_beacon = pool.get_random_beacon(h.decrement())?;
        // check whether this replica was a notary at height h
        if !self
            .membership
            .node_belongs_to_notarization_committee(h, &previous_beacon, me)
            .ok()?
        {
            return None;
        }

        // if this replica already created a finalization share for height `h`, we do
        // not need to finality sign a block anymore
        if pool
            .get_finalization_shares(h, h)
            .any(|share| share.signature.signer == me)
        {
            return None;
        }

        // look up all fully notarized blocks for height `h`
        let mut notarized_blocks: Vec<_> = pool.get_notarized_blocks(h).collect();

        // Check if we have exactly one notarized block, and if so, determine that block
        let notarized_block = match notarized_blocks.len() {
            0 => {
                // If there are no notarized blocks at height `h`, we panic, as we should only
                // try to finalize heights that are notarized.
                unreachable!(
                    "Trying to finalize height {:?} but no notarized block found",
                    h
                )
            }
            1 => notarized_blocks.remove(0),
            _ => {
                // if there are multiple fully notarized blocks, there is no chance we reach
                // finality, so there is no point in creating a finalization share
                return None;
            }
        };

        // If notarization shares exists created by this replica at height `h`
        // that sign a block different than `notarized_block`, do not finalize.
        let other_notarized_shares_exists = pool
            .get_notarization_shares(h)
            .any(|x| x.signature.signer == me && x.content.block != *notarized_block.get_hash());
        if other_notarized_shares_exists {
            return None;
        }

        Some(notarized_block)
    }

    /// Try to create a finalization share for a notarized block at the given
    /// height
    fn finalize_height(&self, pool: &PoolReader<'_>, height: Height) -> Option<FinalizationShare> {
        let content = FinalizationContent::new(
            height,
            self.pick_block_to_finality_sign(pool, height)?
                .get_hash()
                .clone(),
            self.replica_config.replica_version().clone(),
        );
        let signature = self
            .crypto
            .sign(
                &content,
                self.replica_config.node_id,
                pool.registry_version(height)?,
            )
            .ok()?;
        Some(FinalizationShare { content, signature })
    }
}

#[cfg(test)]
mod tests {
    //! Finalizer unit tests
    use super::*;
    use ic_consensus_mocks::{Dependencies, DependenciesBuilder};
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{
        ingress_selector::FakeIngressSelector, message_routing::FakeMessageRouting,
    };
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        RegistryVersion,
        consensus::{HasHeight, HashedBlock},
    };
    use std::sync::Arc;

    fn test_certification_pool(
        node_id: ic_types::NodeId,
        pool_config: ic_config::artifact_pool::ArtifactPoolConfig,
    ) -> Arc<RwLock<dyn CertificationPool + Send + Sync>> {
        Arc::new(RwLock::new(
            ic_artifact_pool::certification_pool::CertificationPoolImpl::new(
                node_id,
                pool_config,
                no_op_logger(),
                MetricsRegistry::new(),
            ),
        ))
    }

    /// Given a single block, just finalize it
    #[test]
    fn test_finalizer_behavior() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                registry,
                crypto,
                ..
            } = DependenciesBuilder::new(pool_config.clone(), 1).build();
            let message_routing = FakeMessageRouting::new();

            assert_eq!(pool.advance_round_normal_operation(), Height::from(1));

            // 1. When notarized_height = finalized_height = expected_height - 1
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);

            let message_routing = Arc::new(message_routing);
            let ingress_selector = Arc::new(FakeIngressSelector::new());

            let certification_pool = test_certification_pool(replica_config.node_id, pool_config);
            let finalizer = Finalizer::new(
                replica_config,
                registry,
                membership,
                crypto,
                message_routing.clone(),
                ingress_selector,
                certification_pool,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(b.is_empty());
            assert!(shares.is_empty());

            // 2. When notarized_height = finalized_height = expected_height
            *message_routing.next_batch_height.write().unwrap() = Height::from(1);
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(!b.is_empty());
            // First block, nothing to remove.
            assert!(shares.is_empty());

            // 3. When notarization exists, create a finalization share
            pool.insert_validated(pool.make_next_beacon());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            pool.notarize(&block);

            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(b.is_empty());
            assert!(shares.len() == 1);

            // 4. When finalization share exists, don't create a full finalization
            // (this is done in the aggregator now), and don't create another share
            // if I have already signed.
            let finalization_share = &shares[0];
            pool.insert_validated(finalization_share.clone());
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(b.is_empty());
            assert!(shares.is_empty());
        })
    }

    /// During an automated recovery, the finalizer delivers batches only up to the recovery
    /// target (the highest height with `f + 1` certification shares on the same hash), followed
    /// by exactly one `Checkpointing` batch right above it. Nodes which already delivered batches
    /// beyond the target deliver nothing.
    #[test]
    fn test_finalizer_delivers_checkpointing_batch_during_recovery() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = (0..4).map(node_test_id).collect::<Vec<_>>();
            let dkg_interval_length = 9;
            let subnet_record = || {
                SubnetRecordBuilder::from(&committee).with_dkg_interval_length(dkg_interval_length)
            };
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                registry,
                registry_data_provider,
                crypto,
                ..
            } = DependenciesBuilder::single_subnet(
                pool_config.clone(),
                subnet_test_id(0),
                vec![(1, subnet_record().build())],
            )
            .build();
            let subnet_id = replica_config.subnet_id;

            // Finalize a few heights within the first DKG interval.
            pool.advance_round_normal_operation_n(5);

            let message_routing = Arc::new(FakeMessageRouting::new());
            let certification_pool =
                crate::consensus::catchup_package_maker::tests::test_certification_pool(
                    replica_config.node_id,
                    pool_config,
                );
            let finalizer = Finalizer::new(
                replica_config,
                registry.clone(),
                membership,
                crypto,
                message_routing.clone(),
                Arc::new(FakeIngressSelector::new()),
                certification_pool.clone(),
                no_op_logger(),
                MetricsRegistry::new(),
            );

            // Insert f + 1 (= 2) validated certification shares on the same hash at height 3:
            // the recovery target.
            for node in [1, 2] {
                certification_pool.read().unwrap().validated.insert(
                    crate::consensus::catchup_package_maker::tests::fake_certification_share(
                        3,
                        node_test_id(node),
                    ),
                );
            }

            // Set the recovery flag at a fresh registry version.
            ic_test_utilities_registry::add_subnet_record(
                &registry_data_provider,
                /*version=*/ 2,
                subnet_id,
                subnet_record().with_is_in_recovery_mode(true).build(),
            );
            registry.update_to_latest_version();

            finalizer.on_state_change(&PoolReader::new(&pool));

            // Despite the finalized height being 5, only the batches up to the recovery target
            // (height 3) are delivered, followed by one `Checkpointing` batch at height 4.
            let batches = message_routing.batches.read().unwrap().clone();
            assert_eq!(batches.len(), 4);
            for batch in &batches[0..3] {
                assert!(matches!(
                    batch.content,
                    ic_types::batch::BatchContent::Data { .. }
                ));
            }
            let checkpointing_batch = &batches[3];
            assert_eq!(checkpointing_batch.batch_number, Height::from(4));
            assert!(matches!(
                checkpointing_batch.content,
                ic_types::batch::BatchContent::CheckpointingWithoutExecution
            ));
            assert!(checkpointing_batch.batch_summary.is_none());
            assert!(checkpointing_batch.blockmaker_metrics.is_none());
            // All fields are derived from the finalized block at the target height.
            let target_block = PoolReader::new(&pool)
                .get_finalized_block(Height::from(3))
                .unwrap();
            assert_eq!(
                checkpointing_batch.time,
                target_block.context.time + Duration::from_nanos(1)
            );
            assert_eq!(
                checkpointing_batch.registry_version,
                target_block.context.registry_version
            );
            assert_eq!(checkpointing_batch.replica_version, *target_block.version());

            // The delivery is idempotent: nothing new is delivered on the next invocation.
            finalizer.on_state_change(&PoolReader::new(&pool));
            assert_eq!(message_routing.batches.read().unwrap().len(), 4);

            // A node which already delivered batches beyond the target ("overshot") delivers
            // nothing during the recovery.
            *message_routing.batches.write().unwrap() = Vec::new();
            *message_routing.next_batch_height.write().unwrap() = Height::from(6);
            finalizer.on_state_change(&PoolReader::new(&pool));
            assert!(message_routing.batches.read().unwrap().is_empty());
        })
    }

    // We expect block maker to correctly detect version change and start
    // making only empty blocks.
    #[test]
    fn test_batch_not_delivered_in_protocol_upgrade() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = vec![node_test_id(0)];
            let dkg_interval_length = 3;
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                registry,
                crypto,
                ..
            } = DependenciesBuilder::single_subnet(
                pool_config.clone(),
                subnet_test_id(0),
                vec![
                    (
                        1,
                        SubnetRecordBuilder::from(&committee)
                            .with_dkg_interval_length(dkg_interval_length)
                            .with_replica_version("1")
                            .build(),
                    ),
                    (
                        10,
                        SubnetRecordBuilder::from(&committee)
                            .with_dkg_interval_length(dkg_interval_length)
                            .with_replica_version("2")
                            .build(),
                    ),
                ],
            )
            .build();
            let metrics_registry = MetricsRegistry::new();
            let message_routing = Arc::new(FakeMessageRouting::new());
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let ingress_selector = Arc::new(FakeIngressSelector::new());
            let certification_pool = test_certification_pool(replica_config.node_id, pool_config);
            let finalizer = Finalizer::new(
                replica_config,
                registry,
                membership,
                crypto,
                message_routing.clone(),
                ingress_selector,
                certification_pool,
                no_op_logger(),
                metrics_registry,
            );

            // 1. Make progress until a CUP block
            pool.advance_round_normal_operation_n(dkg_interval_length);
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(3)),
                Some(RegistryVersion::from(1))
            );

            // 2. Make CUP block at next start block
            let mut block_proposal = pool.make_next_block();
            let block = block_proposal.content.as_mut();
            assert!(block.payload.is_summary());
            assert_eq!(
                block.payload.as_ref().as_summary().dkg.registry_version,
                RegistryVersion::from(1)
            );
            assert_eq!(block.context.registry_version, RegistryVersion::from(10));
            block_proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
            pool.insert_validated(block_proposal.clone());
            pool.insert_validated(pool.make_next_beacon());
            pool.insert_validated(pool.make_next_tape());
            pool.notarize(&block_proposal);
            pool.finalize(&block_proposal);

            let catch_up_package = pool.make_catch_up_package(block_proposal.height());
            pool.insert_validated(catch_up_package);

            // 3. continue to make next CUP, expect block summary version to become 10
            pool.advance_round_normal_operation_n(3);
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(7)),
                Some(RegistryVersion::from(1))
            );
            let block_proposal = pool.make_next_block();
            let block = block_proposal.content.as_ref();
            assert!(block.payload.is_summary());
            assert_eq!(block.context.registry_version, RegistryVersion::from(10));
            assert_eq!(
                block.payload.as_ref().as_summary().dkg.registry_version,
                RegistryVersion::from(10)
            );

            pool.insert_validated(block_proposal.clone());
            pool.insert_validated(pool.make_next_beacon());
            pool.insert_validated(pool.make_next_tape());
            pool.notarize(&block_proposal);
            pool.finalize(&block_proposal);

            // expect batch to be still delivered for block at CUP height
            *message_routing.next_batch_height.write().unwrap() = block_proposal.height();
            pool.insert_validated(pool.make_next_tape());
            let _ = finalizer.on_state_change(&PoolReader::new(&pool));
            assert_eq!(
                *message_routing.next_batch_height.write().unwrap(),
                block_proposal.height().increment(),
            );

            // expect batch to be not delivered for next block
            pool.advance_round_normal_operation();
            pool.insert_validated(pool.make_next_tape());
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(9)),
                Some(RegistryVersion::from(10))
            );
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(10)),
                Some(RegistryVersion::from(10))
            );
            let _ = finalizer.on_state_change(&PoolReader::new(&pool));
            assert_eq!(
                *message_routing.next_batch_height.write().unwrap(),
                block_proposal.height().increment(),
            );
        })
    }
}
