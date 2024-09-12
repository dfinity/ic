//! Old artifacts in consensus pool and old replicated states (managed by
//! [StateManager]) can be purged to save space. The [Purger] examines the state
//! of the consensus pool and decides what can be purged.
//!
//! Additionally, it also instructs state manager which replicated
//! states can be purged when it is safe to do so.
//!
//! The purging rules are:
//!
//! 1. Unvalidated artifacts below the next expected batch height can be purged.
//!
//! 2. Validated artifacts below the latest CatchUpPackage height can be purged.
//!    But we also want to keep a minimum chain length that is older than the
//!    CatchUpPackage to help peers catch up.
//!
//! 3. Validated Finalization and Notarization shares below the latest finalized
//!    height can be purged from the pool.
//!
//! 4. Replicated states below the certified height recorded in the block
//!    in the latest CatchUpPackage can be purged.
use crate::consensus::metrics::PurgerMetrics;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::{
    consensus_pool::{ChangeAction, HeightRange, Mutations, PurgeableArtifactType},
    messaging::MessageRouting,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{error, trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    consensus::{ConsensusMessage, HasHeight, HashedBlock},
    replica_config::ReplicaConfig,
    Height,
};
use std::{cell::RefCell, sync::Arc};

use super::{bounds::validated_pool_within_bounds, MINIMUM_CHAIN_LENGTH};

pub(crate) const VALIDATED_POOL_BOUNDS_CHECK_FREQUENCY: u64 = 10;

/// The Purger sub-component.
pub(crate) struct Purger {
    prev_expected_batch_height: RefCell<Height>,
    prev_finalized_certified_height: RefCell<Height>,
    prev_finalized_height: RefCell<Height>,
    prev_maximum_cup_height: RefCell<Height>,
    prev_latest_state_height: RefCell<Height>,
    replica_config: ReplicaConfig,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    message_routing: Arc<dyn MessageRouting>,
    registry_client: Arc<dyn RegistryClient>,
    log: ReplicaLogger,
    metrics: PurgerMetrics,
}

impl Purger {
    pub(crate) fn new(
        replica_config: ReplicaConfig,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        message_routing: Arc<dyn MessageRouting>,
        registry_client: Arc<dyn RegistryClient>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Purger {
        Self {
            prev_expected_batch_height: RefCell::new(Height::from(0)),
            prev_finalized_certified_height: RefCell::new(Height::from(0)),
            prev_finalized_height: RefCell::new(Height::from(0)),
            prev_maximum_cup_height: RefCell::new(Height::from(0)),
            prev_latest_state_height: RefCell::new(Height::from(0)),
            replica_config,
            state_manager,
            message_routing,
            registry_client,
            log,
            metrics: PurgerMetrics::new(metrics_registry),
        }
    }

    /// Purge unvalidated and validated pools, and replicated states according
    /// to the purging rules.
    ///
    /// Pool purging is conveyed through the returned [Mutations] which has to
    /// be applied by the caller, but state purging is directly communicated to
    /// the state manager.
    pub(crate) fn on_state_change(&self, pool: &PoolReader<'_>) -> Mutations {
        let mut changeset = Mutations::new();
        self.purge_unvalidated_pool_by_expected_batch_height(pool, &mut changeset);
        let previous_finalized_height = *self.prev_finalized_height.borrow();

        let certified_height_increased = self.update_finalized_certified_height(pool);
        let cup_height_increased = self.update_cup_height(pool);
        let latest_state_height_increased = self.update_latest_state_height();

        if let Some(new_finalized_height) = self.update_finalized_height(pool) {
            // Every 10 heights, check the advertised pool bounds
            if new_finalized_height.get() % VALIDATED_POOL_BOUNDS_CHECK_FREQUENCY == 0 {
                self.check_advertised_pool_bounds(pool);
            }
            self.purge_validated_shares_by_finalized_height(new_finalized_height, &mut changeset);
            self.purge_equivocation_proofs_by_finalized_height(
                pool,
                new_finalized_height,
                &mut changeset,
            );
            self.purge_non_finalized_blocks(
                pool,
                previous_finalized_height,
                new_finalized_height,
                &mut changeset,
            );
        }
        self.purge_validated_pool_by_catch_up_package(pool, &mut changeset);

        // During normal operation we need to purge when the finalized tip increases.
        // However, when a number of nodes just restarted and are recomputing the state until
        // the certified height, we also want to purge when the latest state height increases,
        // otherwise we might not purge all the recomputed states until the nodes have caught up.
        if certified_height_increased || latest_state_height_increased {
            self.purge_replicated_state_by_finalized_certified_height(pool);
        }
        // If we observe a new CUP with a larger height than the previous max
        // OR the finalized certified height increases(see: CON-930), purge
        if cup_height_increased || certified_height_increased || latest_state_height_increased {
            self.purge_checkpoints_below_cup_height(pool);
        }
        changeset
    }

    /// Updates the purger's copy of the finalized certified height, and returns true if
    /// the height increased. Otherwise returns false.
    fn update_finalized_certified_height(&self, pool: &PoolReader<'_>) -> bool {
        let finalized_certified_height = pool.get_finalized_tip().context.certified_height;
        let prev_finalized_certified_height = self
            .prev_finalized_certified_height
            .replace(finalized_certified_height);
        finalized_certified_height > prev_finalized_certified_height
    }

    /// Updates the purger's copy of the finalized height, and returns the new height if
    /// it increased. Otherwise returns None.
    fn update_finalized_height(&self, pool: &PoolReader<'_>) -> Option<Height> {
        let finalized_height = pool.get_finalized_height();
        let prev_finalized_height = self.prev_finalized_height.replace(finalized_height);
        (finalized_height > prev_finalized_height).then_some(finalized_height)
    }

    /// Updates the purger's copy of the cup height, and returns true if the height
    /// increased.
    fn update_cup_height(&self, pool: &PoolReader<'_>) -> bool {
        let cup_height = pool.get_catch_up_height();
        let prev_cup_height = self.prev_maximum_cup_height.replace(cup_height);
        cup_height > prev_cup_height
    }

    /// Updates the purger's copy of the latest state height, and returns true if the height
    /// increased
    fn update_latest_state_height(&self) -> bool {
        let latest_state_height = self.state_manager.latest_state_height();
        let prev_latest_state_height = self.prev_latest_state_height.replace(latest_state_height);
        latest_state_height > prev_latest_state_height
    }

    /// Unvalidated pool below or equal to the latest expected batch height can
    /// be purged from the pool.
    ///
    /// To avoid producing redundant purge action, we use a transient cache to
    /// remember the previous expected batch height, and only produce a new
    /// purge action when the expected batch height changes.
    ///
    /// There are two important exceptions:
    /// 1. we do not purge unvalidated pool when expected_batch_height >
    ///    finalized_height + 1. This is because under normal condition,
    ///    expected_batch_height <= finalized_height + 1. The only time it
    ///    might become greater than finalized_height + 1 is when
    ///    we just finished a state sync. In this case we may not have moved
    ///    CatchUpPackage to the validated pool. So we should not purge the
    ///    unvalidated pool.
    ///
    /// 2. We do not purge unvalidated pool when there exists unvalidated
    ///    CatchUpPackage or share with height higher than catch_up_height
    ///    but lower than the expected batch height. This is to ensure we do not
    ///    miss processing unvalidated CatchUpPackages or shares.
    fn purge_unvalidated_pool_by_expected_batch_height(
        &self,
        pool_reader: &PoolReader<'_>,
        changeset: &mut Mutations,
    ) {
        let finalized_height = pool_reader.get_finalized_height();
        let expected_batch_height = self.message_routing.expected_batch_height();
        let mut prev_expected_batch_height = self.prev_expected_batch_height.borrow_mut();
        if *prev_expected_batch_height < expected_batch_height
            && expected_batch_height <= finalized_height.increment()
        {
            let catch_up_height = pool_reader.get_catch_up_height();
            let unvalidated_pool = pool_reader.pool().unvalidated();
            fn below_range_max(h: Height, range: &Option<HeightRange>) -> bool {
                range.as_ref().map(|r| h < r.max).unwrap_or(false)
            }
            fn above_range_min(h: Height, range: &Option<HeightRange>) -> bool {
                range.as_ref().map(|r| h > r.min).unwrap_or(false)
            }
            // Skip purging if we have unprocessed but needed CatchUpPackage
            let unvalidated_catch_up_range = unvalidated_pool.catch_up_package().height_range();
            if below_range_max(catch_up_height, &unvalidated_catch_up_range)
                && above_range_min(expected_batch_height, &unvalidated_catch_up_range)
            {
                return;
            }
            // Skip purging if we have unprocessed but needed CatchUpPackageShare
            let unvalidated_catch_up_share_range =
                unvalidated_pool.catch_up_package_share().height_range();
            if below_range_max(catch_up_height, &unvalidated_catch_up_share_range)
                && above_range_min(expected_batch_height, &unvalidated_catch_up_share_range)
            {
                return;
            }
            *prev_expected_batch_height = expected_batch_height;
            // Because random_beacon of expected_batch_height - 1 is required to
            // make progress, we should only purge below expected_batch_height - 1.
            // This is safe because expected_batch_height is always greater than 0.
            changeset.push(ChangeAction::PurgeUnvalidatedBelow(
                expected_batch_height.decrement(),
            ));
            trace!(
                self.log,
                "Purge unvalidated pool below {:?}",
                expected_batch_height
            );
            self.metrics
                .unvalidated_pool_purge_height
                .set(expected_batch_height.get() as i64);
        }
    }

    /// Validated artifacts older than the latest CatchUpPackage height can be
    /// purged from the pool. However, in order to better help peers catch up,
    /// we still keep a minimum chain length below catch-up height.
    ///
    /// Return true if a PurgeAction is taken.
    fn purge_validated_pool_by_catch_up_package(
        &self,
        pool_reader: &PoolReader<'_>,
        changeset: &mut Mutations,
    ) -> bool {
        if let Some(purge_height) = get_purge_height(pool_reader) {
            changeset.push(ChangeAction::PurgeValidatedBelow(purge_height));
            trace!(self.log, "Purge validated pool below {:?}", purge_height);
            self.metrics
                .validated_pool_purge_height
                .set(purge_height.get() as i64);

            if purge_height > self.state_manager.latest_state_height() {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "Execution state is not yet available at height {} that is below \
                    CUP height at {}. Purging anyways.",
                    purge_height,
                    pool_reader.get_catch_up_height()
                );
            }

            true
        } else {
            false
        }
    }

    /// Validated Finalization and Notarization shares at and below the latest
    /// finalized height can be purged from the pool.
    fn purge_validated_shares_by_finalized_height(
        &self,
        finalized_height: Height,
        changeset: &mut Mutations,
    ) {
        changeset.push(ChangeAction::PurgeValidatedOfTypeBelow(
            PurgeableArtifactType::NotarizationShare,
            finalized_height.increment(),
        ));
        changeset.push(ChangeAction::PurgeValidatedOfTypeBelow(
            PurgeableArtifactType::FinalizationShare,
            finalized_height.increment(),
        ));
        trace!(
            self.log,
            "Purge validated shares at and below {finalized_height:?}"
        );
    }

    /// Equivocation proofs at and below the latest finalized height can
    /// be purged from the pool.
    fn purge_equivocation_proofs_by_finalized_height(
        &self,
        pool: &PoolReader,
        finalized_height: Height,
        changeset: &mut Mutations,
    ) {
        if pool
            .pool()
            .validated()
            .equivocation_proof()
            .height_range()
            .is_some()
        {
            changeset.push(ChangeAction::PurgeValidatedOfTypeBelow(
                PurgeableArtifactType::EquivocationProof,
                finalized_height.increment(),
            ));
            trace!(
                self.log,
                "Purge validated equivocation proofs at and below {finalized_height:?}"
            );
        }
    }

    /// Ask state manager to purge all states below the given height
    fn purge_replicated_state_by_finalized_certified_height(&self, pool: &PoolReader<'_>) {
        let height = pool
            .get_finalized_tip()
            .context
            .certified_height
            .min(self.state_manager.latest_state_height());

        self.state_manager.remove_inmemory_states_below(height);
        trace!(
            self.log,
            "Purge replicated states below [memory] {:?}",
            height
        );
        self.metrics
            .replicated_state_purge_height
            .set(height.get() as i64);
    }

    /// Notify the [`StateManager`] that states with heights strictly less than
    /// the given height can be removed.
    ///
    /// Note from the [`StateManager::remove_states_below`] docs:
    ///  * The initial state (height = 0) cannot be removed.
    ///  * Some states matching the removal criteria might be kept alive.  For
    ///    example, the last fully persisted state might be preserved to
    ///    optimize future operations.
    ///
    /// To find more details on the concrete StateManager implementation and the heuristic for
    /// state removal, check: [`ic_state_manager::StateManagerImpl::remove_states_below`].
    fn purge_checkpoints_below_cup_height(&self, pool: &PoolReader<'_>) {
        let cup_height = pool.get_catch_up_height();
        self.state_manager.remove_states_below(cup_height);
        trace!(
            self.log,
            "Purge replicated states below [disk] {:?}",
            cup_height
        );
        self.metrics
            .replicated_state_purge_height_disk
            .set(cup_height.get() as i64);
    }

    /// Goes through every height in (previous_finalized_height, new_finalized_height] and removes
    /// all non-finalized block proposals and notarizations at the given height.
    fn purge_non_finalized_blocks(
        &self,
        pool: &PoolReader,
        previous_finalized_height: Height,
        new_finalized_height: Height,
        changeset: &mut Mutations,
    ) {
        // TODO: Consider changing the signature of [`PoolReader::get_finalized_block`] to also
        // return the hash of the block.
        let mut maybe_finalized_block = pool
            .get_finalized_block(new_finalized_height)
            .map(|block| HashedBlock::new(ic_types::crypto::crypto_hash, block));

        while let Some(finalized_block) = maybe_finalized_block {
            // Stop if we have reached the `previous_finalized_height`
            if finalized_block.height() <= previous_finalized_height {
                break;
            }

            // Purge notarizations at the given height
            for notarization in pool
                .pool()
                .validated()
                .notarization()
                .get_by_height(finalized_block.height())
            {
                if notarization.content.block != *finalized_block.get_hash() {
                    changeset.push(ChangeAction::RemoveFromValidated(
                        ConsensusMessage::Notarization(notarization),
                    ));
                }
            }

            // Purge block proposals at the given height
            for block_proposal in pool
                .pool()
                .validated()
                .block_proposal()
                .get_by_height(finalized_block.height())
            {
                if block_proposal.content.get_hash() != finalized_block.get_hash() {
                    changeset.push(ChangeAction::RemoveFromValidated(
                        ConsensusMessage::BlockProposal(block_proposal),
                    ));
                }
            }

            // Repeat for the parent of the current block
            maybe_finalized_block = pool.get_parent(&finalized_block);
        }
    }

    /// Checks if advertised validated pool is within our consensus bounds.
    fn check_advertised_pool_bounds(&self, pool: &PoolReader<'_>) {
        if let Some(excess) =
            validated_pool_within_bounds(pool, self.registry_client.as_ref(), &self.replica_config)
        {
            self.metrics.validated_pool_bounds_exceeded.inc();
            error!(
                every_n_seconds => 5,
                self.log,
                "validated_pool_bounds_exceeded: validated pool exceeded bounds.\
                 Expected bounds: {:?}, but found {:?}",
                excess.expected,
                excess.found
            );
        }
    }
}

/// Compute the purge height by looking at available CatchUpPackage(s) in the
/// validated pool. Usually things with height less than a min_length below the
/// latest catch up height can be purged, but if there is nothing to purge,
/// this function will return None.
fn get_purge_height(pool_reader: &PoolReader<'_>) -> Option<Height> {
    pool_reader
        .pool()
        .validated()
        .catch_up_package()
        .height_range()
        .and_then(|range| {
            // The condition check below uses range.min because the existence of a range.min
            // that is different than range.max approximately indicates that a purge should
            // take place.
            let min_length = Height::from(MINIMUM_CHAIN_LENGTH);
            if range.max > range.min + min_length {
                Some(range.max - min_length)
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_interfaces::p2p::consensus::MutablePool;
    use ic_interfaces_mocks::messaging::MockMessageRouting;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::message_routing::FakeMessageRouting;
    use ic_types::{consensus::Rank, crypto::CryptoHash, CryptoHashOfState};
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_purger() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                state_manager,
                replica_config,
                registry,
                ..
            } = dependencies(pool_config, 1);

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));
            let execution_height = Arc::new(RwLock::new(Height::from(0)));
            let execution_height_clone = Arc::clone(&execution_height);
            let increment_execution_state = move || {
                let h = execution_height.read().unwrap().increment();
                *execution_height.write().unwrap() = h;
            };
            state_manager
                .get_mut()
                .expect_latest_state_height()
                .returning(move || *execution_height_clone.read().unwrap());
            // In-memory purge height depends on certified height of latest finalized block
            let inmemory_purge_height = Arc::new(RwLock::new(Height::from(0)));
            // Checkpoint purge height depends on certified height of highest checkpoint
            let checkpoint_purge_height = Arc::new(RwLock::new(Height::from(0)));

            let inmemory_purge_height_clone = Arc::clone(&inmemory_purge_height);
            let checkpoint_purge_height_clone = Arc::clone(&checkpoint_purge_height);

            state_manager
                .get_mut()
                .expect_remove_inmemory_states_below()
                .withf(move |height| *height == *inmemory_purge_height_clone.read().unwrap())
                .return_const(());

            state_manager
                .get_mut()
                .expect_remove_states_below()
                .withf(move |height| *height == *checkpoint_purge_height_clone.read().unwrap())
                .return_const(());

            let mut message_routing = MockMessageRouting::new();
            let expected_batch_height = Arc::new(RwLock::new(Height::from(0)));
            let expected_batch_height_clone = Arc::clone(&expected_batch_height);
            message_routing
                .expect_expected_batch_height()
                .returning(move || *expected_batch_height_clone.read().unwrap());

            let purger = Purger::new(
                replica_config,
                state_manager,
                Arc::new(message_routing),
                registry,
                no_op_logger(),
                MetricsRegistry::new(),
            );

            // Put some stuff in the pool
            pool.advance_round_normal_operation_n(9);

            // Only unvalidated pool and shares of validated pool are purged
            let pool_reader = PoolReader::new(&pool);
            *expected_batch_height.write().unwrap() = Height::from(10);
            let changeset = purger.on_state_change(&pool_reader);
            let purge_height = expected_batch_height.read().unwrap().decrement();
            assert_eq!(
                changeset,
                vec![
                    ChangeAction::PurgeUnvalidatedBelow(purge_height),
                    ChangeAction::PurgeValidatedOfTypeBelow(
                        PurgeableArtifactType::NotarizationShare,
                        purge_height.increment()
                    ),
                    ChangeAction::PurgeValidatedOfTypeBelow(
                        PurgeableArtifactType::FinalizationShare,
                        purge_height.increment()
                    ),
                ]
            );

            // No more purge action when called again
            let changeset = purger.on_state_change(&pool_reader);
            assert_eq!(changeset.len(), 0);

            // Put some more stuff in the pool
            for _ in 1..60 {
                pool.advance_round_normal_operation();
                increment_execution_state();
            }

            // Both unvalidated and validated pools are purged
            let pool_reader = PoolReader::new(&pool);
            assert!(get_purge_height(&pool_reader).is_some());
            // Make sure state manager is purged at purge_height too
            *inmemory_purge_height.write().unwrap() =
                pool_reader.get_finalized_tip().context.certified_height;
            *checkpoint_purge_height.write().unwrap() = pool_reader.get_catch_up_height();
            *expected_batch_height.write().unwrap() = Height::from(65);
            let changeset = purger.on_state_change(&pool_reader);

            assert_eq!(
                changeset,
                vec![
                    ChangeAction::PurgeUnvalidatedBelow(
                        expected_batch_height.read().unwrap().decrement()
                    ),
                    ChangeAction::PurgeValidatedOfTypeBelow(
                        PurgeableArtifactType::NotarizationShare,
                        pool_reader.get_finalized_height().increment()
                    ),
                    ChangeAction::PurgeValidatedOfTypeBelow(
                        PurgeableArtifactType::FinalizationShare,
                        pool_reader.get_finalized_height().increment()
                    ),
                    ChangeAction::PurgeValidatedBelow(get_purge_height(&pool_reader).unwrap()),
                ]
            );

            // No more purge action when called again
            pool.apply_changes(changeset);
            let pool_reader = PoolReader::new(&pool);
            let changeset = purger.on_state_change(&pool_reader);
            assert_eq!(changeset.len(), 0);
        })
    }

    #[test]
    fn test_purge_finalization_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                state_manager,
                replica_config,
                registry,
                ..
            } = dependencies(pool_config, 3);
            state_manager
                .get_mut()
                .expect_latest_state_height()
                .returning(|| Height::new(0));
            let purger = Purger::new(
                replica_config,
                state_manager,
                Arc::new(FakeMessageRouting::new()),
                registry,
                no_op_logger(),
                MetricsRegistry::new(),
            );

            // Move to finalized height 30
            pool.advance_round_normal_operation_n(30);

            // We expect to purge finalization shares below AND at the finalized height.
            let pool_reader = PoolReader::new(&pool);
            let changeset = purger.on_state_change(&pool_reader);
            assert!(changeset.contains(&ChangeAction::PurgeValidatedOfTypeBelow(
                PurgeableArtifactType::FinalizationShare,
                Height::new(31),
            )));
        })
    }

    #[test]
    fn test_purge_equivocation_proofs() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                state_manager,
                replica_config,
                registry,
                ..
            } = dependencies(pool_config, 3);
            state_manager
                .get_mut()
                .expect_latest_state_height()
                .returning(|| Height::new(0));
            let purger = Purger::new(
                replica_config,
                state_manager,
                Arc::new(FakeMessageRouting::new()),
                registry,
                no_op_logger(),
                MetricsRegistry::new(),
            );

            for i in 1..10 {
                pool.insert_validated(pool.make_equivocation_proof(Rank(0), Height::new(i)));
                pool.advance_round_normal_operation();
            }

            // Add an additional equivocation proof above the finalized height
            pool.insert_validated(pool.make_next_beacon());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            pool.notarize(&block);
            pool.insert_validated(pool.make_equivocation_proof(Rank(0), Height::new(11)));

            // We expect to purge equivocation proofs below AND at the finalized height.
            let pool_reader = PoolReader::new(&pool);
            let changeset = purger.on_state_change(&pool_reader);
            assert!(changeset.contains(&ChangeAction::PurgeValidatedOfTypeBelow(
                PurgeableArtifactType::EquivocationProof,
                Height::new(10),
            )));
        })
    }

    #[test]
    fn test_get_purge_height() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);

            // Initial purge height is None.
            assert_eq!(get_purge_height(&PoolReader::new(&pool)), None);

            // Put some stuff in the pool
            pool.advance_round_normal_operation_n(9);
            // Purge height is still None.
            assert_eq!(get_purge_height(&PoolReader::new(&pool)), None);

            // Put more stuff in the pool above catch_up_package threshold.
            pool.advance_round_normal_operation_n(59);
            let pool_reader = PoolReader::new(&pool);
            let catch_up_height = pool_reader.get_catch_up_height();
            assert!(catch_up_height > Height::from(MINIMUM_CHAIN_LENGTH));
            // Purge height is MINIMUM_CHAIN_LENGTH below catch_up_height.
            assert_eq!(
                get_purge_height(&pool_reader),
                Some(catch_up_height - Height::from(MINIMUM_CHAIN_LENGTH))
            );
        })
    }

    #[test]
    fn purging_non_finalized_blocks_test() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                state_manager,
                replica_config,
                registry,
                ..
            } = dependencies(pool_config, 10);
            state_manager
                .get_mut()
                .expect_latest_state_height()
                .returning(|| Height::new(0));
            let mut message_routing = MockMessageRouting::new();
            message_routing
                .expect_expected_batch_height()
                .returning(|| Height::new(0));
            let purger = Purger::new(
                replica_config,
                state_manager,
                Arc::new(message_routing),
                registry,
                no_op_logger(),
                MetricsRegistry::new(),
            );

            // Height 1 - two block proposals, one notarization, one finalization.
            // We will later instruct purger not to consider this height.
            pool.insert_validated(pool.make_next_beacon());
            let finalized_block_proposal_1 = pool.make_next_block_with_rank(Rank(0));
            let non_finalized_block_proposal_1 = pool.make_next_block_with_rank(Rank(1));
            pool.insert_validated(finalized_block_proposal_1.clone());
            pool.insert_validated(non_finalized_block_proposal_1.clone());
            pool.notarize(&finalized_block_proposal_1);
            pool.finalize(&finalized_block_proposal_1);
            // Height 2 - three block proposals, two notarizations, one finalization
            pool.insert_validated(pool.make_next_beacon());
            let finalized_block_proposal_2 = pool.make_next_block_with_rank(Rank(0));
            let non_finalized_block_proposal_2_0 = pool.make_next_block_with_rank(Rank(1));
            let non_finalized_block_proposal_2_1 = pool.make_next_block_with_rank(Rank(2));
            pool.insert_validated(finalized_block_proposal_2.clone());
            pool.insert_validated(non_finalized_block_proposal_2_0.clone());
            pool.insert_validated(non_finalized_block_proposal_2_1.clone());
            pool.notarize(&finalized_block_proposal_2);
            let non_finalized_notarization_2 = pool.notarize(&non_finalized_block_proposal_2_0);
            pool.finalize(&finalized_block_proposal_2);
            // Height 3 - two block proposals, two notarizations, no finalizations.
            // The purger should not consider this height as it hasn't been finalized yet.
            pool.insert_validated(pool.make_next_beacon());
            let finalized_block_proposal_3_0 = pool.make_next_block_with_rank(Rank(0));
            let finalized_block_proposal_3_1 = pool.make_next_block_with_rank(Rank(1));
            pool.insert_validated(finalized_block_proposal_3_0.clone());
            pool.insert_validated(finalized_block_proposal_3_1.clone());
            pool.notarize(&finalized_block_proposal_3_0);
            pool.notarize(&finalized_block_proposal_3_1);

            // We want to purge only artifacts height above Height 1
            purger
                .prev_finalized_height
                .replace(finalized_block_proposal_1.content.as_ref().height);

            let pool_reader = PoolReader::new(&pool);
            let remove_from_validated_changeset: Vec<_> = purger
                .on_state_change(&pool_reader)
                .into_iter()
                .filter(|change_action| {
                    matches!(change_action, ChangeAction::RemoveFromValidated(_))
                })
                .collect();

            assert_eq!(
                remove_from_validated_changeset,
                vec![
                    ChangeAction::RemoveFromValidated(ConsensusMessage::Notarization(
                        non_finalized_notarization_2
                    )),
                    ChangeAction::RemoveFromValidated(ConsensusMessage::BlockProposal(
                        non_finalized_block_proposal_2_0
                    )),
                    ChangeAction::RemoveFromValidated(ConsensusMessage::BlockProposal(
                        non_finalized_block_proposal_2_1
                    )),
                ]
            );
        })
    }
}
