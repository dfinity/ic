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
//! But we also want to keep a minimum chain length that is older than the
//! CatchUpPackage to help peers catch up.
//!
//! 3. Replicated states below the certified height recorded in the block
//! in the latest CatchUpPackage can be purged.
use crate::consensus::{metrics::PurgerMetrics, pool_reader::PoolReader, prelude::*};
use ic_interfaces::{
    consensus_pool::HeightRange, messaging::MessageRouting, state_manager::StateManager,
};
use ic_logger::{trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use std::cell::RefCell;
use std::sync::Arc;

/// The Purger sub-component.
pub struct Purger {
    prev_expected_batch_height: RefCell<Height>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    message_routing: Arc<dyn MessageRouting>,
    log: ReplicaLogger,
    metrics: PurgerMetrics,
}

impl Purger {
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        message_routing: Arc<dyn MessageRouting>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Purger {
        Self {
            // expected_batch_height starts from 1
            prev_expected_batch_height: RefCell::new(Height::from(1)),
            state_manager,
            message_routing,
            log,
            metrics: PurgerMetrics::new(metrics_registry),
        }
    }

    /// Purge unvalidated and validated pools, and replicated states according
    /// to the purging rules.
    ///
    /// Pool purging is conveyed through the returned [ChangeSet] which has to
    /// be applied by the caller, but state purging is directly communicated to
    /// the state manager.
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> ChangeSet {
        let mut changeset = ChangeSet::new();
        self.purge_unvalidated_pool_by_expected_batch_height(pool, &mut changeset);
        if self.purge_validated_pool_by_catch_up_package(pool, &mut changeset) {
            // When we do purge consensus artifacts, we also want to purge state too.
            // NOTE: Unlike changeset, this function has an immediate side-effect.
            self.purge_replicated_state_by_catch_up_height(pool);
        }
        changeset
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
    /// finalized_height + 1. This is because under normal condition,
    /// expected_batch_height <= finalized_height + 1. The only time it
    /// might become greater than finalized_height + 1 is when
    /// we just finished a state sync. In this case we may not have moved
    /// CatchUpPackage to the validated pool. So we should not purge the
    /// unvalidated pool.
    ///
    /// 2. We do not purge unvalidated pool when there exists unvalidated
    /// CatchUpPackage or share with height higher than catch_up_height
    /// but lower than the expected batch height. This is to ensure we do not
    /// miss processing unvalidated CatchUpPackages or shares.
    fn purge_unvalidated_pool_by_expected_batch_height(
        &self,
        pool_reader: &PoolReader<'_>,
        changeset: &mut ChangeSet,
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
            };
            fn above_range_min(h: Height, range: &Option<HeightRange>) -> bool {
                range.as_ref().map(|r| h > r.min).unwrap_or(false)
            };
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
            // artifacts below or equal to expected batch height can be purged.
            changeset.push(ChangeAction::PurgeUnvalidatedBelow(expected_batch_height));
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
        changeset: &mut ChangeSet,
    ) -> bool {
        if let Some(purge_height) = get_purge_height(pool_reader) {
            if purge_height < self.state_manager.latest_state_height() {
                changeset.push(ChangeAction::PurgeValidatedBelow(purge_height));
                trace!(self.log, "Purge validated pool below {:?}", purge_height);
                self.metrics
                    .validated_pool_purge_height
                    .set(purge_height.get() as i64);
                true
            } else {
                warn!(
                    self.log,
                    "Execution state is not yet available at {:?} that is below \
                    CUP height at {:?}. Cancel purge.",
                    purge_height,
                    pool_reader.get_catch_up_height()
                );
                false
            }
        } else {
            false
        }
    }

    /// Ask state manager to purge all states below the certified height
    /// recorded in the block in the latest CatchUpPackage.
    fn purge_replicated_state_by_catch_up_height(&self, pool_reader: &PoolReader<'_>) {
        let catch_up_package = pool_reader.get_highest_catch_up_package();
        let state_purge_height = catch_up_package
            .content
            .block
            .as_ref()
            .context
            .certified_height;
        self.state_manager.remove_states_below(state_purge_height);
        trace!(
            self.log,
            "Purge replicated states below {:?}",
            state_purge_height
        );
        self.metrics
            .replicated_state_purge_height
            .set(state_purge_height.get() as i64);
    }
}

/// We always keep a minimum chain length below catch-up height.
const MINIMUM_CHAIN_LENGTH: u64 = 50;

/// Compute the purge height by looking at available CatchUpPackage(s) in the
/// validated pool. Usually things with height less than a min_length below the
/// latest catch up height can be purged, but if there is nothing to purge,
/// this function will return None.
///
/// Note that for actual purging, we must also consider execution state
/// so that we don't purge below latest known state height. Otherwise
/// we cannot replay past blocks to catch up state during a replica restart.
pub fn get_purge_height(pool_reader: &PoolReader<'_>) -> Option<Height> {
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
    use crate::consensus::{
        mocks::{dependencies, Dependencies},
        pool_reader::PoolReader,
    };
    use ic_interfaces::consensus_pool::MutableConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::message_routing::MockMessageRouting;
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_purger() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                time_source,
                state_manager,
                ..
            } = dependencies(pool_config, 1);

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(Some(CryptoHashOfState::from(CryptoHash(Vec::new())))));
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
            let state_purge_height = Arc::new(RwLock::new(Height::from(0)));
            let state_purge_height_clone = Arc::clone(&state_purge_height);
            state_manager
                .get_mut()
                .expect_remove_states_below()
                .withf(move |height| *height == *state_purge_height_clone.read().unwrap())
                .return_const(());
            let mut message_routing = MockMessageRouting::new();
            let expected_batch_height = Arc::new(RwLock::new(Height::from(0)));
            let expected_batch_height_clone = Arc::clone(&expected_batch_height);
            message_routing
                .expect_expected_batch_height()
                .returning(move || *expected_batch_height_clone.read().unwrap());

            let purger = Purger::new(
                state_manager,
                Arc::new(message_routing),
                no_op_logger(),
                MetricsRegistry::new(),
            );

            // Put some stuff in the pool
            pool.advance_round_normal_operation_n(9);

            // Only unvalidated pool is purged
            let pool_reader = PoolReader::new(&pool);
            *expected_batch_height.write().unwrap() = Height::from(10);
            let changeset = purger.on_state_change(&pool_reader);
            assert_eq!(changeset.len(), 1);
            assert_eq!(
                changeset[0],
                ChangeAction::PurgeUnvalidatedBelow(*expected_batch_height.read().unwrap())
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
            *state_purge_height.write().unwrap() = pool_reader
                .get_highest_catch_up_package()
                .content
                .block
                .as_ref()
                .context
                .certified_height;
            *expected_batch_height.write().unwrap() = Height::from(65);
            let changeset = purger.on_state_change(&pool_reader);
            assert_eq!(changeset.len(), 2);
            assert_eq!(
                changeset[0],
                ChangeAction::PurgeUnvalidatedBelow(*expected_batch_height.read().unwrap())
            );
            assert_eq!(
                changeset[1],
                ChangeAction::PurgeValidatedBelow(get_purge_height(&pool_reader).unwrap())
            );

            // No more purge action when called again
            pool.apply_changes(time_source.as_ref(), changeset);
            let pool_reader = PoolReader::new(&pool);
            let changeset = purger.on_state_change(&pool_reader);
            assert_eq!(changeset.len(), 0);
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
}
