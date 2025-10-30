//! In the internet computer consensus protocol, individual nodes may propose
//! blocks in the form of block proposals. They are only considered notarized if
//! a group of nodes (aka. notary group) signed to indicate that they believe
//! the proposed block is valid. Every round must have at least one notarized
//! block and may produce many notarized blocks.
//!
//! This module provides functionality that determines if a block proposal
//! should be notarized by the calling node, and if so, publishes a notary
//! share for the block proposal.
//!
//! # Properties
//!
//! Liveness
//! * A node will issue a notarization share for some block of the latest round
//!   if it is selected as a notary and the waiting time has passed.
//!
//! Security
//! * A node must only issue notarization shares for rounds for which this node
//!   is selected as a notary.
//! * A node must only issue notarization shares for blocks that have a lower
//!   (or equal) rank than every non-disqualified block for which the node
//!   has previously issued shares for in the same round.
//! * A node must not issue new notarization share for any round older than the
//!   latest round, which would break security if it has already finality-signed
//!   for that round.
use crate::consensus::{
    ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP, ACCEPTABLE_NOTARIZATION_CUP_GAP,
    metrics::NotaryMetrics,
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto,
    find_lowest_ranked_non_disqualified_proposals, get_notarization_delay_settings,
    membership::{Membership, MembershipError},
    pool_reader::PoolReader,
};
use ic_interfaces::time_source::TimeSource;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{ReplicaLogger, error, trace, warn};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::NotarizationDelaySettings;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height,
    consensus::{
        BlockProposal, HasBlockHash, HasHeight, HasRank, HashedBlock, NotarizationContent,
        NotarizationShare, RandomBeacon, Rank,
    },
    replica_config::ReplicaConfig,
};
use std::{sync::Arc, time::Duration};

use super::status;

/// The acceptable gap between the finalized height and the certified height. If
/// the actual gap is greater than this, consensus starts slowing down the block
/// rate.
const ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP: u64 = 1;

/// The amount of time consensus should delay notarization of the next block by,
/// for each height that the latest finalized block is ahead of the latest certified state.
/// The value was chosen empirically.
const BACKLOG_DELAY_MILLIS: u64 = 2_000;
pub(crate) struct Notary {
    time_source: Arc<dyn TimeSource>,
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    pub(crate) crypto: Arc<dyn ConsensusCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    log: ReplicaLogger,
    metrics: NotaryMetrics,
}

impl Notary {
    pub fn new(
        time_source: Arc<dyn TimeSource>,
        replica_config: ReplicaConfig,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Notary {
        Notary {
            time_source,
            replica_config,
            membership,
            crypto,
            state_manager,
            log,
            metrics: NotaryMetrics::new(metrics_registry),
        }
    }

    /// If this node is a member of the notary group for the current round,
    /// attempt to find the best blocks that we can notarize, and notarize them.
    /// Else, do nothing.
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Vec<NotarizationShare> {
        trace!(self.log, "on_state_change");
        let notarized_height = pool.get_notarized_height();
        let mut notarization_shares = Vec::new();
        if let Some(previous_beacon) = pool.get_random_beacon(notarized_height) {
            if !self.is_notary(pool, &previous_beacon) {
                return notarization_shares;
            }
            let height = notarized_height.increment();
            for proposal in find_lowest_ranked_non_disqualified_proposals(pool, height) {
                if let Some(elapsed) = self.time_to_notarize(pool, height, proposal.rank())
                    && !self.is_proposal_already_notarized_by_me(pool, &proposal)
                    && let Some(s) = self.notarize_block(pool, &proposal.content)
                {
                    self.metrics.report_notarization(proposal.as_ref(), elapsed);
                    notarization_shares.push(s);
                }
            }
        }
        notarization_shares
    }

    /// Return the time since round start, if it is greater than required
    /// notarization delay for the given block rank, or None otherwise.
    fn time_to_notarize(
        &self,
        pool: &PoolReader<'_>,
        height: Height,
        rank: Rank,
    ) -> Option<Duration> {
        let adjusted_notary_delay = get_adjusted_notary_delay(
            self.membership.as_ref(),
            pool,
            self.state_manager.as_ref(),
            &self.log,
            height,
            rank,
        )?;

        let now_relative = self.time_source.get_relative_time();
        let now_instant = self.time_source.get_instant();

        pool.get_round_start_time(height)
            .filter(|&start| now_relative >= start + adjusted_notary_delay)
            .map(|start| now_relative.saturating_duration_since(start))
            // If the relative time indicates that not enough time has passed, we fall
            // back to the monotonic round start time. We do this to safeguard
            // against a stalled relative clock.
            .or(pool
                .get_round_start_instant(height, self.time_source.get_origin_instant())
                .filter(|&start| now_instant >= start + adjusted_notary_delay)
                .map(|start| now_instant.saturating_duration_since(start)))
    }

    /// Return `true` if this node is a member of the notary group for the
    /// current round (given the previous beacon). Return `false` if not or we
    /// failed to determine the committee for this round.
    fn is_notary(&self, pool: &PoolReader<'_>, previous_beacon: &RandomBeacon) -> bool {
        match self.membership.node_belongs_to_notarization_committee(
            previous_beacon.height().increment(),
            previous_beacon,
            self.replica_config.node_id,
        ) {
            Ok(value) => value,
            Err(MembershipError::UnableToRetrieveDkgSummary(h)) => {
                error!(
                    self.log,
                    "Couldn't find transcript at height {} with finalized height {} and CUP height {}",
                    h,
                    pool.get_finalized_height(),
                    pool.get_catch_up_height()
                );
                false
            }
            Err(err) => {
                warn!(self.log, "Membership error: {:?}", err);
                false
            }
        }
    }

    /// Notarize and return a `NotarizationShare` for the given block
    pub(crate) fn notarize_block(
        &self,
        pool: &PoolReader<'_>,
        block: &HashedBlock,
    ) -> Option<NotarizationShare> {
        let registry_version = pool.registry_version(block.height())?;
        let content = NotarizationContent::new(block.height(), block.get_hash().clone());
        match self
            .crypto
            .sign(&content, self.replica_config.node_id, registry_version)
        {
            Ok(signature) => Some(NotarizationShare { content, signature }),
            Err(err) => {
                error!(self.log, "Couldn't create a signature: {:?}", err);
                None
            }
        }
    }

    /// Return true if this node has already published a notarization share
    /// for the given block proposal. Return false otherwise.
    pub(crate) fn is_proposal_already_notarized_by_me(
        &self,
        pool: &PoolReader<'_>,
        proposal: &BlockProposal,
    ) -> bool {
        let height = proposal.height();

        pool.get_notarization_shares(height)
            .filter(|s| s.signature.signer == self.replica_config.node_id)
            .any(|s| s.block_hash() == proposal.block_hash())
    }
}

#[derive(PartialEq, Debug)]
enum NotaryDelay {
    /// Notary can notarize after this delay.
    CanNotarizeAfter(Duration),
    /// Gap between notarization and certification is too large. Because we have a
    /// hard limit on this gap, the notary cannot progress for now.
    ReachedMaxNotarizationCertificationGap {
        notarized_height: Height,
        certified_height: Height,
    },
    /// Gap between notarization and the next CUP is too large. Because we have a
    /// hard limit on this gap, the notary cannot progress for now.
    ReachedMaxNotarizationCUPGap {
        notarized_height: Height,
        next_cup_height: Height,
    },
}

/// Calculate the required delay for notary based on the rank of block to notarize,
/// adjusted by a multiplier depending on the gap between finalized and notarized
/// heights, adjusted by how far the certified height lags behind the finalized
/// height. Return `None` when the registry is unavailable, or when the notary has
/// reached a hard limit (either notarization/certification or notarization/CUP gap
/// limits).
/// Use membership and height to determine the notarization settings that should be used.
fn get_adjusted_notary_delay(
    membership: &Membership,
    pool: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    log: &ReplicaLogger,
    height: Height,
    rank: Rank,
) -> Option<Duration> {
    match get_adjusted_notary_delay_from_settings(
        get_notarization_delay_settings(
            log,
            &*membership.registry_client,
            membership.subnet_id,
            pool.registry_version(height)?,
        ),
        pool,
        state_manager,
        membership,
        rank,
        log,
    ) {
        NotaryDelay::CanNotarizeAfter(duration) => Some(duration),
        NotaryDelay::ReachedMaxNotarizationCertificationGap {
            notarized_height,
            certified_height,
        } => {
            warn!(
                every_n_seconds => 5,
                log,
                "The gap between the notarization height ({notarized_height}) and \
                 the certification height ({certified_height}) exceeds hard bound of \
                 {ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP}"
            );
            None
        }
        NotaryDelay::ReachedMaxNotarizationCUPGap {
            notarized_height,
            next_cup_height,
        } => {
            warn!(
                every_n_seconds => 5,
                log,
                "The gap between the notarization height ({notarized_height}) and \
                the next CUP height ({next_cup_height}) exceeds hard bound of \
                {ACCEPTABLE_NOTARIZATION_CUP_GAP}"
            );
            None
        }
    }
}

/// Calculate the required delay for notary based on the rank of block to notarize,
/// adjusted by a multiplier depending on the gap between finalized and notarized
/// heights, adjusted by how far the certified height lags behind the finalized
/// height.
fn get_adjusted_notary_delay_from_settings(
    settings: NotarizationDelaySettings,
    pool: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    membership: &Membership,
    rank: Rank,
    logger: &ReplicaLogger,
) -> NotaryDelay {
    let NotarizationDelaySettings {
        unit_delay,
        initial_notary_delay,
        ..
    } = settings;

    // We impose a hard limit on the gap between notarization and certification.
    let notarized_height = pool.get_notarized_height();
    let certified_height = state_manager.latest_certified_height();
    if notarized_height
        .get()
        .saturating_sub(certified_height.get())
        >= ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP
    {
        return NotaryDelay::ReachedMaxNotarizationCertificationGap {
            notarized_height,
            certified_height,
        };
    }

    // We adjust regular delay based on the gap between finalization and
    // notarization to make it exponentially longer to keep the gap from growing too
    // big. This is because increasing delay leads to higher chance of notarizing
    // only 1 block, which leads to higher chance of getting a finalization for that
    // round.  This exponential backoff does not apply to block rank 0.
    let finalized_height = pool.get_finalized_height().get();
    let initial_delay = initial_notary_delay.as_millis() as f32;
    let ranked_delay = unit_delay.as_millis() as f32 * rank.0 as f32;
    let finality_gap = (notarized_height.get() - finalized_height) as i32;
    let finality_adjusted_delay =
        (initial_delay + ranked_delay * 1.5_f32.powi(finality_gap)) as u64;

    // We adjust the delay based on the gap between the finalized height and the
    // certified height: when the certified height is more than
    // ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP rounds behind the
    // finalized height, we increase the delay. More precisely, for every
    // round that certified height is behind finalized height, we add `unit_delay`.
    let certified_gap =
        finalized_height.saturating_sub(state_manager.latest_certified_height().get());

    // Determine if we are currently in the process of halting at the next CUP height, i.e.
    // due to a pending upgrade or registry flag. In this case, we should not adjust the
    // notary delay based on the certified-finalized gap. During an upgrade, execution will
    // halt at the CUP height by design while consensus continues to deliver empty blocks.
    // This will naturally increase the gap between certified and finalized height, and
    // slowing down the block rate would only delay the upgrade.
    let halting = || {
        status::should_halt(
            notarized_height,
            membership.registry_client.as_ref(),
            membership.subnet_id,
            pool,
            logger,
        ) == Some(true)
    };

    let certified_adjusted_delay =
        if certified_gap <= ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP || halting() {
            finality_adjusted_delay
        } else {
            finality_adjusted_delay + BACKLOG_DELAY_MILLIS * certified_gap
        };

    // We bound the gap between the next CUP height and the current notarization
    // height by ACCEPTABLE_NOTARIZATION_CUP_GAP.
    let next_cup_height = pool.get_next_cup_height();
    if notarized_height.get().saturating_sub(next_cup_height.get())
        >= ACCEPTABLE_NOTARIZATION_CUP_GAP
    {
        return NotaryDelay::ReachedMaxNotarizationCUPGap {
            notarized_height,
            next_cup_height,
        };
    }

    NotaryDelay::CanNotarizeAfter(Duration::from_millis(certified_adjusted_delay))
}

#[cfg(test)]
mod tests {
    //! Notary unit tests
    use super::*;
    use assert_matches::assert_matches;
    use ic_consensus_mocks::{Dependencies, dependencies_with_subnet_params};
    use ic_interfaces::{consensus_pool::ConsensusPool, time_source::TimeSource};
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_consensus::fake::*;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use std::{
        sync::{Arc, RwLock},
        time::Duration,
    };

    /// Do basic notary validations
    #[test]
    fn test_notary_behavior() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = vec![node_test_id(0)];
            let dkg_interval_length = 30;
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                time_source,
                crypto,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                )],
            );
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(Height::new(0));

            pool.advance_round_normal_operation();

            let h = PoolReader::new(&pool).get_notarized_height();
            assert_eq!(h, Height::from(1));

            // 1. insert a new block proposal and check if notarization share is created
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());

            let metrics_registry = MetricsRegistry::new();

            let notary = Notary::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config,
                membership.clone(),
                crypto,
                state_manager.clone(),
                metrics_registry,
                no_op_logger(),
            );
            // Time has not expired for rank 0 initially
            let run_notary = |pool: &dyn ConsensusPool| {
                let reader = PoolReader::new(pool);
                notary.on_state_change(&reader)
            };
            assert!(run_notary(&pool).is_empty());

            // Time has expired for rank 0, do something
            time_source
                .set_time(
                    time_source.get_relative_time()
                        + get_adjusted_notary_delay(
                            membership.as_ref(),
                            &PoolReader::new(&pool),
                            state_manager.as_ref(),
                            &no_op_logger(),
                            Height::from(1),
                            Rank(0),
                        )
                        .unwrap(),
                )
                .unwrap();
            assert!(match run_notary(&pool).as_slice() {
                [share] => {
                    pool.insert_validated(share.clone());
                    true
                }
                _ => false,
            });

            // 2. Make sure we do not create a duplicate share
            assert!(run_notary(&pool).is_empty());

            pool.notarize(&block);
            assert_eq!(
                PoolReader::new(&pool).get_notarized_height(),
                Height::from(2)
            );

            // 3. Make sure the lowest block is selected for notarization
            pool.insert_beacon_chain(&pool.make_next_beacon(), Height::from(3));

            // Insert block with rank 20
            let base_block = pool.make_next_block();
            let mut twenty_block = base_block.clone();
            twenty_block.content.as_mut().rank = Rank(20);
            twenty_block.update_content();
            pool.insert_validated(twenty_block.clone());
            run_notary(&pool);

            // Insert block with lower rank 10
            let mut ten_block = base_block.clone();
            ten_block.content.as_mut().rank = Rank(10);
            ten_block.update_content();
            pool.insert_validated(ten_block.clone());

            // Time has not expired for the lowest ranked block
            time_source
                .set_time(
                    time_source.get_relative_time()
                        + get_adjusted_notary_delay(
                            membership.as_ref(),
                            &PoolReader::new(&pool),
                            state_manager.as_ref(),
                            &no_op_logger(),
                            Height::from(1),
                            Rank(9),
                        )
                        .unwrap(),
                )
                .unwrap();
            assert!(run_notary(&pool).is_empty());

            // Time has expired for both rank 10 and 20
            time_source
                .set_time(
                    time_source.get_relative_time()
                        + get_adjusted_notary_delay(
                            membership.as_ref(),
                            &PoolReader::new(&pool),
                            state_manager.as_ref(),
                            &no_op_logger(),
                            Height::from(1),
                            twenty_block.rank(),
                        )
                        .unwrap(),
                )
                .unwrap();
            assert!(match run_notary(&pool).as_slice() {
                [share] => {
                    assert_eq!(&share.content.block, ten_block.content.get_hash());
                    pool.insert_validated(share.clone());
                    true
                }
                _ => false,
            });

            // 4. Make sure blocks with lower ranks do get notarized even after higher ranks
            // are notarized
            let mut five_block = base_block.clone();
            five_block.content.as_mut().rank = Rank(5);
            five_block.update_content();
            pool.insert_validated(five_block.clone());

            assert!(match run_notary(&pool).as_slice() {
                [share] => {
                    assert_eq!(&share.content.block, five_block.content.get_hash());
                    pool.insert_validated(share.clone());
                    true
                }
                _ => false,
            });

            // 5. Test how we deal with equivocating block makers, resulting in multiple
            // blocks with the same rank

            // create and insert a rank 1 block, and ensure a notarization share is created
            // for it
            let mut one_block = base_block;
            one_block.content.as_mut().rank = Rank(1);
            one_block.update_content();
            pool.insert_validated(one_block.clone());
            println!("one_block.hash {:?}", one_block.content.get_hash());

            assert!(match run_notary(&pool).as_slice() {
                [share] => {
                    assert_eq!(&share.content.block, one_block.content.get_hash());
                    pool.insert_validated(share.clone());
                    true
                }
                _ => false,
            });

            // create and insert another rank 1 block (by modifying the time stamp in the
            // other rank 1 block), and ensure that this one will also be
            // notarized
            let mut one_block_prime = one_block.clone();
            one_block_prime.content.as_mut().context.time =
                one_block.content.as_ref().context.time + Duration::from_millis(1);
            one_block_prime.update_content();
            pool.insert_validated(one_block_prime.clone());

            assert!(match run_notary(&pool).as_slice() {
                [share] => {
                    assert_eq!(&share.content.block, one_block_prime.content.get_hash());
                    pool.insert_validated(share.clone());
                    true
                }
                _ => false,
            });
        })
    }

    #[test]
    fn test_out_of_sync_notarization() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = vec![node_test_id(0)];
            let dkg_interval_length = 30;
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                time_source,
                crypto,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                )],
            );
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(Height::new(0));
            let metrics_registry = MetricsRegistry::new();
            let notary = Notary::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config,
                membership.clone(),
                crypto,
                state_manager.clone(),
                metrics_registry,
                no_op_logger(),
            );
            let run_notary = |pool: &dyn ConsensusPool| {
                let reader = PoolReader::new(pool);
                notary.on_state_change(&reader)
            };

            // Play 5 rounds, finalizing one block per second.
            for _ in 0..5 {
                time_source.advance_time(Duration::from_secs(1));
                pool.advance_round_normal_operation();
            }

            // Insert new block. Must not get notarized, because no additional
            // time has passed.
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            assert!(run_notary(&pool).is_empty());

            // Stall the relative clock, and only advance monotonic clock past
            // the notary delay. This should get notarized.
            time_source.advance_only_monotonic(
                get_adjusted_notary_delay(
                    membership.as_ref(),
                    &PoolReader::new(&pool),
                    state_manager.as_ref(),
                    &no_op_logger(),
                    Height::from(5),
                    Rank(0),
                )
                .unwrap(),
            );
            assert!(!run_notary(&pool).is_empty());
        })
    }

    #[test]
    fn test_get_adjusted_notary_delay_cup_delay() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let logger = no_op_logger();
            let settings = NotarizationDelaySettings {
                unit_delay: Duration::from_secs(1),
                initial_notary_delay: Duration::from_secs(0),
            };
            let committee = (0..3).map(node_test_id).collect::<Vec<_>>();
            /* use large enough DKG interval to trigger notarization/CUP gap limit */
            let record = SubnetRecordBuilder::from(&committee)
                .with_dkg_interval_length(ACCEPTABLE_NOTARIZATION_CUP_GAP + 30)
                .build();

            let Dependencies {
                mut pool,
                state_manager,
                membership,
                ..
            } = dependencies_with_subnet_params(pool_config, subnet_test_id(0), vec![(1, record)]);
            let last_cup_dkg_info = PoolReader::new(&pool)
                .get_highest_catch_up_package()
                .content
                .block
                .as_ref()
                .payload
                .as_ref()
                .as_summary()
                .dkg
                .clone();

            // Advance to next summary height
            pool.advance_round_normal_operation_no_cup_n(
                last_cup_dkg_info.interval_length.get() + 1,
            );
            assert!(pool.get_cache().finalized_block().payload.is_summary());
            // Advance to one height before the highest possible CUP-less notarized height
            pool.advance_round_normal_operation_no_cup_n(ACCEPTABLE_NOTARIZATION_CUP_GAP - 1);

            let gap_trigger_height = Height::new(
                PoolReader::new(&pool).get_notarized_height().get()
                    - ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP
                    - 1,
            );
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(gap_trigger_height);

            assert_matches!(
                get_adjusted_notary_delay_from_settings(
                    settings.clone(),
                    &PoolReader::new(&pool),
                    state_manager.as_ref(),
                    membership.as_ref(),
                    Rank(0),
                    &logger,
                ),
                NotaryDelay::ReachedMaxNotarizationCertificationGap { .. }
            );

            state_manager.get_mut().checkpoint();
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(PoolReader::new(&pool).get_finalized_height());

            assert_eq!(
                get_adjusted_notary_delay_from_settings(
                    settings.clone(),
                    &PoolReader::new(&pool),
                    state_manager.as_ref(),
                    membership.as_ref(),
                    Rank(0),
                    &logger,
                ),
                NotaryDelay::CanNotarizeAfter(Duration::from_secs(0))
            );

            state_manager.get_mut().checkpoint();
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(PoolReader::new(&pool).get_finalized_height());

            pool.advance_round_normal_operation_no_cup();

            assert_matches!(
                get_adjusted_notary_delay_from_settings(
                    settings,
                    &PoolReader::new(&pool),
                    state_manager.as_ref(),
                    membership.as_ref(),
                    Rank(0),
                    &logger,
                ),
                NotaryDelay::ReachedMaxNotarizationCUPGap { .. }
            );
        });
    }

    #[test]
    fn test_get_adjusted_notary_delay_certified_finalized_gap() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let logger = no_op_logger();
            let backlog_delay = Duration::from_millis(BACKLOG_DELAY_MILLIS);
            let initial_notary_delay = Duration::from_secs(1);
            let dkg_interval = 19;
            let settings = NotarizationDelaySettings {
                unit_delay: Duration::from_secs(1),
                initial_notary_delay,
            };
            let committee = (0..3).map(node_test_id).collect::<Vec<_>>();
            let record = SubnetRecordBuilder::from(&committee)
                .with_dkg_interval_length(dkg_interval)
                .build();

            let Dependencies {
                mut pool,
                state_manager,
                membership,
                ..
            } = dependencies_with_subnet_params(pool_config, subnet_test_id(0), vec![(1, record)]);

            let certified_height = Arc::new(RwLock::new(Height::from(0)));
            let certified_height_clone = Arc::clone(&certified_height);
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .returning(move || *certified_height_clone.read().unwrap());

            let notary_delay = get_adjusted_notary_delay_from_settings(
                settings.clone(),
                &PoolReader::new(&pool),
                state_manager.as_ref(),
                membership.as_ref(),
                Rank(0),
                &logger,
            );
            assert_eq!(
                notary_delay,
                NotaryDelay::CanNotarizeAfter(initial_notary_delay)
            );

            // Advance to finalized height by the acceptable gap
            pool.advance_round_normal_operation_n(ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP);
            let notary_delay = get_adjusted_notary_delay_from_settings(
                settings.clone(),
                &PoolReader::new(&pool),
                state_manager.as_ref(),
                membership.as_ref(),
                Rank(0),
                &logger,
            );
            assert_eq!(
                notary_delay,
                NotaryDelay::CanNotarizeAfter(initial_notary_delay)
            );

            // Advance to finalized height by one more round
            pool.advance_round_normal_operation_n(1);
            let notary_delay = get_adjusted_notary_delay_from_settings(
                settings.clone(),
                &PoolReader::new(&pool),
                state_manager.as_ref(),
                membership.as_ref(),
                Rank(0),
                &logger,
            );
            assert_eq!(
                notary_delay,
                NotaryDelay::CanNotarizeAfter(
                    initial_notary_delay + backlog_delay.saturating_mul(2)
                )
            );
            // Advance to finalized height by one more round
            pool.advance_round_normal_operation_n(1);
            let notary_delay = get_adjusted_notary_delay_from_settings(
                settings.clone(),
                &PoolReader::new(&pool),
                state_manager.as_ref(),
                membership.as_ref(),
                Rank(0),
                &logger,
            );
            assert_eq!(
                notary_delay,
                NotaryDelay::CanNotarizeAfter(
                    initial_notary_delay + backlog_delay.saturating_mul(3)
                )
            );

            // Execution catches up
            *certified_height.write().unwrap() =
                Height::from(ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP + 2);
            let notary_delay = get_adjusted_notary_delay_from_settings(
                settings.clone(),
                &PoolReader::new(&pool),
                state_manager.as_ref(),
                membership.as_ref(),
                Rank(0),
                &logger,
            );
            assert_eq!(
                notary_delay,
                NotaryDelay::CanNotarizeAfter(initial_notary_delay)
            );
        });
    }

    #[test]
    fn test_get_adjusted_notary_delay_upgrades() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let logger = no_op_logger();
            let backlog_delay = Duration::from_millis(BACKLOG_DELAY_MILLIS);
            let initial_notary_delay = Duration::from_secs(1);
            let dkg_interval = 19;
            let settings = NotarizationDelaySettings {
                unit_delay: Duration::from_secs(1),
                initial_notary_delay,
            };
            let committee = (0..3).map(node_test_id).collect::<Vec<_>>();
            let Dependencies {
                mut pool,
                state_manager,
                membership,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![
                    (
                        1,
                        SubnetRecordBuilder::from(&committee)
                            .with_dkg_interval_length(dkg_interval)
                            .build(),
                    ),
                    (
                        10,
                        SubnetRecordBuilder::from(&committee)
                            .with_dkg_interval_length(dkg_interval)
                            .with_replica_version("new_version")
                            .build(),
                    ),
                ],
            );

            let certified_height = Arc::new(RwLock::new(Height::from(0)));
            let certified_height_clone = Arc::clone(&certified_height);
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .returning(move || *certified_height_clone.read().unwrap());

            // Advance pool to the next CUP height
            pool.advance_round_normal_operation_n(dkg_interval + 1);
            *certified_height.write().unwrap() = Height::from(dkg_interval + 1);

            // Advance pool past acceptable gap
            pool.advance_round_normal_operation_n(ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP + 2);

            // Notary delay should be increased
            let notary_delay = get_adjusted_notary_delay_from_settings(
                settings.clone(),
                &PoolReader::new(&pool),
                state_manager.as_ref(),
                membership.as_ref(),
                Rank(0),
                &logger,
            );
            assert_eq!(
                notary_delay,
                NotaryDelay::CanNotarizeAfter(
                    initial_notary_delay + backlog_delay.saturating_mul(3)
                )
            );

            // Advance pool past the upgrade CUP height
            pool.advance_round_normal_operation_n(dkg_interval + 1);
            // Advance certified height to the upgrade CUP height
            *certified_height.write().unwrap() = Height::from(2 * (dkg_interval + 1));

            // Notary delay should not be increased during pending upgrade
            let notary_delay = get_adjusted_notary_delay_from_settings(
                settings.clone(),
                &PoolReader::new(&pool),
                state_manager.as_ref(),
                membership.as_ref(),
                Rank(0),
                &logger,
            );
            assert_eq!(
                notary_delay,
                NotaryDelay::CanNotarizeAfter(initial_notary_delay)
            );
        });
    }
}
