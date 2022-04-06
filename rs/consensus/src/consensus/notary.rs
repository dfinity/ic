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
//!   (or equal) rank than what it has previously issued shares for in the same
//!   round.
//! * A node must not issue new notarization share for any round older than the
//!   latest round, which would break security if it has already finality-signed
//!   for that round.
use crate::consensus::{
    membership::{Membership, MembershipError},
    metrics::NotaryMetrics,
    pool_reader::PoolReader,
    prelude::*,
    utils::{find_lowest_ranked_proposals, get_adjusted_notary_delay},
    ConsensusCrypto,
};
use ic_interfaces::time_source::TimeSource;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{error, trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::replica_config::ReplicaConfig;
use std::sync::Arc;

pub struct Notary {
    time_source: Arc<dyn TimeSource>,
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
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
            for proposal in find_lowest_ranked_proposals(pool, height) {
                if let Some(elapsed) = self.time_to_notarize(pool, height, proposal.rank()) {
                    if !self.is_proposal_already_notarized_by_me(pool, &proposal) {
                        let block = proposal.as_ref();
                        if let Some(s) = self.notarize_block(pool, block) {
                            self.metrics.report_notarization(block, elapsed);
                            notarization_shares.push(s);
                        }
                    }
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
    ) -> Option<std::time::Duration> {
        let adjusted_notary_delay = get_adjusted_notary_delay(
            self.membership.as_ref(),
            pool,
            self.state_manager.as_ref(),
            &self.log,
            height,
            rank,
        )?;
        if let Some(start_time) = pool.get_round_start_time(height) {
            let now = self.time_source.get_relative_time();
            if now >= start_time + adjusted_notary_delay {
                return Some(now - start_time);
            }
        }
        None
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
    fn notarize_block<'a>(
        &self,
        pool: &PoolReader<'_>,
        block: &'a Block,
    ) -> Option<NotarizationShare> {
        let registry_version = pool.registry_version(block.height)?;
        let content = NotarizationContent::new(block.height, ic_crypto::crypto_hash(block));
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
    fn is_proposal_already_notarized_by_me<'a>(
        &self,
        pool: &PoolReader<'_>,
        proposal: &'a BlockProposal,
    ) -> bool {
        let height = proposal.height();

        pool.get_notarization_shares(height)
            .filter(|s| s.signature.signer == self.replica_config.node_id)
            .any(|s| s.block_hash() == proposal.block_hash())
    }

    /// Maliciously notarize all unnotarized proposals for the current height.
    #[cfg(feature = "malicious_code")]
    pub(crate) fn maliciously_notarize_all(&self, pool: &PoolReader<'_>) -> Vec<NotarizationShare> {
        use ic_interfaces::consensus_pool::HeightRange;
        use ic_protobuf::log::malicious_behaviour_log_entry::v1::{
            MaliciousBehaviour, MaliciousBehaviourLogEntry,
        };
        trace!(self.log, "maliciously_notarize");
        let mut notarization_shares = Vec::<NotarizationShare>::new();

        let range = HeightRange::new(
            pool.get_notarized_height().increment(),
            pool.get_random_beacon_height().increment(),
        );

        let proposals = pool
            .pool()
            .validated()
            .block_proposal()
            .get_by_height_range(range);
        for proposal in proposals {
            if !self.is_proposal_already_notarized_by_me(pool, &proposal) {
                let block = proposal.as_ref();
                if let Some(share) = self.notarize_block(pool, block) {
                    notarization_shares.push(share);
                }
            }
        }

        if !notarization_shares.is_empty() {
            ic_logger::info!(
                self.log,
                "[MALICIOUS] maliciously notarizing all {} proposals",
                notarization_shares.len();
                malicious_behaviour => MaliciousBehaviourLogEntry { malicious_behaviour: MaliciousBehaviour::NotarizeAll as i32}
            );
        }

        notarization_shares
    }
}

#[cfg(test)]
mod tests {
    //! Notary unit tests
    use super::*;
    use crate::consensus::mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{
        consensus::fake::*,
        types::ids::{node_test_id, subnet_test_id},
    };
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use std::sync::Arc;
    use std::time::Duration;

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
}
