//! The share aggregator is responsible for the aggregation of different types
//! of shares into full objects. That is, it constructs Random Beacon objects
//! from random beacon shares, Notarizations from notarization shares and
//! Finalizations from finalization shares.
use crate::consensus::{
    membership::Membership, pool_reader::PoolReader, prelude::*, utils, ConsensusCrypto,
};
use ic_interfaces::messaging::MessageRouting;
use ic_logger::ReplicaLogger;
use std::cmp::min;
use std::sync::Arc;

/// The ShareAggregator is responsible for aggregating shares of random beacons,
/// notarizations, and finalizations into full objects
pub struct ShareAggregator {
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    message_routing: Arc<dyn MessageRouting>,
    log: ReplicaLogger,
}

impl ShareAggregator {
    pub fn new(
        membership: Arc<Membership>,
        message_routing: Arc<dyn MessageRouting>,
        crypto: Arc<dyn ConsensusCrypto>,
        log: ReplicaLogger,
    ) -> ShareAggregator {
        ShareAggregator {
            membership,
            crypto,
            message_routing,
            log,
        }
    }

    /// Attempt to construct artifacts from artifact shares in the artifact
    /// pool
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Vec<ConsensusMessage> {
        let mut messages = Vec::new();
        messages.append(&mut self.aggregate_random_beacon_shares(pool));
        messages.append(&mut self.aggregate_random_tape_shares(pool));
        messages.append(&mut self.aggregate_notarization_shares(pool));
        messages.append(&mut self.aggregate_finalization_shares(pool));
        messages.append(&mut self.aggregate_catch_up_package_shares(pool));
        messages
    }

    /// Attempt to construct the next round's `RandomBeacon`
    fn aggregate_random_beacon_shares(&self, pool: &PoolReader<'_>) -> Vec<ConsensusMessage> {
        let height = pool.get_random_beacon_height().increment();
        let shares = pool.get_random_beacon_shares(height);
        let state_reader = pool.as_cache();
        let dkg_id = utils::active_low_threshold_transcript(state_reader, height)
            .map(|transcript| transcript.dkg_id);
        to_messages(utils::aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|_| dkg_id),
            shares,
        ))
    }

    /// Attempt to construct random tapes for rounds greater than or equal to
    /// expected_batch_height.
    fn aggregate_random_tape_shares(&self, pool: &PoolReader<'_>) -> Vec<ConsensusMessage> {
        let expected_height = self.message_routing.expected_batch_height();
        let finalized_height = pool.get_finalized_height();
        let max_height = min(
            expected_height + Height::from(RANDOM_TAPE_CHECK_MAX_HEIGHT_RANGE),
            finalized_height.increment(),
        );
        // Filter out those at a height where we have a full tape already.
        let shares = pool
            .get_random_tape_shares(expected_height, max_height)
            .filter(|share| pool.get_random_tape(share.height()).is_none());
        let state_reader = pool.as_cache();
        to_messages(utils::aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|content: &RandomTapeContent| {
                utils::active_low_threshold_transcript(state_reader, content.height())
                    .map(|transcript| transcript.dkg_id)
            }),
            shares,
        ))
    }

    /// Attempt to construct `Notarization`s at `notarized_height + 1`
    fn aggregate_notarization_shares(&self, pool: &PoolReader<'_>) -> Vec<ConsensusMessage> {
        let height = pool.get_notarized_height().increment();
        let shares = pool.get_notarization_shares(height);
        let state_reader = pool.as_cache();
        let registry_version = utils::registry_version_at_height(state_reader, height);
        to_messages(utils::aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|_| registry_version),
            shares,
        ))
    }

    /// Attempt to construct `Finalization`s
    fn aggregate_finalization_shares(&self, pool: &PoolReader<'_>) -> Vec<ConsensusMessage> {
        let shares = pool.get_finalization_shares(
            pool.get_finalized_height().increment(),
            pool.get_notarized_height(),
        );
        let state_reader = pool.as_cache();
        to_messages(utils::aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|content: &FinalizationContent| {
                utils::registry_version_at_height(state_reader, content.height())
            }),
            shares,
        ))
    }

    /// Attempt to construct `CatchUpPackage`s.
    fn aggregate_catch_up_package_shares(&self, pool: &PoolReader<'_>) -> Vec<ConsensusMessage> {
        let start_block = pool.get_highest_summary_block();
        let height = start_block.height();

        // Skip if we have a full CatchUpPackage already
        if height <= pool.get_catch_up_height() {
            return Vec::new();
        }
        let shares = pool.get_catch_up_package_shares(height).map(|share| {
            let block = pool
                .get_block(&share.content.block, height)
                .unwrap_or_else(|err| panic!("Block not found for {:?}, error: {:?}", share, err));
            Signed {
                content: CatchUpContent::from_share_content(share.content, block),
                signature: share.signature,
            }
        });
        let state_reader = pool.as_cache();
        let dkg_id = utils::active_high_threshold_transcript(state_reader, height)
            .map(|transcript| transcript.dkg_id);
        to_messages(utils::aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|_| dkg_id),
            shares,
        ))
    }
}

fn to_messages<T: ConsensusMessageHashable>(artifacts: Vec<T>) -> Vec<ConsensusMessage> {
    artifacts.into_iter().map(|a| a.into_message()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{
        consensus::fake::*,
        message_routing::FakeMessageRouting,
        registry::SubnetRecordBuilder,
        types::ids::{node_test_id, subnet_test_id},
    };
    use std::sync::Arc;

    #[test]
    /// Adds a random beacon and notarization share to a pool
    /// and asserts that `on_state_change` returns the associated aggregated
    /// artifacts. After that, it adds the aggregated objects to the pool and
    /// adds a finalization share to the pool, and checks that a full
    /// finalization is constructed, and that the previously aggregated
    /// objects are not constructed a second time (now that the full object
    /// is already in the pool).
    fn test_basic_on_state_change() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                membership,
                crypto,
                ..
            } = dependencies(pool_config, 1);

            let block = pool.make_next_block();
            let signer = block.signature.signer;
            let current_beacon = pool.validated().random_beacon().get_highest().unwrap();
            let beacon_share = RandomBeaconShare::fake(&current_beacon, signer);
            let notarization_share = NotarizationShare::fake(block.as_ref(), signer);

            // Initialize pool
            pool.insert_validated(beacon_share);
            pool.insert_validated(block.clone());
            pool.insert_validated(notarization_share);

            let message_routing = Arc::new(FakeMessageRouting::new());

            let aggregator =
                ShareAggregator::new(membership, message_routing, crypto, no_op_logger());
            let messages = aggregator.on_state_change(&PoolReader::new(&pool));

            let beacon_was_created = messages.iter().any(|x| match x {
                ConsensusMessage::RandomBeacon(random_beacon) => {
                    pool.insert_validated(random_beacon.clone());
                    true
                }
                _ => false,
            });

            let notarization_was_created = messages.iter().any(|x| match x {
                ConsensusMessage::Notarization(notarization) => {
                    pool.insert_validated(notarization.clone());
                    true
                }
                _ => false,
            });

            assert!(beacon_was_created);
            assert!(notarization_was_created);
            assert_eq!(messages.len(), 2);

            let finalization_share = FinalizationShare::fake(block.as_ref(), signer);
            pool.insert_validated(finalization_share);

            let messages = aggregator.on_state_change(&PoolReader::new(&pool));
            let finalization_was_created = messages
                .iter()
                .any(|x| matches!(x, ConsensusMessage::Finalization(_)));

            assert!(finalization_was_created);
            assert_eq!(messages.len(), 1);
        })
    }

    #[test]
    /// Test the aggregation of 'CatchUpPackageShare's
    fn test_catch_up_package_aggregation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let node_ids: Vec<_> = (0..3).map(node_test_id).collect();
            let interval_length = 3;
            let Dependencies {
                mut pool,
                membership,
                crypto,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&node_ids)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                )],
            );
            let message_routing = Arc::new(FakeMessageRouting::new());
            let aggregator =
                ShareAggregator::new(membership, message_routing, crypto, no_op_logger());

            // Skip till next DKG interval.
            pool.advance_round_normal_operation_n(interval_length);

            // Prepare beacon and block
            let beacon = pool.make_next_beacon();
            pool.insert_validated(beacon.clone());
            let block = pool.make_next_block();
            assert!(block.content.as_ref().payload.is_summary());
            pool.insert_validated(block.clone());
            pool.notarize(&block);
            pool.finalize(&block);

            // Insert a few CUP shares
            fn new_cup_share(
                start_block: &Block,
                random_beacon: &RandomBeacon,
                node_id: NodeId,
            ) -> CatchUpPackageShare {
                let state_hash = CryptoHashOf::from(CryptoHash(Vec::new()));
                CatchUpPackageShare {
                    content: (&CatchUpContent::new(
                        HashedBlock::new(ic_crypto::crypto_hash, start_block.clone()),
                        HashedRandomBeacon::new(ic_crypto::crypto_hash, random_beacon.clone()),
                        state_hash,
                    ))
                        .into(),
                    signature: ThresholdSignatureShare::fake(node_id),
                }
            }
            let share0 = new_cup_share(block.content.as_ref(), &beacon, node_test_id(0));
            let share1 = new_cup_share(block.content.as_ref(), &beacon, node_test_id(1));
            let share2 = new_cup_share(block.content.as_ref(), &beacon, node_test_id(2));
            pool.insert_validated(share0.clone());
            pool.insert_validated(share1);
            pool.insert_validated(share2);

            // Check if CUP is made from the shares
            let mut messages = aggregator.on_state_change(&PoolReader::new(&pool));
            assert!(messages.len() == 1);
            let cup = match messages.pop() {
                Some(ConsensusMessage::CatchUpPackage(x)) => x,
                x => panic!("Expecting CatchUpPackageShare but got {:?}\n", x),
            };

            assert_eq!(CatchUpShareContent::from(&cup.content), share0.content);
        })
    }
}
