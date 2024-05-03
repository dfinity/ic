//! The share aggregator is responsible for the aggregation of different types
//! of shares into full objects. That is, it constructs Random Beacon objects
//! from random beacon shares, Notarizations from notarization shares and
//! Finalizations from finalization shares.
use crate::consensus::random_tape_maker::RANDOM_TAPE_CHECK_MAX_HEIGHT_RANGE;
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_consensus_utils::{
    active_high_threshold_transcript, active_low_threshold_transcript, aggregate,
    registry_version_at_height,
};
use ic_interfaces::messaging::MessageRouting;
use ic_logger::ReplicaLogger;
use ic_types::consensus::{
    CatchUpContent, ConsensusMessage, ConsensusMessageHashable, FinalizationContent, HasHeight,
    RandomTapeContent,
};
use ic_types::crypto::Signed;
use ic_types::Height;
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
        let dkg_id = active_low_threshold_transcript(state_reader, height)
            .map(|transcript| transcript.dkg_id);
        to_messages(aggregate(
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
        to_messages(aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|content: &RandomTapeContent| {
                active_low_threshold_transcript(state_reader, content.height())
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
        let registry_version = registry_version_at_height(state_reader, height);
        to_messages(aggregate(
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
        to_messages(aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|content: &FinalizationContent| {
                registry_version_at_height(state_reader, content.height())
            }),
            shares,
        ))
    }

    /// Attempt to construct `CatchUpPackage`s.
    fn aggregate_catch_up_package_shares(&self, pool: &PoolReader<'_>) -> Vec<ConsensusMessage> {
        let mut start_block = pool.get_highest_summary_block();
        let current_cup_height = pool.get_catch_up_height();

        while start_block.height() > current_cup_height {
            let height = start_block.height();
            let shares = pool.get_catch_up_package_shares(height).map(|share| {
                let block = pool
                    .get_block(&share.content.block, height)
                    .unwrap_or_else(|err| {
                        panic!("Block not found for {:?}, error: {:?}", share, err)
                    });
                Signed {
                    content: CatchUpContent::from_share_content(share.content, block.into_inner()),
                    signature: share.signature,
                }
            });
            let state_reader = pool.as_cache();
            let dkg_id = active_high_threshold_transcript(state_reader, height)
                .map(|transcript| transcript.dkg_id);
            let result = aggregate(
                &self.log,
                self.membership.as_ref(),
                self.crypto.as_aggregate(),
                Box::new(|_| dkg_id),
                shares,
            );
            if !result.is_empty() {
                return to_messages(result);
            }

            if let Some(block_from_last_interval) =
                pool.get_finalized_block(start_block.height.decrement())
            {
                let next_start_height = block_from_last_interval
                    .payload
                    .as_ref()
                    .dkg_interval_start_height();
                if let Some(new_start_block) = pool.get_finalized_block(next_start_height) {
                    start_block = new_start_block;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        Vec::new()
    }
}

fn to_messages<T: ConsensusMessageHashable>(artifacts: Vec<T>) -> Vec<ConsensusMessage> {
    artifacts.into_iter().map(|a| a.into_message()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::message_routing::FakeMessageRouting;
    use ic_test_utilities_consensus::fake::{FakeContentSigner, FakeSigner};
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::{
            CatchUpPackage, CatchUpPackageShare, CatchUpShareContent, FinalizationShare,
            HashedBlock, HashedRandomBeacon, NotarizationShare, RandomBeaconShare,
        },
        crypto::{CryptoHash, CryptoHashOf},
        signature::ThresholdSignatureShare,
        NodeId, RegistryVersion,
    };
    use std::sync::Arc;

    const INITIAL_REGISTRY_VERSION: u64 = 1;

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
    fn test_catch_up_aggregation_without_oldest_registry_version() {
        let cup = catch_up_package_aggregation(None);
        assert_eq!(
            cup.content
                .oldest_registry_version_in_use_by_replicated_state,
            None
        );
        assert_eq!(
            cup.get_oldest_registry_version_in_use(),
            RegistryVersion::from(INITIAL_REGISTRY_VERSION)
        );
    }

    #[test]
    fn test_catch_up_aggregation_with_smaller_oldest_registry_version() {
        let cup = catch_up_package_aggregation(Some(RegistryVersion::from(0)));
        assert_eq!(
            cup.content
                .oldest_registry_version_in_use_by_replicated_state,
            Some(RegistryVersion::from(0))
        );
        assert_eq!(
            cup.get_oldest_registry_version_in_use(),
            RegistryVersion::from(0),
        );
    }

    #[test]
    fn test_catch_up_aggregation_with_larger_oldest_registry_version() {
        let cup = catch_up_package_aggregation(Some(RegistryVersion::from(1234)));
        assert_eq!(
            cup.content
                .oldest_registry_version_in_use_by_replicated_state,
            Some(RegistryVersion::from(1234))
        );
        assert_eq!(
            cup.get_oldest_registry_version_in_use(),
            RegistryVersion::from(INITIAL_REGISTRY_VERSION)
        );
    }

    /// Test the aggregation of 'CatchUpPackageShare's
    fn catch_up_package_aggregation(
        oldest_registry_version_in_use_by_replicated_state: Option<RegistryVersion>,
    ) -> CatchUpPackage {
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
                    INITIAL_REGISTRY_VERSION,
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
            let new_cup_share = |node_id: NodeId| -> CatchUpPackageShare {
                let state_hash = CryptoHashOf::from(CryptoHash(Vec::new()));
                CatchUpPackageShare {
                    content: (&CatchUpContent::new(
                        HashedBlock::new(
                            ic_types::crypto::crypto_hash,
                            block.content.as_ref().clone(),
                        ),
                        HashedRandomBeacon::new(ic_types::crypto::crypto_hash, beacon.clone()),
                        state_hash,
                        oldest_registry_version_in_use_by_replicated_state,
                    ))
                        .into(),
                    signature: ThresholdSignatureShare::fake(node_id),
                }
            };
            let share0 = new_cup_share(node_test_id(0));
            let share1 = new_cup_share(node_test_id(1));
            let share2 = new_cup_share(node_test_id(2));
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
            cup
        })
    }
}
