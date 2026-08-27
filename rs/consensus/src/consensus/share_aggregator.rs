//! The share aggregator is responsible for the aggregation of different types
//! of shares into full objects. That is, it constructs Random Beacon objects
//! from random beacon shares, Notarizations from notarization shares and
//! Finalizations from finalization shares.
use crate::consensus::random_tape_maker::RANDOM_TAPE_CHECK_MAX_HEIGHT_RANGE;
use ic_consensus_utils::{
    active_low_threshold_nidkg_id, aggregate, aggregate_with_threshold, crypto::ConsensusCrypto,
    get_current_transcript_from_summary_block, membership::Membership, pool_reader::PoolReader,
    registry_version_at_height,
};
use ic_interfaces::messaging::MessageRouting;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::{
    Height,
    consensus::{
        Block, CatchUpContent, CatchUpPackage, ConsensusMessage, ConsensusMessageHashable,
        FinalizationContent, HasHeight, RandomTapeContent, catchup::CatchUpPackageType,
    },
    crypto::{Signed, threshold_sig::ni_dkg::NiDkgTag},
    replica_config::ReplicaConfig,
};
use std::{cmp::min, sync::Arc};

use super::catchup_package_maker;

/// The ShareAggregator is responsible for aggregating shares of random beacons,
/// notarizations, and finalizations into full objects
pub(crate) struct ShareAggregator {
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    message_routing: Arc<dyn MessageRouting>,
    registry: Arc<dyn RegistryClient>,
    replica_config: ReplicaConfig,
    log: ReplicaLogger,
}

impl ShareAggregator {
    pub fn new(
        membership: Arc<Membership>,
        message_routing: Arc<dyn MessageRouting>,
        crypto: Arc<dyn ConsensusCrypto>,
        registry: Arc<dyn RegistryClient>,
        replica_config: ReplicaConfig,
        log: ReplicaLogger,
    ) -> ShareAggregator {
        ShareAggregator {
            membership,
            crypto,
            message_routing,
            registry,
            replica_config,
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
        let dkg_id = active_low_threshold_nidkg_id(state_reader, height);
        to_messages(aggregate(
            &self.log,
            self.membership.as_ref(),
            self.crypto.as_aggregate(),
            Box::new(|_| dkg_id.clone()),
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
                active_low_threshold_nidkg_id(state_reader, content.height())
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
        let mut start_block = pool.get_highest_finalized_summary_block();
        let current_cup_height = pool.get_catch_up_height();

        loop {
            let start_block_height = start_block.height();
            if start_block_height <= current_cup_height {
                break;
            }
            match self.aggregate_catch_up_package_shares_for_summary_block(pool, start_block) {
                Ok(messages) if !messages.is_empty() => {
                    return to_messages(messages);
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(
                        every_n_seconds => 5,
                        self.log,
                        "Encountered an error while aggregating CUP shares at height {start_block_height}: {err}",
                    );
                }
            }

            let Some(block_from_last_interval) =
                pool.get_finalized_block(start_block_height.decrement())
            else {
                break;
            };

            let next_start_height = block_from_last_interval
                .payload
                .as_ref()
                .dkg_interval_start_height();

            let Some(new_start_block) = pool.get_finalized_block(next_start_height) else {
                break;
            };

            start_block = new_start_block;
        }
        Vec::new()
    }

    fn aggregate_catch_up_package_shares_for_summary_block(
        &self,
        pool: &PoolReader<'_>,
        summary_block: Block,
    ) -> Result<Vec<CatchUpPackage>, String> {
        let cup_type = catchup_package_maker::get_catch_up_package_type(
            self.registry.as_ref(),
            self.replica_config.node_id,
            &summary_block,
        )
        .map_err(|err| format!("Failed to determine the cup type: {err}"))?;

        let block = match cup_type {
            CatchUpPackageType::Normal => summary_block,
            CatchUpPackageType::PostSplit { new_subnet_id } => {
                catchup_package_maker::create_post_split_summary_block(
                    &summary_block,
                    new_subnet_id,
                    self.registry.as_ref(),
                )
                .map_err(|err| format!("Failed to create a post-split summary block: {err}"))?
            }
        };

        // The high-threshold current transcript of the CUP block's own summary defines both who
        // signs a CUP and how many such signatures are needed, so we take everything from there
        let transcript =
            get_current_transcript_from_summary_block(&block, &NiDkgTag::HighThreshold)
                .ok_or_else(|| {
                    String::from("Couldn't find the high threshold transcript in the summary block")
                })?;
        let threshold = transcript.threshold.get().get() as usize;
        let dkg_id = transcript.dkg_id.clone();

        let block_hash = ic_types::crypto::crypto_hash(&block);
        let shares = pool
            .get_catch_up_package_shares(block.height())
            .filter_map(|share| {
                // The validator should already perform this check if implemented correctly, so this
                // is just a sanity check
                if block_hash != share.content.block {
                    return None;
                }

                Some(Signed {
                    content: CatchUpContent::from_share_content(share.content, block.clone()),
                    signature: share.signature,
                })
            });

        let cups = aggregate_with_threshold(
            &self.log,
            self.crypto.as_aggregate(),
            Box::new(|_| Some(dkg_id.clone())),
            Box::new(|_| Some(threshold)),
            shares,
        );

        if let CatchUpPackageType::PostSplit { new_subnet_id } = cup_type {
            for cup in &cups {
                info!(
                    self.log,
                    "Aggregated a Post-Split CUP for subnet {new_subnet_id} at height {}",
                    cup.height()
                );
            }
        }

        Ok(cups)
    }
}

fn to_messages<T: ConsensusMessageHashable>(artifacts: Vec<T>) -> Vec<ConsensusMessage> {
    artifacts.into_iter().map(|a| a.into_message()).collect()
}

#[cfg(test)]
mod tests {
    use crate::consensus::catchup_package_maker::CatchUpPackageMaker;

    use super::*;
    use ic_consensus_mocks::{Dependencies, DependenciesBuilder};
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::message_routing::FakeMessageRouting;
    use ic_test_utilities_consensus::fake::{FakeContentSigner, FakeSigner};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, insert_initial_dkg_transcript};
    use ic_test_utilities_types::ids::{node_test_id, test_replica_version};
    use ic_types::{
        CryptoHashOfState, NodeId, RegistryVersion, SubnetId,
        consensus::{
            BlockPayload, CatchUpPackage, CatchUpPackageShare, CatchUpShareContent,
            FinalizationShare, HashedBlock, HashedRandomBeacon, NotarizationShare, Payload,
            RandomBeaconShare,
            dkg::{SplittingArgs, SubnetSplittingStatus},
        },
        crypto::{CryptoHash, CryptoHashOf},
        signature::ThresholdSignatureShare,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, SUBNET_1, SUBNET_2};
    use rstest::rstest;
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
                registry,
                replica_config,
                ..
            } = DependenciesBuilder::new(pool_config, 1).build();

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

            let aggregator = ShareAggregator::new(
                membership,
                message_routing,
                crypto,
                registry,
                replica_config,
                no_op_logger(),
            );
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
            let interval_length = 3;
            let Dependencies {
                mut pool,
                membership,
                crypto,
                registry,
                replica_config,
                ..
            } = DependenciesBuilder::new(pool_config, 3)
                .with_dkg_interval_length(interval_length)
                .build();
            let message_routing = Arc::new(FakeMessageRouting::new());
            let aggregator = ShareAggregator::new(
                membership,
                message_routing,
                crypto,
                registry,
                replica_config,
                no_op_logger(),
            );

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
                x => panic!("Expecting CatchUpPackageShare but got {x:?}\n"),
            };

            assert!(cup.check_integrity());
            assert_eq!(CatchUpShareContent::from(&cup.content), share0.content);
            cup
        })
    }

    #[rstest]
    #[trace]
    #[case::no_shares(&[], false)]
    #[case::not_enough_shares(&[NODE_1], false)]
    #[case::not_enough_shares(&[NODE_1, NODE_2], false)]
    #[case::enough_shares(&[NODE_1, NODE_2, NODE_3], true)]
    #[case::enough_shares(&[NODE_1, NODE_2, NODE_3, NODE_4], true)]
    fn aggregate_post_split_cup_shares_test(
        #[case] signers: &[NodeId],
        #[case] expected_cup: bool,
    ) {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
                const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
                const INITIAL_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);
                const SPLITTING_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);
                const INTERVAL_LENGTH: Height = Height::new(9);
                let fake_state_hash = CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]));

                let Dependencies {
                    mut pool,
                    membership,
                    registry,
                    registry_data_provider,
                    crypto,
                    state_manager,
                    replica_config,
                    ..
                } = DependenciesBuilder::multiple_subnets(
                    pool_config,
                    vec![
                        (
                            INITIAL_REGISTRY_VERSION.get(),
                            SOURCE_SUBNET_ID,
                            SubnetRecordBuilder::from(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5])
                                .with_dkg_interval_length(INTERVAL_LENGTH.get())
                                .build(),
                        ),
                        (
                            SPLITTING_REGISTRY_VERSION.get(),
                            SOURCE_SUBNET_ID,
                            SubnetRecordBuilder::from(&[NODE_1, NODE_2, NODE_3, NODE_4])
                                .with_dkg_interval_length(INTERVAL_LENGTH.get())
                                .build(),
                        ),
                        (
                            SPLITTING_REGISTRY_VERSION.get(),
                            DESTINATION_SUBNET_ID,
                            SubnetRecordBuilder::from(&[NODE_5])
                                .with_dkg_interval_length(INTERVAL_LENGTH.get())
                                .build(),
                        ),
                    ],
                )
                .with_replica_config(ReplicaConfig {
                    node_id: NODE_1,
                    subnet_id: SOURCE_SUBNET_ID,
                    replica_version: test_replica_version(),
                })
                .build();
                // Manually insert DKG transcripts at the splitting version to simulate what the
                // registry would do. The setup above only inserts the transcripts at the initial
                // version.
                insert_initial_dkg_transcript(
                    SPLITTING_REGISTRY_VERSION.get(),
                    SOURCE_SUBNET_ID,
                    &SubnetRecordBuilder::from(&[NODE_1, NODE_2, NODE_3, NODE_4])
                        .with_dkg_interval_length(INTERVAL_LENGTH.get())
                        .build(),
                    &registry_data_provider,
                );
                registry.reload();

                state_manager
                    .get_mut()
                    .expect_get_state_hash_at()
                    .return_const(Ok(fake_state_hash.clone()));

                let message_routing = FakeMessageRouting::new();
                *message_routing.next_batch_height.write().unwrap() = Height::from(2);
                let message_routing = Arc::new(message_routing);

                pool.advance_round_normal_operation_n(INTERVAL_LENGTH.get());

                let subnet_splitting_status = SubnetSplittingStatus::Scheduled(SplittingArgs {
                    source_subnet_id: SOURCE_SUBNET_ID,
                    destination_subnet_id: DESTINATION_SUBNET_ID,
                });
                let mut proposal = pool.make_next_block();
                let block = proposal.content.as_mut();
                block.context.certified_height = block.height;
                block.context.registry_version = SPLITTING_REGISTRY_VERSION;
                let mut payload = block.payload.as_ref().as_summary().clone();
                payload.dkg.subnet_splitting_status = subnet_splitting_status;
                block.payload = Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(payload),
                );
                proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.insert_validated(proposal.clone());
                pool.notarize(&proposal);
                pool.finalize(&proposal);

                let mut insert_cup_share = |node_id: NodeId| {
                    let cup_maker = CatchUpPackageMaker::new(
                        ReplicaConfig {
                            node_id,
                            subnet_id: SOURCE_SUBNET_ID,
                            replica_version: test_replica_version(),
                        },
                        membership.clone(),
                        crypto.clone(),
                        state_manager.clone(),
                        message_routing.clone(),
                        registry.clone(),
                        log.clone(),
                    );

                    let share = cup_maker
                        .consider_block(&PoolReader::new(&pool), proposal.content.as_ref().clone())
                        .expect("Should succeed with valid inputs");
                    pool.insert_validated(share.clone());
                    share
                };

                let shares = signers
                    .iter()
                    .map(|node_id| insert_cup_share(*node_id))
                    .collect::<Vec<_>>();

                let aggregator = ShareAggregator::new(
                    membership,
                    message_routing,
                    crypto,
                    registry,
                    replica_config,
                    log,
                );

                let messages = aggregator.on_state_change(&PoolReader::new(&pool));

                if expected_cup {
                    let [ConsensusMessage::CatchUpPackage(cup)] = messages.as_slice() else {
                        panic!("Should have aggregated a single CUP: {messages:?}");
                    };

                    assert!(cup.check_integrity());
                    for share in shares {
                        assert_eq!(CatchUpShareContent::from(&cup.content), share.content);
                    }
                } else {
                    assert_eq!(messages, vec![], "Shouldn't have aggregated any artifacts");
                }
            })
        })
    }
}
