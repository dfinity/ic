//! Wrapper to read the consensus pool

use crate::registry_version_at_height;
use ic_interfaces::{
    batch_payload::PastPayload,
    consensus_pool::{ConsensusBlockCache, ConsensusPool, ConsensusPoolCache},
    pool_reader::PoolReader,
};
use ic_types::{consensus::Payload, Height, RegistryVersion, Time};

/// A struct and corresponding impl with helper methods to obtain particular
/// artifacts/messages from the artifact pool.
///
/// An important invariant is that the validated pool always has at least one
/// valid random beacon and one valid block that is considered finalized.
pub struct PoolReaderImpl<'a> {
    pool: &'a dyn ConsensusPool,
    pub(crate) cache: &'a dyn ConsensusPoolCache,
    pub(crate) block_cache: &'a dyn ConsensusBlockCache,
}

impl<'a> PoolReaderImpl<'a> {
    /// Create a PoolReader for a ConsensusPool.
    pub fn new(pool: &'a dyn ConsensusPool) -> Self {
        Self {
            pool,
            cache: pool.as_cache(),
            block_cache: pool.as_block_cache(),
        }
    }
}

impl<'a> PoolReader<'a> for PoolReaderImpl<'a> {
    fn as_cache(&self) -> &dyn ConsensusPoolCache {
        self.cache
    }

    fn as_block_cache(&self) -> &dyn ConsensusBlockCache {
        self.block_cache
    }

    fn registry_version(&self, height: Height) -> Option<RegistryVersion> {
        registry_version_at_height(self.cache, height)
    }

    fn pool(&self) -> &dyn ConsensusPool {
        self.pool
    }
}

/// Take a slice returned by [`PoolReader::get_payloads_from_height`]
/// and return it in the [`PastPayload`] format that is used by the batch payload builders
///
/// The returned vector contains only the values for which the supplied closure `filter`
/// returns Some(value).
pub fn filter_past_payloads<'a, P>(
    input: &'a [(Height, Time, Payload)],
    filter: P,
) -> Vec<PastPayload<'a>>
where
    P: Fn(&'a Height, &'a Time, &'a Payload) -> Option<&'a [u8]>,
{
    input
        .iter()
        .filter_map(|(height, time, payload)| {
            filter(height, time, payload).map(|data| PastPayload {
                height: *height,
                time: *time,
                block_hash: payload.get_hash().clone(),
                payload: data,
            })
        })
        .collect()
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ic_consensus_mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_interfaces::consensus_pool::HeightRange;
    use ic_interfaces_registry::RegistryClient;
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::consensus::HasHeight;

    #[test]
    fn test_get_dkg_summary_block() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 3;
            let Dependencies { mut pool, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(
                        (0..1).map(node_test_id).collect::<Vec<_>>().as_slice(),
                    )
                    .with_dkg_interval_length(interval_length)
                    .build(),
                )],
            );

            // Get the finalized block after skipping exactly one DKG interval.
            let height = pool.advance_round_normal_operation_n(interval_length + 1);
            assert_eq!(height, Height::from(interval_length).increment());
            let block = pool.get_cache().finalized_block();
            // This block is expected to be the summary of the next block, so we'll get it
            // back.
            assert!(block.payload.is_summary());
            let pool_reader = PoolReaderImpl::new(&pool);
            assert_eq!(Some(block.clone()), pool_reader.dkg_summary_block(&block));
            assert_eq!(
                Some(block.clone()),
                pool_reader.dkg_summary_block_for_finalized_height(block.height)
            );

            // Now, we'll capture the next block after the current summary block.
            pool.advance_round_normal_operation();
            let block2 = pool.get_cache().finalized_block();

            // Skip one DKG interval.
            pool.advance_round_normal_operation_n(interval_length);
            let pool_reader = PoolReaderImpl::new(&pool);
            // Make sure we do not get summaries for too old blocks.
            assert_eq!(None, pool_reader.dkg_summary_block(&block2));
            assert_eq!(
                None,
                pool_reader.dkg_summary_block_for_finalized_height(block2.height)
            );

            // Get the new summary block and make sure it's a summary.
            let block3 = pool.get_cache().finalized_block();
            assert!(block3.payload.is_summary());
            // Advance the pool, but stay within the current DKG interval.
            pool.advance_round_normal_operation_n(interval_length - 1);
            let block4 = pool.get_cache().finalized_block();
            // Make sure block4 points to the latest summary.
            let pool_reader = PoolReaderImpl::new(&pool);
            assert_eq!(Some(block3.clone()), pool_reader.dkg_summary_block(&block4));
            assert_eq!(
                Some(block3.clone()),
                pool_reader.dkg_summary_block_for_finalized_height(block4.height)
            );

            // Advance the pool into the next interval, but don't create a CUP yet.
            pool.advance_round_normal_operation_no_cup_n(interval_length + 1);
            let block5 = pool.get_cache().finalized_block();
            // A summary block higher than block4 exists. While `dkg_summary_block` should return `None`,
            // `dkg_summary_block_for_finalized_height` should continue to return block3.
            let pool_reader = PoolReaderImpl::new(&pool);
            assert_eq!(None, pool_reader.dkg_summary_block(&block4));
            assert_eq!(
                Some(block3),
                pool_reader.dkg_summary_block_for_finalized_height(block4.height)
            );
            // The summary of block5 should be the highest summary block eventhough no CUP was created at that height.
            let summary = pool_reader.get_highest_finalized_summary_block();
            assert_eq!(
                Some(summary.clone()),
                pool_reader.dkg_summary_block(&block5)
            );
            assert_eq!(
                Some(summary),
                pool_reader.dkg_summary_block_for_finalized_height(block5.height)
            );

            // `dkg_summary_block_for_finalized_height` should return none for blocks below a CUP and non-finalized blocks.
            assert_eq!(
                None,
                pool_reader.dkg_summary_block_for_finalized_height(
                    pool_reader.get_finalized_height().increment()
                )
            );
            assert_eq!(
                None,
                pool_reader.dkg_summary_block_for_finalized_height(
                    pool_reader.get_catch_up_height().decrement()
                )
            );
        })
    }

    #[test]
    fn test_get_finalized_block_at_height_without_finalization() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            let start = pool.make_next_block();
            pool.insert_beacon_chain(&pool.make_next_beacon(), Height::from(10));
            pool.insert_block_chain_with(start.clone(), Height::from(10));
            let ten_block = pool
                .validated()
                .block_proposal()
                .get_only_by_height(Height::from(10))
                .unwrap();
            pool.finalize(&ten_block);

            let pool_reader = PoolReaderImpl::new(&pool);
            pool_reader
                .get_finalized_block(Height::from(10))
                .expect("Can't find finalized block at 10");
            assert_eq!(
                &pool_reader.get_finalized_block(Height::from(1)).unwrap(),
                start.as_ref()
            );
        })
    }

    #[test]
    fn test_get_notarized_finalized_height() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = vec![node_test_id(0)];
            let interval_length = 4;
            let Dependencies { mut pool, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                )],
            );
            pool.advance_round_normal_operation_n(4);
            pool.prepare_round().dont_add_catch_up_package().advance();
            let block = pool.latest_notarized_blocks().next().unwrap();
            pool.finalize_block(&block);
            let notarization = pool.validated().notarization().get_highest().unwrap();
            let catch_up_package = pool.make_catch_up_package(notarization.height());
            pool.insert_validated(catch_up_package);
            pool.purge_validated_below(notarization);
            let pool_reader = PoolReaderImpl::new(&pool);
            // notarized/finalized height are still 3, same as catchup height
            assert_eq!(pool_reader.get_notarized_height(), Height::from(5));
            assert_eq!(pool_reader.get_finalized_height(), Height::from(5));
            assert_eq!(pool_reader.get_catch_up_height(), Height::from(5));
        })
    }

    #[test]
    // Tests that both the in-memory and the persisted pool return artifacts
    // sorted in ascending order.
    fn test_get_by_height_range() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let rounds = 30;
            let replicas = 10;
            let f = 3;
            let Dependencies { mut pool, .. } = dependencies(pool_config, replicas);

            // Because `TestConsensusPool::advance_round` alternates between
            // putting blocks in validated and unvalidated pools for each rank,
            // we expect (f+1)/2 blocks in the unvalidated pool per round.
            let mut round = pool
                .prepare_round()
                .with_replicas(replicas as u32)
                .with_new_block_proposals(f + 1)
                .with_random_beacon_shares(replicas as u32)
                .with_notarization_shares(replicas as u32)
                .with_finalization_shares(replicas as u32);
            // Grow the artifact pool for `rounds`.
            for _ in 0..rounds {
                round.advance();
            }
            let artifacts = pool
                .validated()
                .finalization()
                .get_by_height_range(HeightRange::new(Height::from(0), Height::from(100)))
                .collect::<Vec<_>>();
            // We expect to see `rounds` new finalizations sorted by height in
            // ascending order.
            assert_eq!(artifacts.len(), rounds);
            for i in 0..artifacts.len() - 1 {
                // All heights are expected to be unique, because we have exactly
                // one finalization per round.
                assert!(artifacts[i].content.height < artifacts[i + 1].content.height);
            }
            let artifacts = pool
                .unvalidated()
                .block_proposal()
                .get_by_height_range(HeightRange::new(
                    Height::from(0),
                    Height::from((rounds * 2) as u64),
                ))
                .collect::<Vec<_>>();
            // We expect to see `rounds * ((f+1)/2)` unvalidated block proposals sorted by
            // height in ascending order.
            assert_eq!(artifacts.len(), rounds * ((f as usize + 1) / 2));
            for i in 0..artifacts.len() - 1 {
                // Heights are ascending, but NOT unique.
                assert!(artifacts[i].content.height() <= artifacts[i + 1].content.height());
            }
        })
    }

    #[test]
    fn test_registry_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 3;
            let total_length = interval_length + 1; // account for the summary block
            let record = SubnetRecordBuilder::from(&[node_test_id(0)])
                .with_dkg_interval_length(interval_length)
                .build();
            let Dependencies {
                mut pool,
                registry_data_provider,
                registry,
                replica_config,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(1, record.clone())],
            );
            let subnet_id = replica_config.subnet_id;
            let pool_reader = PoolReaderImpl::new(&pool);
            // Right now we only have the genesis block. For the genesis interval and the
            // interval behind it, we will use the RegistryVersion = 1, as it is
            // currently used in genesis generation inside the summary and
            // inside the block validation context.
            for h in 0..(2 * total_length) {
                assert_eq!(
                    pool_reader.registry_version(Height::from(h)).unwrap(),
                    RegistryVersion::from(1)
                );
            }

            // However the height outside of the next interval, is not going to
            // work.
            assert!(pool_reader
                .registry_version(Height::from(2 * total_length + 1))
                .is_none());

            // Let's advance the pool for one round, update the registry,
            // and advance the pool till the next DKG start.
            pool.advance_round_normal_operation();

            // Before we update the registry, make sure we agree on the latest version.
            assert_eq!(registry.get_latest_version(), RegistryVersion::from(1),);

            // We update the registry and expect, that the validation context of the next
            // dkg summary will pick it up.
            add_subnet_record(&registry_data_provider, 2, subnet_id, record.clone());
            registry.update_to_latest_version();

            // Make sure changes were picked up.
            assert_eq!(registry.get_latest_version(), RegistryVersion::from(2),);

            pool.advance_round_normal_operation_n(total_length);

            // Now the the next summary block should pick up the next version in its context
            // validation.

            // Advance the pool to the start of the third interval and upgrade the registry
            // in between.
            pool.advance_round_normal_operation();
            add_subnet_record(&registry_data_provider, 3, subnet_id, record);
            registry.update_to_latest_version();
            pool.advance_round_normal_operation_n(total_length);

            // Now all heights, abobe the 3rd DKG round should use registry version 2
            let pool_reader = PoolReaderImpl::new(&pool);
            for h in (2 * total_length)..(3 * total_length) {
                assert_eq!(
                    pool_reader.registry_version(Height::from(h)).unwrap(),
                    RegistryVersion::from(2),
                );
            }

            // In the forth interval, we would see the version 3
            for h in (3 * total_length)..(4 * total_length) {
                assert_eq!(
                    pool_reader.registry_version(Height::from(h)).unwrap(),
                    RegistryVersion::from(3),
                );
            }

            // For the height from the 4th round there is no version.
            assert!(pool_reader
                .registry_version(Height::from(4 * total_length + 1))
                .is_none());

            // However, all old versions are not available as they are below the latest CUP.
            for h in 0..(2 * total_length) {
                assert!(pool_reader.registry_version(Height::from(h)).is_none(),);
            }
        })
    }
}
