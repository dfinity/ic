//! This module provides two public interfaces, compute_attribute and
//! get_priority_function.

use crate::consensus::{metrics::ConsensusGossipMetrics, pool_reader::PoolReader, prelude::*};
use ic_interfaces::consensus_pool::{ConsensusPool, HeightIndexedPool, HeightRange};
use ic_types::artifact::{ConsensusMessageId, Priority, Priority::*, PriorityFn};
use prometheus::Histogram;
use std::collections::BTreeSet;

/// A cache remembering which notarized/finalized blocks exist in which pool.
/// Here blocks are only identified by their hashes.
#[derive(Default)]
struct BlockSets {
    notarized_validated: BlockSet,
    notarized_unvalidated: BlockSet,
    finalized_unvalidated: BlockSet,
}

/// A set remembering possibly known blocks only by their hashes.
/// It is used as a block_set by the priority function. This is only
/// used temporarily by a new priority function created from
/// get_priority_function.
type BlockSet = BTreeSet<CryptoHashOf<Block>>;

/// Return a priority function that matches the given consensus pool.
pub fn get_priority_function(
    pool: &dyn ConsensusPool,
    expected_batch_height: Height,
    metrics: &ConsensusGossipMetrics,
) -> PriorityFn<ConsensusMessageId, ConsensusMessageAttribute> {
    let pool_reader = PoolReader::new(pool);
    let catch_up_height = pool_reader.get_catch_up_height();
    let finalized_height = pool_reader.get_finalized_height();
    let notarized_height = pool_reader.get_notarized_height();
    let beacon_height = pool_reader.get_random_beacon_height();
    let catch_up_package = pool_reader.get_highest_catch_up_package();
    let catchup_block_hash = catch_up_package.content.block.get_hash().clone();

    // Build a block_set of notarized/finalized blocks of what we have
    // in the pool.
    let mut block_sets = BlockSets::default();
    block_sets.notarized_validated.insert(catchup_block_hash);
    // Update block_sets with what is in the consensus pool.

    let histograms = &metrics.get_priority_update_block_duration;
    update_block_set(
        &mut block_sets.notarized_validated,
        finalized_height,
        pool.validated().notarization(),
        &histograms.with_label_values(&["notarized_validated"]),
    );
    update_block_set(
        &mut block_sets.finalized_unvalidated,
        finalized_height,
        pool.unvalidated().finalization(),
        &histograms.with_label_values(&["finalized_validated"]),
    );
    update_block_set(
        &mut block_sets.notarized_unvalidated,
        finalized_height,
        pool.unvalidated().notarization(),
        &histograms.with_label_values(&["notarized_unvalidated"]),
    );

    Box::new(move |_, attr: &'_ ConsensusMessageAttribute| {
        compute_priority(
            catch_up_height,
            expected_batch_height,
            finalized_height,
            notarized_height,
            beacon_height,
            &block_sets,
            attr,
        )
    })
}

/// Update the given BlockSet with blocks that are references by artifacts
/// in the given `pool_section`, meant to be used for both Finalization and
/// Notarization. Only artifacts with height greater than finalized_height
/// are considered. A BlockMap is used to cache loaded blocks to
/// avoid an unnecessary reading of the consensus pool for the same set of
/// blocks.
fn update_block_set<T: HasHeight + HasBlockHash>(
    block_set: &mut BlockSet,
    finalized_height: Height,
    pool_section: &dyn HeightIndexedPool<T>,
    histogram: &Histogram,
) {
    let _timer = histogram.start_timer();
    if let Some(max_height) = pool_section.max_height() {
        let range = HeightRange::new(finalized_height.increment(), max_height);
        for obj in pool_section.get_by_height_range(range) {
            let hash = obj.block_hash();
            block_set.insert(hash.clone());
        }
    }
}

/// We do not need to request artifacts that are too far ahead.
const LOOK_AHEAD: u64 = 10;

/// The actual priority computation utilizing cached BlockSets instead of
/// having to read from the pool every time when it is called.
fn compute_priority(
    catch_up_height: Height,
    expected_batch_height: Height,
    finalized_height: Height,
    notarized_height: Height,
    beacon_height: Height,
    block_sets: &BlockSets,
    attr: &ConsensusMessageAttribute,
) -> Priority {
    let height = attr.height();
    // Ignore older than the min of catch-up height and expected_batch_height
    if height < expected_batch_height.min(catch_up_height) {
        return Drop;
    }
    // Other decisions depend on type, default is to fetch.
    match attr {
        ConsensusMessageAttribute::RandomBeacon(_)
        | ConsensusMessageAttribute::RandomBeaconShare(_) => {
            // Ignore old beacon or beacon shares
            if height <= beacon_height {
                Drop
            } else if height < beacon_height + Height::from(LOOK_AHEAD) {
                Fetch
            } else {
                Later
            }
        }
        ConsensusMessageAttribute::NotarizationShare(_) => {
            // Ignore old notarization shares
            if height <= notarized_height {
                Drop
            } else if height < notarized_height + Height::from(LOOK_AHEAD) {
                Fetch
            } else {
                Later
            }
        }
        ConsensusMessageAttribute::Notarization(block_hash, _) => {
            // Ignore older than finalized
            if height <= finalized_height {
                Drop
            } else {
                // Drop notarization we already have
                if block_sets.notarized_validated.contains(block_hash) {
                    Drop
                }
                // Postpone notarization we might already have
                else if block_sets.notarized_unvalidated.contains(block_hash)
                    || height >= finalized_height + Height::from(LOOK_AHEAD)
                {
                    Later
                } else {
                    Fetch
                }
            }
        }
        ConsensusMessageAttribute::Finalization(block_hash, _) => {
            // Ignore older than finalized
            if height <= finalized_height {
                Drop
            } else {
                // Postpone finalization we might already have
                if block_sets.finalized_unvalidated.contains(block_hash)
                    || height >= finalized_height + Height::from(LOOK_AHEAD)
                {
                    Later
                } else {
                    Fetch
                }
            }
        }
        ConsensusMessageAttribute::FinalizationShare(_)
        | ConsensusMessageAttribute::BlockProposal(_, _) => {
            // Ignore finalized
            if height <= finalized_height {
                Drop
            } else if height < finalized_height + Height::from(LOOK_AHEAD) {
                Fetch
            } else {
                Later
            }
        }
        ConsensusMessageAttribute::RandomTape(_)
        | ConsensusMessageAttribute::RandomTapeShare(_) => {
            if height < expected_batch_height {
                Drop
            } else if height < finalized_height + Height::from(LOOK_AHEAD) {
                Fetch
            } else {
                Later
            }
        }
        ConsensusMessageAttribute::CatchUpPackage(_) => FetchNow,
        ConsensusMessageAttribute::CatchUpPackageShare(_) => Fetch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{dependencies, Dependencies};
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{consensus::fake::*, types::ids::node_test_id};

    /// Create dummy test metrics to pass into get_priority_function
    fn test_metrics() -> ConsensusGossipMetrics {
        ConsensusGossipMetrics::new(MetricsRegistry::new())
    }

    #[test]
    fn test_priority_function() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            pool.advance_round_normal_operation_n(2);

            let expected_batch_height = Height::from(1);
            let priority = get_priority_function(&pool, expected_batch_height, &test_metrics());
            // New block ==> Fetch
            let block = pool.make_next_block();
            assert_eq!(
                priority(
                    &block.get_id(),
                    &ConsensusMessageAttribute::from(&block.clone().into_message())
                ),
                Fetch
            );

            // Older than finalized ==> Drop
            let notarization = pool
                .validated()
                .notarization()
                .get_by_height(Height::from(1))
                .last()
                .unwrap();
            assert_eq!(
                priority(
                    &notarization.get_id(),
                    &ConsensusMessageAttribute::from(&notarization.into_message())
                ),
                Drop
            );

            // Put block into validated pool, notarization in to unvalidated pool
            pool.insert_validated(block.clone());
            let notarization = Notarization::fake(NotarizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            pool.insert_unvalidated(notarization.clone());

            // Possible duplicate notarization ==> Later
            let mut dup_notarization = notarization.clone();
            let dup_notarization_id = dup_notarization.get_id();
            dup_notarization.signature.signers = vec![node_test_id(42)];
            let dup_msg = dup_notarization.into_message();
            let attr = ConsensusMessageAttribute::from(&dup_msg);
            // Move block back to unvalidated after attribute is computed
            pool.remove_validated(block.clone());
            pool.insert_unvalidated(block.clone());
            let priority = get_priority_function(&pool, expected_batch_height, &test_metrics());
            assert_eq!(priority(&dup_notarization_id, &attr), Later);

            // Moving block to validated does not affect result
            pool.remove_unvalidated(block.clone());
            pool.insert_validated(block.clone());
            let priority = get_priority_function(&pool, expected_batch_height, &test_metrics());
            assert_eq!(
                priority(
                    &dup_notarization_id,
                    &ConsensusMessageAttribute::from(&dup_msg)
                ),
                Later
            );

            // Definite duplicate notarization ==> Drop
            pool.insert_validated(notarization.clone());
            pool.remove_unvalidated(notarization);
            let priority = get_priority_function(&pool, expected_batch_height, &test_metrics());
            assert_eq!(
                priority(
                    &dup_notarization_id,
                    &ConsensusMessageAttribute::from(&dup_msg)
                ),
                Drop
            );

            // Put finalization in the unvalidated pool
            let finalization = Finalization::fake(FinalizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            pool.insert_unvalidated(finalization.clone());

            // Possible duplicate finalization ==> Later
            let mut dup_finalization = finalization.clone();
            let dup_finalization_id = dup_finalization.get_id();
            dup_finalization.signature.signers = vec![node_test_id(42)];
            let dup_msg = dup_finalization.into_message();
            let priority = get_priority_function(&pool, expected_batch_height, &test_metrics());
            assert_eq!(
                priority(
                    &dup_finalization_id,
                    &ConsensusMessageAttribute::from(&dup_msg)
                ),
                Later
            );

            // Once finalized, possible duplicate finalization ==> Drop
            pool.insert_validated(finalization.clone());
            pool.remove_unvalidated(finalization);
            let priority = get_priority_function(&pool, expected_batch_height, &test_metrics());
            assert_eq!(
                priority(
                    &dup_finalization_id,
                    &ConsensusMessageAttribute::from(&dup_msg)
                ),
                Drop
            );
        })
    }
}
