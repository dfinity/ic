//! This module provides two public interfaces, compute_attribute and
//! get_priority_function.

use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::consensus_pool::ConsensusPool;
use ic_types::{
    artifact::{ConsensusMessageId, Priority, Priority::*, PriorityFn},
    consensus::ConsensusMessageHash,
    Height,
};

/// Return a priority function that matches the given consensus pool.
pub fn get_priority_function(
    pool: &dyn ConsensusPool,
    expected_batch_height: Height,
) -> PriorityFn<ConsensusMessageId, ()> {
    let pool_reader = PoolReader::new(pool);
    let catch_up_height = pool_reader.get_catch_up_height();
    let finalized_height = pool_reader.get_finalized_height();
    let notarized_height = pool_reader.get_notarized_height();
    let beacon_height = pool_reader.get_random_beacon_height();

    Box::new(move |id: &'_ ConsensusMessageId, ()| {
        compute_priority(
            catch_up_height,
            expected_batch_height,
            finalized_height,
            notarized_height,
            beacon_height,
            id,
        )
    })
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
    id: &ConsensusMessageId,
) -> Priority {
    let height = id.height;
    // Ignore older than the min of catch-up height and expected_batch_height
    if height < expected_batch_height.min(catch_up_height) {
        return Drop;
    }
    // Other decisions depend on type, default is to FetchNow.
    match id.hash {
        ConsensusMessageHash::RandomBeacon(_) | ConsensusMessageHash::RandomBeaconShare(_) => {
            // Ignore old beacon or beacon shares
            if height <= beacon_height {
                Drop
            } else if height <= beacon_height + Height::from(LOOK_AHEAD) {
                FetchNow
            } else {
                Stash
            }
        }
        ConsensusMessageHash::NotarizationShare(_) => {
            // Ignore old notarization shares
            if height <= notarized_height {
                Drop
            } else if height <= notarized_height + Height::from(LOOK_AHEAD) {
                FetchNow
            } else {
                Stash
            }
        }
        ConsensusMessageHash::Notarization(_)
        | ConsensusMessageHash::Finalization(_)
        | ConsensusMessageHash::FinalizationShare(_)
        | ConsensusMessageHash::BlockProposal(_)
        | ConsensusMessageHash::EquivocationProof(_) => {
            // Ignore finalized
            if height <= finalized_height {
                Drop
            } else if height <= notarized_height + Height::from(LOOK_AHEAD) {
                FetchNow
            } else {
                Stash
            }
        }
        ConsensusMessageHash::RandomTape(_) | ConsensusMessageHash::RandomTapeShare(_) => {
            if height < expected_batch_height {
                Drop
            } else if height <= finalized_height + Height::from(LOOK_AHEAD) {
                FetchNow
            } else {
                Stash
            }
        }
        ConsensusMessageHash::CatchUpPackage(_) => FetchNow,
        ConsensusMessageHash::CatchUpPackageShare(_) => {
            if height <= catch_up_height {
                Drop
            } else if height <= finalized_height {
                FetchNow
            } else {
                Stash
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_test_utilities_consensus::fake::FakeContent;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::consensus::{
        ConsensusMessageHashable, Finalization, FinalizationContent, HasHeight, Notarization,
        NotarizationContent,
    };

    #[test]
    fn test_priority_function() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            pool.advance_round_normal_operation_n(2);

            let expected_batch_height = Height::from(1);
            let priority = get_priority_function(&pool, expected_batch_height);
            // New block ==> FetchNow
            let block = pool.make_next_block();
            assert_eq!(priority(&block.get_id(), &()), FetchNow);

            // Older than finalized ==> Drop
            let notarization = pool
                .validated()
                .notarization()
                .get_by_height(Height::from(1))
                .last()
                .unwrap();
            assert_eq!(priority(&notarization.get_id(), &()), Drop);

            // Put block into validated pool, notarization in to unvalidated pool
            pool.insert_validated(block.clone());
            let notarization = Notarization::fake(NotarizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            pool.insert_unvalidated(notarization.clone());

            // Possible duplicate notarization ==> FetchNow
            let mut dup_notarization = notarization.clone();
            let dup_notarization_id = dup_notarization.get_id();
            dup_notarization.signature.signers = vec![node_test_id(42)];
            // Move block back to unvalidated after attribute is computed
            pool.purge_validated_below(block.clone());
            pool.insert_unvalidated(block.clone());
            let priority = get_priority_function(&pool, expected_batch_height);
            assert_eq!(priority(&dup_notarization_id, &()), FetchNow);

            // Moving block to validated does not affect result
            pool.remove_unvalidated(block.clone());
            pool.insert_validated(block.clone());
            let priority = get_priority_function(&pool, expected_batch_height);
            assert_eq!(priority(&dup_notarization_id, &()), FetchNow);

            // Definite duplicate notarization ==> FetchNow but within look ahead window
            pool.insert_validated(notarization.clone());
            pool.remove_unvalidated(notarization);
            let priority = get_priority_function(&pool, expected_batch_height);
            assert_eq!(priority(&dup_notarization_id, &()), FetchNow);

            // Put finalization in the unvalidated pool
            let finalization = Finalization::fake(FinalizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            pool.insert_unvalidated(finalization.clone());

            // Possible duplicate finalization ==> FetchNow but within look ahead window
            let mut dup_finalization = finalization.clone();
            let dup_finalization_id = dup_finalization.get_id();
            dup_finalization.signature.signers = vec![node_test_id(42)];
            let priority = get_priority_function(&pool, expected_batch_height);
            assert_eq!(priority(&dup_finalization_id, &()), FetchNow);

            // Once finalized, possible duplicate finalization ==> Drop
            pool.insert_validated(finalization.clone());
            pool.remove_unvalidated(finalization);
            let priority = get_priority_function(&pool, expected_batch_height);
            assert_eq!(priority(&dup_finalization_id, &()), Drop);

            // Add notarizations until we reach finalized_height + LOOK_AHEAD.
            for _ in 0..LOOK_AHEAD {
                let block = pool.make_next_block();
                pool.insert_validated(block.clone());
                let notarization = Notarization::fake(NotarizationContent::new(
                    block.height(),
                    block.content.get_hash().clone(),
                ));
                pool.insert_validated(notarization.clone());
            }
            // Insert one more block
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            let notarization = Notarization::fake(NotarizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            assert!(
                block.height().get()
                    > PoolReader::new(&pool).get_finalized_height().get() + LOOK_AHEAD
            );
            // Recompute priority function since pool content has changed
            let priority = get_priority_function(&pool, expected_batch_height);
            // Still fetch even when notarization is much ahead of finalization
            assert_eq!(priority(&notarization.get_id(), &()), FetchNow);
        })
    }
}
