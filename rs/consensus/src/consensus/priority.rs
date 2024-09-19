use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::consensus_pool::ConsensusPool;
use ic_interfaces::p2p::consensus::{Bouncer, BouncerValue, BouncerValue::*};
use ic_types::{artifact::ConsensusMessageId, consensus::ConsensusMessageHash, Height};

use super::ACCEPTABLE_VALIDATION_CUP_GAP;

/// Return a bouncer function that matches the given consensus pool.
pub fn new_bouncer(
    pool: &dyn ConsensusPool,
    expected_batch_height: Height,
) -> Bouncer<ConsensusMessageId> {
    let pool_reader = PoolReader::new(pool);
    let cup_height = pool_reader.get_catch_up_height();
    let next_cup_height = pool_reader.get_next_cup_height();
    let finalized_height = pool_reader.get_finalized_height();
    let notarized_height = pool_reader.get_notarized_height();
    let beacon_height = pool_reader.get_random_beacon_height();

    Box::new(move |id: &'_ ConsensusMessageId| {
        compute_bouncer(
            cup_height,
            next_cup_height,
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

/// The actual bouncer computation utilizing cached BlockSets instead of
/// having to read from the pool every time when it is called.
fn compute_bouncer(
    cup_height: Height,
    next_cup_height: Height,
    expected_batch_height: Height,
    finalized_height: Height,
    notarized_height: Height,
    beacon_height: Height,
    id: &ConsensusMessageId,
) -> BouncerValue {
    let height = id.height;
    // Ignore older than the min of catch-up height and expected_batch_height
    if height < expected_batch_height.min(cup_height) {
        return Unwanted;
    }
    // Stash non-CUP artifacts, as long as they're too far ahead of the next CUP height.
    // This prevents nodes that have fallen behind to exceed their validated pool bounds.
    if !matches!(id.hash, ConsensusMessageHash::CatchUpPackage(_))
        && height > next_cup_height + Height::new(ACCEPTABLE_VALIDATION_CUP_GAP)
    {
        return MaybeWantsLater;
    }
    // Other decisions depend on type, default is to Wants.
    match id.hash {
        ConsensusMessageHash::RandomBeacon(_) | ConsensusMessageHash::RandomBeaconShare(_) => {
            // Ignore old beacon or beacon shares
            if height <= beacon_height {
                Unwanted
            } else if height <= beacon_height + Height::from(LOOK_AHEAD) {
                Wants
            } else {
                MaybeWantsLater
            }
        }
        ConsensusMessageHash::NotarizationShare(_) => {
            // Ignore old notarization shares
            if height <= notarized_height {
                Unwanted
            } else if height <= notarized_height + Height::from(LOOK_AHEAD) {
                Wants
            } else {
                MaybeWantsLater
            }
        }
        ConsensusMessageHash::Notarization(_)
        | ConsensusMessageHash::Finalization(_)
        | ConsensusMessageHash::FinalizationShare(_)
        | ConsensusMessageHash::BlockProposal(_)
        | ConsensusMessageHash::EquivocationProof(_) => {
            // Ignore finalized
            if height <= finalized_height {
                Unwanted
            } else if height <= notarized_height + Height::from(LOOK_AHEAD) {
                Wants
            } else {
                MaybeWantsLater
            }
        }
        ConsensusMessageHash::RandomTape(_) | ConsensusMessageHash::RandomTapeShare(_) => {
            if height < expected_batch_height {
                Unwanted
            } else if height <= finalized_height + Height::from(LOOK_AHEAD) {
                Wants
            } else {
                MaybeWantsLater
            }
        }
        ConsensusMessageHash::CatchUpPackage(_) => Wants,
        ConsensusMessageHash::CatchUpPackageShare(_) => {
            if height <= cup_height {
                Unwanted
            } else if height <= finalized_height {
                Wants
            } else {
                MaybeWantsLater
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_consensus_utils::ACCEPTABLE_VALIDATION_CUP_GAP;
    use ic_test_utilities_consensus::fake::FakeContent;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::{
            ConsensusMessageHashable, Finalization, FinalizationContent, HasHeight, Notarization,
            NotarizationContent,
        },
        crypto::{CryptoHash, CryptoHashOf},
    };

    #[test]
    fn test_bouncer_for_validation_cup_gap() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let dkg_interval = ACCEPTABLE_VALIDATION_CUP_GAP + 29;
            let committee = (0..4).map(node_test_id).collect::<Vec<_>>();
            let Dependencies { mut pool, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(committee.as_slice())
                        .with_dkg_interval_length(dkg_interval)
                        .build(),
                )],
            );

            // Advance pool *without* producing CUP to the maximum height beyond
            // which we don't validate non-CUP artifacts anymore.
            let max_validation_height = dkg_interval + ACCEPTABLE_VALIDATION_CUP_GAP + 1;
            pool.advance_round_normal_operation_no_cup_n(max_validation_height);

            let expected_batch_height = Height::from(1);
            let bouncer = new_bouncer(&pool, expected_batch_height);

            // Artifacts at the next height are within look-ahead, but exceed
            // the validator-CUP gap. We should stash them, but not fetch them.
            let beacon = pool.make_next_beacon();
            let block = pool.make_next_block();
            let notarization = Notarization::fake(NotarizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            let equivocation_proof_id = ConsensusMessageId {
                hash: ConsensusMessageHash::EquivocationProof(CryptoHashOf::new(CryptoHash(
                    vec![],
                ))),
                height: block.height(),
            };
            assert_eq!(bouncer(&beacon.get_id()), MaybeWantsLater);
            assert_eq!(bouncer(&block.get_id()), MaybeWantsLater);
            assert_eq!(bouncer(&notarization.get_id()), MaybeWantsLater);
            assert_eq!(bouncer(&equivocation_proof_id), MaybeWantsLater);

            // Regardless of bounds, we should always fetch CUPs.
            let cup_id = ConsensusMessageId {
                hash: ConsensusMessageHash::CatchUpPackage(CryptoHashOf::new(CryptoHash(vec![]))),
                height: Height::new(100000000),
            };
            assert_eq!(bouncer(&cup_id), Wants);

            // Insert CUP for next summary height and recompute bouncer function.
            pool.insert_validated(pool.make_catch_up_package(Height::new(dkg_interval + 1)));
            let bouncer = new_bouncer(&pool, expected_batch_height);

            // The artifacts are not outside the validation-CUP gap, and
            // within look-ahead distance. We should fetch them all.
            assert_eq!(bouncer(&beacon.get_id()), Wants);
            assert_eq!(bouncer(&block.get_id()), Wants);
            assert_eq!(bouncer(&notarization.get_id()), Wants);
            assert_eq!(bouncer(&equivocation_proof_id), Wants);
        })
    }

    #[test]
    fn test_bouncer_function() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            pool.advance_round_normal_operation_n(2);

            let expected_batch_height = Height::from(1);
            let bouncer = new_bouncer(&pool, expected_batch_height);
            // New block ==> Wants
            pool.insert_validated(pool.make_next_beacon());
            let block = pool.make_next_block();
            assert_eq!(bouncer(&block.get_id()), Wants);

            // Older than finalized ==> Unwanted
            let notarization = pool
                .validated()
                .notarization()
                .get_by_height(Height::from(1))
                .last()
                .unwrap();
            assert_eq!(bouncer(&notarization.get_id()), Unwanted);

            // Put block into validated pool, notarization in to unvalidated pool
            pool.insert_validated(block.clone());
            let notarization = Notarization::fake(NotarizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            pool.insert_unvalidated(notarization.clone());

            // Possible duplicate notarization ==> Wants
            let mut dup_notarization = notarization.clone();
            let dup_notarization_id = dup_notarization.get_id();
            dup_notarization.signature.signers = vec![node_test_id(42)];
            // Move block back to unvalidated after attribute is computed
            pool.purge_validated_below(block.clone());
            pool.insert_unvalidated(block.clone());
            let bouncer = new_bouncer(&pool, expected_batch_height);
            assert_eq!(bouncer(&dup_notarization_id), Wants);

            // Moving block to validated does not affect result
            pool.remove_unvalidated(block.clone());
            pool.insert_validated(block.clone());
            let bouncer = new_bouncer(&pool, expected_batch_height);
            assert_eq!(bouncer(&dup_notarization_id), Wants);

            // Definite duplicate notarization ==> Wants but within look ahead window
            pool.insert_validated(notarization.clone());
            pool.remove_unvalidated(notarization);
            let bouncer = new_bouncer(&pool, expected_batch_height);
            assert_eq!(bouncer(&dup_notarization_id), Wants);

            // Put finalization in the unvalidated pool
            let finalization = Finalization::fake(FinalizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));
            pool.insert_unvalidated(finalization.clone());

            // Possible duplicate finalization ==> Wants but within look ahead window
            let mut dup_finalization = finalization.clone();
            let dup_finalization_id = dup_finalization.get_id();
            dup_finalization.signature.signers = vec![node_test_id(42)];
            let bouncer = new_bouncer(&pool, expected_batch_height);
            assert_eq!(bouncer(&dup_finalization_id), Wants);

            // Once finalized, possible duplicate finalization ==> Drop
            pool.insert_validated(finalization.clone());
            pool.remove_unvalidated(finalization);
            let bouncer = new_bouncer(&pool, expected_batch_height);
            assert_eq!(bouncer(&dup_finalization_id), Unwanted);

            // Add notarizations until we reach finalized_height + LOOK_AHEAD.
            for _ in 0..LOOK_AHEAD {
                pool.insert_validated(pool.make_next_beacon());
                let block = pool.make_next_block();
                pool.insert_validated(block.clone());
                let notarization = Notarization::fake(NotarizationContent::new(
                    block.height(),
                    block.content.get_hash().clone(),
                ));
                pool.insert_validated(notarization.clone());
            }
            // Insert one more block
            pool.insert_validated(pool.make_next_beacon());
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
            // Recompute bouncer function since pool content has changed
            let bouncer = new_bouncer(&pool, expected_batch_height);
            // Still fetch even when notarization is much ahead of finalization
            assert_eq!(bouncer(&notarization.get_id()), Wants);
        })
    }
}
