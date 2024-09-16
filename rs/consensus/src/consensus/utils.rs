use ic_consensus_utils::{
    membership::Membership, pool_reader::PoolReader, ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP,
    ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP, ACCEPTABLE_NOTARIZATION_CUP_GAP,
};
use ic_interfaces::{
    consensus::{PayloadValidationError, PayloadValidationFailure},
    time_source::TimeSource,
    validation::ValidationError,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_helpers::subnet::{NotarizationDelaySettings, SubnetRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    consensus::{Block, BlockProposal, HasRank, Rank},
    Height, NodeId, RegistryVersion, SubnetId,
};
use std::{collections::BTreeSet, time::Duration};

/// Return the hash of a block as a string.
pub(super) fn get_block_hash_string(block: &Block) -> String {
    hex::encode(ic_types::crypto::crypto_hash(block).get().0)
}

/// Calculate the required delay for block making based on the block maker's
/// rank.
pub(super) fn get_block_maker_delay(
    log: &ReplicaLogger,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    rank: Rank,
) -> Option<Duration> {
    get_notarization_delay_settings(log, registry_client, subnet_id, registry_version)
        .map(|settings| settings.unit_delay * rank.0 as u32)
}

/// Return true if the time since round start is greater than the required block
/// maker delay for the given rank.
pub(super) fn is_time_to_make_block(
    log: &ReplicaLogger,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    pool: &PoolReader<'_>,
    height: Height,
    rank: Rank,
    time_source: &dyn TimeSource,
) -> bool {
    let Some(registry_version) = pool.registry_version(height) else {
        return false;
    };
    let Some(block_maker_delay) =
        get_block_maker_delay(log, registry_client, subnet_id, registry_version, rank)
    else {
        return false;
    };

    // If the relative time indicates that not enough time has passed, we fall
    // back to the the monotonic round start time. We do this to safeguard
    // against a stalled relative clock.
    pool.get_round_start_time(height)
        .is_some_and(|start_time| time_source.get_relative_time() >= start_time + block_maker_delay)
        || pool
            .get_round_start_instant(height, time_source.get_origin_instant())
            .is_some_and(|start_instant| {
                time_source.get_instant() >= start_instant + block_maker_delay
            })
}

/// Calculate the required delay for notary based on the rank of block to notarize,
/// adjusted by a multiplier depending on the gap between finalized and notarized
/// heights, adjusted by how far the certified height lags behind the finalized
/// height. Return `None` when the registry is unavailable, or when the notary has
/// reached a hard limit (either notarization/certification or notarization/CUP gap
/// limits).
/// Use membership and height to determine the notarization settings that should be used.
pub(super) fn get_adjusted_notary_delay(
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
        )?,
        pool,
        state_manager,
        rank,
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

#[derive(PartialEq, Debug)]
pub(super) enum NotaryDelay {
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
/// height.
pub(super) fn get_adjusted_notary_delay_from_settings(
    settings: NotarizationDelaySettings,
    pool: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    rank: Rank,
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
    let finality_gap = (pool.get_notarized_height().get() - finalized_height) as i32;
    let finality_adjusted_delay =
        (initial_delay + ranked_delay * 1.5_f32.powi(finality_gap)) as u64;

    // We adjust the delay based on the gap between the finalized height and the
    // certified height: when the certified height is more than
    // ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP rounds behind the
    // finalized height, we increase the delay. More precisely, for every additional
    // round that certified height is behind finalized height, we add `unit_delay`.
    let certified_gap = finalized_height.saturating_sub(
        state_manager.latest_certified_height().get() + ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP,
    );

    let certified_adjusted_delay =
        finality_adjusted_delay + unit_delay.as_millis() as u64 * certified_gap;

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

/// Return the validated block proposals with the lowest rank at height `h` that
/// have not been disqualified, if there are any. Else, return an empty Vec.
pub(super) fn find_lowest_ranked_non_disqualified_proposals(
    pool: &PoolReader<'_>,
    h: Height,
) -> Vec<BlockProposal> {
    let disqualified: BTreeSet<NodeId> = pool
        .pool()
        .validated()
        .equivocation_proof()
        .get_by_height(h)
        .map(|proof| proof.signer)
        .collect();

    let mut best_proposals = vec![];
    for proposal in pool
        .pool()
        .validated()
        .block_proposal()
        .get_by_height(h)
        .filter(|proposal| !disqualified.contains(&proposal.signature.signer))
    {
        let best_rank = best_proposals.first().map(HasRank::rank);
        if !best_rank.is_some_and(|rank| rank <= proposal.rank()) {
            best_proposals = vec![proposal];
        } else if Some(proposal.rank()) == best_rank {
            best_proposals.push(proposal);
        }
    }
    best_proposals
}

/// Fetches the notarization delay settings from the registry.
pub(super) fn get_notarization_delay_settings(
    log: &ReplicaLogger,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> Option<NotarizationDelaySettings> {
    match registry_client.get_notarization_delay_settings(subnet_id, registry_version) {
        Ok(None) => {
            panic!(
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                registry_version, subnet_id,
            );
        }
        Err(err) => {
            error!(
                log,
                "Could not retrieve notarization delay settings from the registry: {:?}", err
            );
            None
        }
        Ok(result) => result,
    }
}

/// Get the [`SubnetRecord`] of this subnet with the specified [`RegistryVersion`]
pub(super) fn get_subnet_record(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> Result<SubnetRecord, PayloadValidationError> {
    match registry_client.get_subnet_record(subnet_id, registry_version) {
        Ok(Some(record)) => Ok(record),
        Ok(None) => {
            warn!(logger, "Subnet id {:?} not found in registry", subnet_id);
            Err(ValidationError::ValidationFailed(
                PayloadValidationFailure::SubnetNotFound(subnet_id),
            ))
        }
        Err(err) => {
            warn!(logger, "Failed to get subnet record in block_maker");
            Err(ValidationError::ValidationFailed(
                PayloadValidationFailure::RegistryUnavailable(err),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_consensus_mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_types::consensus::get_faults_tolerated;
    use ic_types_test_utils::ids::{node_test_id, subnet_test_id};

    #[test]
    fn test_get_adjusted_notary_delay_cup_delay() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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
                    Rank(0),
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
                    Rank(0),
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
                    Rank(0),
                ),
                NotaryDelay::ReachedMaxNotarizationCUPGap { .. }
            );
        });
    }

    #[test]
    fn test_ignore_disqualified_ranks() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            const SUBNET_SIZE: u64 = 10;
            let Dependencies { mut pool, .. } = dependencies(pool_config, SUBNET_SIZE);

            let height = Height::new(1);

            // We fill the validated pool with blocks from every rank and incrementally
            // disqualify the lowest qualified rank. Each time we assert that it's
            // ignored by [`find_lowest_ranked_non_disqualified_proposals`].
            let f = get_faults_tolerated(SUBNET_SIZE as usize) as u64;
            for i in 0..f + 1 {
                pool.insert_validated(pool.make_next_block_with_rank(Rank(i)));
            }

            assert_matches!(
                &find_lowest_ranked_non_disqualified_proposals(&PoolReader::new(&pool), height)[..],
                [b] if b.content.as_ref().rank == Rank(0)
            );
            for i in 0..f {
                pool.insert_validated(pool.make_equivocation_proof(Rank(i), height));
                // We disqualify rank i, so lowest ranked proposal must be i + 1
                match &find_lowest_ranked_non_disqualified_proposals(
                    &PoolReader::new(&pool),
                    height,
                )[..]
                {
                    [proposal] => assert_eq!(proposal.content.as_ref().rank, Rank(i + 1)),
                    _ => panic!("expected exactly one proposal at the given height"),
                }
            }
        });
    }
}
