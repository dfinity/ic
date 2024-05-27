//! Consensus utility functions
use crate::{crypto::Aggregate, membership::Membership, pool_reader::PoolReader};
use ic_interfaces::{
    consensus::{PayloadValidationError, PayloadValidationFailure},
    consensus_pool::ConsensusPoolCache,
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
    consensus::{idkg::EcdsaPayload, Block, BlockProposal, HasCommittee, HasHeight, HasRank, Rank},
    crypto::{
        threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript},
        CryptoHash, CryptoHashable, Signed,
    },
    Height, RegistryVersion, ReplicaVersion, SubnetId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

pub mod crypto;
pub mod membership;
pub mod pool_reader;

/// The acceptable gap between the finalized height and the certified height. If
/// the actual gap is greater than this, consensus starts slowing down the block
/// rate.
pub const ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP: u64 = 3;

/// In order to have a bound on the advertised consensus pool, we place a limit on
/// the notarization/certification gap.
pub const ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP: u64 = 70;

/// In order to have a bound on the advertised consensus pool, we place a limit on
/// the gap between notarized height and the height of the next pending CUP.
pub const ACCEPTABLE_NOTARIZATION_CUP_GAP: u64 = 70;

/// Rotate on_state_change calls with a round robin schedule to ensure fairness.
#[derive(Default)]
pub struct RoundRobin {
    index: std::cell::RefCell<usize>,
}

impl RoundRobin {
    /// Call the next function in the given list of calls according to a round
    /// robin schedule. Return as soon as a call returns a non-empty ChangeSet.
    /// Otherwise try calling the next one, and return empty ChangeSet if all
    /// calls from the given list have been tried.
    pub fn call_next<T>(&self, calls: &[&dyn Fn() -> Vec<T>]) -> Vec<T> {
        let mut result;
        let mut index = self.index.borrow_mut();
        let mut next = *index;
        loop {
            result = calls[next]();
            next = (next + 1) % calls.len();
            if !result.is_empty() || *index == next {
                break;
            };
        }
        *index = next;
        result
    }
}

/// Convert a CryptoHashable into a 32 bytes which can be used to seed a RNG
pub fn crypto_hashable_to_seed<T: CryptoHashable>(hashable: &T) -> [u8; 32] {
    let hash = ic_types::crypto::crypto_hash(hashable);
    let CryptoHash(hash_bytes) = hash.get();
    let mut seed = [0; 32]; // zero padded if digest is less than 32 bytes
    let n = hash_bytes.len().min(32);
    seed[0..n].copy_from_slice(&hash_bytes[0..n]);
    seed
}

/// Calculate the required delay for block making based on the block maker's
/// rank.
pub fn get_block_maker_delay(
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
pub fn is_time_to_make_block(
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
pub fn get_adjusted_notary_delay(
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
            cup_height,
        } => {
            warn!(
                every_n_seconds => 5,
                log,
                "The gap between the notarization height ({notarized_height}) and \
                the CUP height ({cup_height}) exceeds hard bound of \
                {ACCEPTABLE_NOTARIZATION_CUP_GAP}"
            );
            None
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum NotaryDelay {
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
        cup_height: Height,
    },
}

/// Calculate the required delay for notary based on the rank of block to notarize,
/// adjusted by a multiplier depending on the gap between finalized and notarized
/// heights, adjusted by how far the certified height lags behind the finalized
/// height.
pub fn get_adjusted_notary_delay_from_settings(
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

    // We measure the gap between our current CUP height and the current notarized
    // height. If the notarized height is in a DKG interval for which we don't yet have
    // the CUP, we limit the notarization-CUP gap to ACCEPTABLE_NOTARIZATION_CUP_GAP.
    let last_cup = pool.get_highest_catch_up_package();
    let last_cup_dkg_info = &last_cup
        .content
        .block
        .as_ref()
        .payload
        .as_ref()
        .as_summary()
        .dkg;
    let cup_height = last_cup.height();
    let cup_gap = notarized_height.get().saturating_sub(cup_height.get());
    if cup_gap >= last_cup_dkg_info.interval_length.get() + ACCEPTABLE_NOTARIZATION_CUP_GAP {
        return NotaryDelay::ReachedMaxNotarizationCUPGap {
            notarized_height,
            cup_height,
        };
    }

    NotaryDelay::CanNotarizeAfter(Duration::from_millis(certified_adjusted_delay))
}

/// Return the validated block proposals with the lowest rank at height `h`, if
/// there are any. Else return `None`.
pub fn find_lowest_ranked_proposals(pool: &PoolReader<'_>, h: Height) -> Vec<BlockProposal> {
    let (_, best_proposals) = pool
        .pool()
        .validated()
        .block_proposal()
        .get_by_height(h)
        .fold(
            (None, Vec::new()),
            |(mut best_rank, mut best_proposals), proposal| {
                if best_rank.is_none() || best_rank.unwrap() > proposal.rank() {
                    best_rank = Some(proposal.rank());
                    best_proposals = vec![proposal];
                } else if Some(proposal.rank()) == best_rank {
                    best_proposals.push(proposal);
                }
                (best_rank, best_proposals)
            },
        );
    best_proposals
}

/// Fetches the notarization delay settings from the registry.
pub fn get_notarization_delay_settings(
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

/// Aggregate shares into complete artifacts
///
/// Consensus receives many artifact signature shares during its lifetime.
/// `aggregate` attempts to aggregate these signature shares into complete
/// signatures for the associated content.
///
/// For example, `aggregate` can take a `Vec<&RandomBeaconShare>` and
/// output a `Vec<&RandomBeacon>`
///
/// `aggregate` behaves as follows:
/// * groups the shares by content, producing a map from content to a vector of
///   signature shares, each of which signs the associated content
/// * for each grouped (content, shares) pair, lookup the threshold and
///   determine if there are enough shares to construct a full signature for the
///   content
/// * if so, attempt to construct the full signature from the shares
/// * if a full signature can be constructed, construct an artifact with the
///   given content and full signature
/// * return all successfully constructed artifacts
///
/// # Arguments
///
/// * `artifact_shares` - A vector of artifact shares, e.g.
///   `Vec<&RandomBeaconShare>`
#[allow(clippy::type_complexity)]
pub fn aggregate<
    Message: Eq + Ord + Clone + std::fmt::Debug + HasHeight + HasCommittee,
    CryptoMessage,
    Signature: Ord,
    KeySelector: Copy,
    CommitteeSignature,
    Shares: Iterator<Item = Signed<Message, Signature>>,
>(
    log: &ReplicaLogger,
    membership: &Membership,
    crypto: &dyn Aggregate<CryptoMessage, Signature, KeySelector, CommitteeSignature>,
    selector: Box<dyn Fn(&Message) -> Option<KeySelector> + '_>,
    artifact_shares: Shares,
) -> Vec<Signed<Message, CommitteeSignature>> {
    group_shares(artifact_shares)
        .into_iter()
        .filter_map(|(content_ref, shares)| {
            let selector = selector(&content_ref).or_else(|| {
                warn!(
                    log,
                    "aggregate: cannot find selector for content {:?}", content_ref
                );
                None
            })?;
            let threshold = match membership
                .get_committee_threshold(content_ref.height(), Message::committee())
            {
                Ok(threshold) => threshold,
                Err(err) => {
                    error!(log, "MembershipError: {:?}", err);
                    return None;
                }
            };
            if shares.len() < threshold {
                return None;
            }
            let shares_ref = shares.iter().collect();
            crypto
                .aggregate(shares_ref, selector)
                .ok()
                .map(|signature| {
                    let content = content_ref.clone();
                    Signed { content, signature }
                })
        })
        .collect()
}

// Return a mapping from the unique content contained in `shares` to the
// shares that contain this content
pub(crate) fn group_shares<C: Eq + Ord, S: Ord, Shares: Iterator<Item = Signed<C, S>>>(
    shares: Shares,
) -> BTreeMap<C, BTreeSet<S>> {
    shares.fold(BTreeMap::new(), |mut grouped_shares, share| {
        match grouped_shares.get_mut(&share.content) {
            Some(existing) => {
                existing.insert(share.signature);
            }
            None => {
                let mut new_set = BTreeSet::new();
                new_set.insert(share.signature);
                grouped_shares.insert(share.content, new_set);
            }
        };
        grouped_shares
    })
}

/// Return the hash of a block as a string.
pub fn get_block_hash_string(block: &Block) -> String {
    hex::encode(ic_types::crypto::crypto_hash(block).get().0)
}

/// Helper function to lookup replica version, and log errors if any.
pub fn lookup_replica_version(
    registry_client: &(impl RegistryClient + ?Sized),
    subnet_id: SubnetId,
    log: &ReplicaLogger,
    registry_version: RegistryVersion,
) -> Option<ReplicaVersion> {
    match registry_client.get_replica_version(subnet_id, registry_version) {
        Ok(version) => {
            if version.is_none() {
                warn!(
                    log,
                    "replica version id does not exist at registry version {:?}", version
                );
            }
            version
        }
        Err(err) => {
            warn!(
                log,
                "Unable to get replica version id for registry version {:?}: {:?}",
                registry_version,
                err
            );
            None
        }
    }
}

/// Return the registry version to be used for the given height.
/// Note that this can only look up for height that is greater than or equal
/// to the latest catch-up package height, otherwise an error is returned.
pub fn registry_version_at_height(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<RegistryVersion> {
    get_active_data_at(reader, height, get_registry_version_at_given_summary)
}

/// Return the current low transcript for the given height if it was found.
pub fn active_low_threshold_transcript(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<NiDkgTranscript> {
    get_active_data_at(reader, height, |block, height| {
        get_transcript_at_given_summary(block, height, NiDkgTag::LowThreshold)
    })
}

/// Return the current high transcript for the given height if it was found.
pub fn active_high_threshold_transcript(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<NiDkgTranscript> {
    get_active_data_at(reader, height, |block, height| {
        get_transcript_at_given_summary(block, height, NiDkgTag::HighThreshold)
    })
}

/// Return the active DKGData active at the given height if it was found.
fn get_active_data_at<T>(
    reader: &dyn ConsensusPoolCache,
    height: Height,
    getter: impl Fn(&Block, Height) -> Option<T>,
) -> Option<T> {
    // Note that we cannot always use the latest finalized DKG summary to determine
    // the active DKG data: Suppose we have CUPs every 100th block, and we just
    // finalized DKG summary block 300. With that block, we can find the active
    // data for heights 300 - 499. However, we may still need to compute e.g. the
    // random tape at height 299.
    // However, always using the summary from the latest CUP is also not sufficient:
    // We can only create a CUP
    // for height 300 if we have finalized a chain up to height 300, and the
    // finalized chain tip points to certified state of at least 300.
    // If batch processing lags behind consensus, we could get stuck:
    // If we finalize blocks up to height 499, but those blocks do not
    // reference certified state of at least 300, then we are not yet able to
    // compute CUP 300 or newer. If we use only the DKG summary from the CUP to
    // determine the active DKG data we are now stuck at height 499, because we
    // do not know which registry version to use for the next heights,
    // and we can therefore never compute the next block or CUP.
    // As a solution, we try to establish the active DKG data using the summary
    // block from the CUP first, and if that does not work, we try the latest
    // finalized summary block. This way we avoid both ways of getting stuck.
    getter(reader.catch_up_package().content.block.get_value(), height)
        .or_else(|| getter(&reader.summary_block(), height))
}

fn get_registry_version_at_given_summary(
    summary_block: &Block,
    height: Height,
) -> Option<RegistryVersion> {
    let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
    if dkg_summary.current_interval_includes(height) {
        Some(dkg_summary.registry_version)
    } else if dkg_summary.next_interval_includes(height) {
        Some(summary_block.context.registry_version)
    } else {
        None
    }
}

fn get_transcript_at_given_summary(
    summary_block: &Block,
    height: Height,
    tag: NiDkgTag,
) -> Option<NiDkgTranscript> {
    let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
    if dkg_summary.current_interval_includes(height) {
        Some(dkg_summary.current_transcript(&tag).clone())
    } else if dkg_summary.next_interval_includes(height) {
        Some(
            dkg_summary
                .next_transcript(&tag)
                .unwrap_or_else(|| dkg_summary.current_transcript(&tag))
                .clone(),
        )
    } else {
        None
    }
}

/// Get the [`SubnetRecord`] of this subnet with the specified [`RegistryVersion`]
pub fn get_subnet_record(
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

/// Return the oldest registry version of transcripts in the given ECDSA summary payload that are
/// referenced by the given replicated state.
pub fn get_oldest_ecdsa_state_registry_version(
    ecdsa: &EcdsaPayload,
    state: &ReplicatedState,
) -> Option<RegistryVersion> {
    state
        .sign_with_ecdsa_contexts()
        .values()
        .flat_map(|context| context.matched_quadruple.as_ref())
        .flat_map(|(pre_sig_id, _)| ecdsa.available_pre_signatures.get(pre_sig_id))
        .flat_map(|quadruple| quadruple.get_refs())
        .flat_map(|transcript_ref| ecdsa.idkg_transcripts.get(&transcript_ref.transcript_id))
        .map(|transcript| transcript.registry_version)
        .min()
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::str::FromStr;

    use super::*;
    use ic_consensus_mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_management_canister_types::EcdsaKeyId;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_state::ReplicatedStateBuilder;
    use ic_test_utilities_types::{
        ids::{node_test_id, subnet_test_id},
        messages::RequestBuilder,
    };
    use ic_types::{
        consensus::idkg::{
            common::PreSignatureRef, ecdsa::PreSignatureQuadrupleRef, EcdsaKeyTranscript,
            KeyTranscriptCreation, MaskedTranscript, PreSigId, UnmaskedTranscript,
        },
        crypto::{
            canister_threshold_sig::idkg::{
                IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
                IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
            },
            ThresholdSigShare, ThresholdSigShareOf,
        },
        messages::CallbackId,
        signature::ThresholdSignatureShare,
        time::UNIX_EPOCH,
    };

    /// Test that two shares with the same content are grouped together, and
    /// that a different share is grouped by itself
    #[test]
    fn test_group_shares() {
        let share1 = fake_share(1, vec![1]);
        let share2 = fake_share(1, vec![2]);
        let share3 = fake_share(2, vec![1]);

        let grouped_shares = group_shares(Box::new(vec![share1, share2, share3].into_iter()));
        assert_eq!(grouped_shares.get(&1).unwrap().len(), 2);
        assert_eq!(grouped_shares.get(&2).unwrap().len(), 1);
    }

    fn fake_share<C: Eq + Ord + Clone>(
        content: C,
        sig: Vec<u8>,
    ) -> Signed<C, ThresholdSignatureShare<C>> {
        let signer = node_test_id(0);
        let signature = ThresholdSignatureShare {
            signature: ThresholdSigShareOf::new(ThresholdSigShare(sig)),
            signer,
        };
        Signed { content, signature }
    }

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

            for _ in 0..last_cup_dkg_info.interval_length.get() {
                pool.advance_round_normal_operation_no_cup();
            }

            for _ in 0..(ACCEPTABLE_NOTARIZATION_CUP_GAP - 1) {
                pool.advance_round_normal_operation_no_cup();
            }

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
    fn test_round_robin() {
        // check if iteration is complete
        let round_robin = RoundRobin::default();
        let make_1 = || vec![1];
        let make_2 = || vec![2];
        let make_3 = || vec![3];

        let calls: [&'_ dyn Fn() -> Vec<u8>; 3] = [&make_1, &make_2, &make_3];
        let mut result = vec![];
        for _ in 0..6 {
            result.append(&mut round_robin.call_next(&calls));
        }
        assert_eq!(result, vec![1, 2, 3, 1, 2, 3]);

        // check if empty returns are skipped
        let round_robin = RoundRobin::default();
        let make_empty = Vec::new;
        let calls: [&'_ dyn Fn() -> Vec<u8>; 6] = [
            &make_empty,
            &make_1,
            &make_2,
            &make_empty,
            &make_3,
            &make_empty,
        ];
        let mut result = vec![];
        for _ in 0..6 {
            result.append(&mut round_robin.call_next(&calls));
        }
        assert_eq!(result, vec![1, 2, 3, 1, 2, 3]);

        // check termination
        let round_robin = RoundRobin::default();
        let calls: [&'_ dyn Fn() -> Vec<u8>; 3] = [&make_empty, &make_empty, &make_empty];
        assert!(round_robin.call_next(&calls).is_empty());

        // check iterations
        let round_robin = RoundRobin::default();
        let calls: [&'_ dyn Fn() -> Vec<u8>; 3] = [&make_empty, &make_1, &make_empty];
        assert_eq!(round_robin.call_next(&calls), vec![1]);
        assert_eq!(round_robin.call_next(&calls), vec![1]);
    }

    fn empty_ecdsa_payload() -> EcdsaPayload {
        EcdsaPayload::empty(
            Height::new(0),
            subnet_test_id(0),
            vec![EcdsaKeyTranscript::new(
                EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                KeyTranscriptCreation::Begin,
            )],
        )
    }

    fn fake_transcript(id: IDkgTranscriptId, registry_version: RegistryVersion) -> IDkgTranscript {
        IDkgTranscript {
            transcript_id: id,
            receivers: IDkgReceivers::new(BTreeSet::from_iter([node_test_id(0)])).unwrap(),
            registry_version,
            verified_dealings: Default::default(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(fake_transcript_id(0)),
            ),
            algorithm_id: ic_types::crypto::AlgorithmId::EcdsaSecp256k1,
            internal_transcript_raw: vec![],
        }
    }

    fn fake_transcript_id(id: u64) -> IDkgTranscriptId {
        IDkgTranscriptId::new(subnet_test_id(0), id, Height::from(0))
    }

    // Create a fake quadruple, it will use transcripts with ids
    // id, id+1, id+2, and id+3.
    fn fake_quadruple(id: u64) -> PreSignatureQuadrupleRef {
        let temp_rv = RegistryVersion::from(0);
        let kappa_unmasked = fake_transcript(fake_transcript_id(id), temp_rv);
        let mut lambda_masked = kappa_unmasked.clone();
        lambda_masked.transcript_id = fake_transcript_id(id + 1);
        lambda_masked.transcript_type =
            IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);
        let mut kappa_times_lambda = lambda_masked.clone();
        kappa_times_lambda.transcript_id = fake_transcript_id(id + 2);
        let mut key_times_lambda = lambda_masked.clone();
        key_times_lambda.transcript_id = fake_transcript_id(id + 3);
        let mut key_unmasked = kappa_unmasked.clone();
        key_unmasked.transcript_id = fake_transcript_id(id + 4);
        let h = Height::from(0);
        PreSignatureQuadrupleRef {
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
            kappa_unmasked_ref: UnmaskedTranscript::try_from((h, &kappa_unmasked)).unwrap(),
            lambda_masked_ref: MaskedTranscript::try_from((h, &lambda_masked)).unwrap(),
            kappa_times_lambda_ref: MaskedTranscript::try_from((h, &kappa_times_lambda)).unwrap(),
            key_times_lambda_ref: MaskedTranscript::try_from((h, &key_times_lambda)).unwrap(),
            key_unmasked_ref: UnmaskedTranscript::try_from((h, &key_unmasked)).unwrap(),
        }
    }

    fn fake_context(pre_signature_id: Option<PreSigId>) -> SignWithEcdsaContext {
        SignWithEcdsaContext {
            request: RequestBuilder::new().build(),
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
            message_hash: [0; 32],
            derivation_path: vec![],
            pseudo_random_id: [0; 32],
            matched_quadruple: pre_signature_id.map(|qid| (qid, Height::from(0))),
            nonce: None,
            batch_time: UNIX_EPOCH,
        }
    }

    fn fake_state_with_contexts(contexts: Vec<SignWithEcdsaContext>) -> ReplicatedState {
        let mut state = ReplicatedStateBuilder::default().build();
        let iter = contexts
            .into_iter()
            .enumerate()
            .map(|(i, context)| (CallbackId::from(i as u64), context));
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts = BTreeMap::from_iter(iter);
        state
    }

    // Create an ECDSA payload with 10 quadruples, each using registry version 2, 3 or 4.
    fn ecdsa_payload_with_quadruples() -> EcdsaPayload {
        let mut ecdsa = empty_ecdsa_payload();
        let mut rvs = [
            RegistryVersion::from(2),
            RegistryVersion::from(3),
            RegistryVersion::from(4),
        ]
        .into_iter()
        .cycle();
        for i in (0..50).step_by(5) {
            let quadruple = fake_quadruple(i as u64);
            let rv = rvs.next().unwrap();
            for r in quadruple.get_refs() {
                ecdsa
                    .idkg_transcripts
                    .insert(r.transcript_id, fake_transcript(r.transcript_id, rv));
            }
            ecdsa
                .available_pre_signatures
                .insert(PreSigId(i as u64), PreSignatureRef::Ecdsa(quadruple));
        }
        ecdsa
    }

    #[test]
    fn test_empty_state_should_return_no_registry_version() {
        let ecdsa = ecdsa_payload_with_quadruples();
        let state = fake_state_with_contexts(vec![]);
        assert_eq!(
            None,
            get_oldest_ecdsa_state_registry_version(&ecdsa, &state)
        );
    }

    #[test]
    fn test_state_without_matches_should_return_no_registry_version() {
        let ecdsa = ecdsa_payload_with_quadruples();
        let state = fake_state_with_contexts(vec![fake_context(None)]);
        assert_eq!(
            None,
            get_oldest_ecdsa_state_registry_version(&ecdsa, &state)
        );
    }

    #[test]
    fn test_should_return_oldest_registry_version() {
        let ecdsa = ecdsa_payload_with_quadruples();
        // create contexts for all quadruples, but only create a match for
        // quadruples with registry version >= 3 (not 2!). Thus the oldest
        // registry version referenced by the state should be 3.
        let contexts = ecdsa
            .available_pre_signatures
            .iter()
            .map(|(id, pre_sig)| {
                let PreSignatureRef::Ecdsa(quad) = pre_sig else {
                    panic!("Expected ECDSA pre-signature");
                };
                let t_id = quad.lambda_masked_ref.as_ref().transcript_id;
                let transcript = ecdsa.idkg_transcripts.get(&t_id).unwrap();
                (transcript.registry_version.get() >= 3).then_some(*id)
            })
            .map(fake_context)
            .collect();
        let state = fake_state_with_contexts(contexts);
        assert_eq!(
            Some(RegistryVersion::from(3)),
            get_oldest_ecdsa_state_registry_version(&ecdsa, &state)
        );

        let mut ecdsa_without_transcripts = ecdsa.clone();
        ecdsa_without_transcripts.idkg_transcripts = BTreeMap::new();
        assert_eq!(
            None,
            get_oldest_ecdsa_state_registry_version(&ecdsa_without_transcripts, &state)
        );

        let mut ecdsa_without_quadruples = ecdsa.clone();
        ecdsa_without_quadruples.available_pre_signatures = BTreeMap::new();
        assert_eq!(
            None,
            get_oldest_ecdsa_state_registry_version(&ecdsa_without_quadruples, &state)
        );
    }
}
