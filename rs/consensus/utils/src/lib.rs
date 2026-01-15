//! Consensus utility functions
use crate::{crypto::Aggregate, membership::Membership, pool_reader::PoolReader};
use ic_interfaces::{
    consensus::{PayloadValidationError, PayloadValidationFailure},
    consensus_pool::ConsensusPoolCache,
    validation::ValidationError,
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, error, warn};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_helpers::subnet::{NotarizationDelaySettings, SubnetRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height, NodeId, RegistryVersion, ReplicaVersion, SubnetId,
    consensus::{Block, BlockProposal, HasCommittee, HasHeight, HasRank, Threshold},
    crypto::{
        CryptoHash, CryptoHashable, Signed,
        threshold_sig::ni_dkg::{NiDkgId, NiDkgReceivers, NiDkgTag, NiDkgTranscript},
    },
};
use std::collections::{BTreeMap, BTreeSet};

pub mod bouncer_metrics;
pub mod crypto;
pub mod membership;
pub mod pool_reader;

/// When purging consensus or certification artifacts, we always keep a
/// minimum chain length below the catch-up height.
pub const MINIMUM_CHAIN_LENGTH: u64 = 50;

/// Rotate on_state_change calls with a round robin schedule to ensure fairness.
#[derive(Default)]
pub struct RoundRobin {
    index: std::cell::RefCell<usize>,
}

impl RoundRobin {
    /// Call the next function in the given list of calls according to a round
    /// robin schedule. Return as soon as a call returns a non-empty Mutations.
    /// Otherwise try calling the next one, and return empty Mutations if all
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

/// Return the validated block proposals with the lowest rank at height `h` that
/// have not been disqualified, if there are any. Else, return an empty Vec.
pub fn find_lowest_ranked_non_disqualified_proposals(
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
        if best_rank.is_none_or(|rank| rank > proposal.rank()) {
            best_proposals = vec![proposal];
        } else if Some(proposal.rank()) == best_rank {
            best_proposals.push(proposal);
        }
    }
    best_proposals
}

/// Fetches the notarization delay settings from the registry.
pub fn get_notarization_delay_settings(
    log: &ReplicaLogger,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> NotarizationDelaySettings {
    match registry_client.get_notarization_delay_settings(subnet_id, registry_version) {
        Ok(None) => {
            error!(
                log,
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                registry_version,
                subnet_id,
            );
            NotarizationDelaySettings::default()
        }
        Err(err) => {
            error!(
                log,
                "Could not retrieve notarization delay settings from the registry: {:?}", err
            );
            NotarizationDelaySettings::default()
        }
        Ok(Some(result)) => result,
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
    KeySelector,
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
/// Note that this can only look up heights that are greater than or equal
/// to the latest catch-up package height, otherwise `None` is returned.
pub fn registry_version_at_height(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<RegistryVersion> {
    get_active_data_at(reader, height, get_registry_version_at_given_summary)
}

/// Return the registry version and DKG interval length to be used for the given height.
/// Note that this can only look up heights that are greater than or equal
/// to the latest catch-up package height, otherwise `None` is returned.
pub fn get_registry_version_and_interval_length_at_height(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<(RegistryVersion, Height)> {
    get_active_data_at(reader, height, |block, height| {
        let registry_version = get_registry_version_at_given_summary(block, height)?;
        let dkg_interval_length = get_dkg_interval_length_at_given_summary(block, height)?;
        Some((registry_version, dkg_interval_length))
    })
}

/// Return the current low transcript for the given height if it was found.
pub fn active_low_threshold_nidkg_id(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<NiDkgId> {
    get_active_data_at(reader, height, |block, height| {
        get_transcript_data_at_given_summary(block, height, NiDkgTag::LowThreshold, |transcript| {
            transcript
                .expect("No active low threshold transcript available for tag {:?}")
                .dkg_id
                .clone()
        })
    })
}

/// Return the current high transcript for the given height if it was found.
pub fn active_high_threshold_nidkg_id(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<NiDkgId> {
    get_active_data_at(reader, height, |block, height| {
        get_transcript_data_at_given_summary(block, height, NiDkgTag::HighThreshold, |transcript| {
            transcript
                .expect("No active high threshold transcript available for tag {:?}")
                .dkg_id
                .clone()
        })
    })
}

/// Return the current low transcript for the given height if it was found.
pub fn active_low_threshold_committee(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<(Threshold, NiDkgReceivers)> {
    get_active_data_at(reader, height, |block, height| {
        get_transcript_data_at_given_summary(block, height, NiDkgTag::LowThreshold, |transcript| {
            let transcript = transcript.expect("No active low threshold transcript available");
            (
                transcript.threshold.get().get() as usize,
                transcript.committee.clone(),
            )
        })
    })
}

/// Return the current high transcript for the given height if it was found.
pub fn active_high_threshold_committee(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<(Threshold, NiDkgReceivers)> {
    get_active_data_at(reader, height, |block, height| {
        get_transcript_data_at_given_summary(block, height, NiDkgTag::HighThreshold, |transcript| {
            let transcript = transcript.expect("No active high threshold transcript available");
            (
                transcript.threshold.get().get() as usize,
                transcript.committee.clone(),
            )
        })
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

fn get_dkg_interval_length_at_given_summary(
    summary_block: &Block,
    height: Height,
) -> Option<Height> {
    let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
    if dkg_summary.current_interval_includes(height) {
        Some(dkg_summary.interval_length)
    } else if dkg_summary.next_interval_includes(height) {
        Some(dkg_summary.next_interval_length)
    } else {
        None
    }
}

fn get_transcript_data_at_given_summary<T>(
    summary_block: &Block,
    height: Height,
    tag: NiDkgTag,
    getter: impl Fn(Option<&NiDkgTranscript>) -> T,
) -> Option<T> {
    let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
    if dkg_summary.current_interval_includes(height) {
        Some(getter(dkg_summary.current_transcript(&tag)))
    } else if dkg_summary.next_interval_includes(height) {
        let transcript = dkg_summary
            .next_transcript(&tag)
            .or(dkg_summary.current_transcript(&tag));
        Some(getter(transcript))
    } else {
        None
    }
}

/// Check if the [`ReplicaVersion`] is the current version
///
/// # Arguments
///
/// - `version`: the [`ReplicaVersion`] to check against
///
/// # Returns
///
/// - `true` if `version` matches the current version
/// - `false` otherwise
pub fn is_current_protocol_version(version: &ReplicaVersion) -> bool {
    version == &ReplicaVersion::default()
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

/// Return the oldest registry version of transcripts that were matched to signature
/// request contexts in the given replicated state.
pub fn get_oldest_idkg_state_registry_version(state: &ReplicatedState) -> Option<RegistryVersion> {
    state
        .signature_request_contexts()
        .values()
        .flat_map(|context| context.iter_idkg_transcripts())
        .map(|transcript| transcript.registry_version)
        .min()
}

/// Calculate the number of heights in the given range (inclusive)
pub fn range_len(start: Height, end: Height) -> usize {
    if end >= start {
        (end.get() - start.get())
            .checked_add(1)
            .expect("We should never reach the maximum number of heights") as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ic_test_utilities_consensus::idkg::{
        fake_master_public_key_ids_for_all_idkg_algorithms,
        fake_signature_request_context_with_registry_version,
    };

    use super::*;
    use ic_consensus_mocks::{Dependencies, dependencies};
    use ic_management_canister_types_private::MasterPublicKeyId;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithThresholdContext;
    use ic_test_utilities_state::ReplicatedStateBuilder;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        consensus::{Rank, get_faults_tolerated, idkg::PreSigId},
        crypto::{ThresholdSigShare, ThresholdSigShareOf},
        messages::CallbackId,
        signature::ThresholdSignatureShare,
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

    fn fake_state_with_contexts(contexts: Vec<SignWithThresholdContext>) -> ReplicatedState {
        let mut state = ReplicatedStateBuilder::default().build();
        let iter = contexts
            .into_iter()
            .enumerate()
            .map(|(i, context)| (CallbackId::from(i as u64), context));
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts = BTreeMap::from_iter(iter);
        state
    }

    fn fake_key_ids() -> Vec<MasterPublicKeyId> {
        fake_master_public_key_ids_for_all_idkg_algorithms()
            .into_iter()
            .map(|id| id.inner().clone())
            .collect()
    }

    #[test]
    fn test_empty_state_should_return_no_registry_version() {
        let state = fake_state_with_contexts(vec![]);
        assert_eq!(None, get_oldest_idkg_state_registry_version(&state));
    }

    #[test]
    fn test_state_without_matches_should_return_no_registry_version() {
        for key_id in fake_key_ids() {
            println!("Running test for key ID {key_id}");
            let state = fake_state_with_contexts(vec![
                fake_signature_request_context_with_registry_version(
                    None,
                    &key_id,
                    RegistryVersion::from(4),
                ),
            ]);
            assert_eq!(None, get_oldest_idkg_state_registry_version(&state));
        }
    }

    #[test]
    fn test_should_return_oldest_registry_version_all() {
        for key_id in fake_key_ids() {
            println!("Running test for key ID {key_id}");
            test_should_return_oldest_registry_version(key_id)
        }
    }

    fn test_should_return_oldest_registry_version(key_id: MasterPublicKeyId) {
        let mut contexts = vec![];
        // Create some contexts with registry version 4 and some unmatched ones
        for i in 0..3 {
            contexts.push(fake_signature_request_context_with_registry_version(
                Some(PreSigId(i)),
                &key_id,
                RegistryVersion::from(4),
            ));
            contexts.push(fake_signature_request_context_with_registry_version(
                None,
                &key_id,
                RegistryVersion::from(4),
            ));
        }
        // Create one context with registry version 2
        contexts.push(fake_signature_request_context_with_registry_version(
            Some(PreSigId(3)),
            &key_id,
            RegistryVersion::from(2),
        ));
        // Create some contexts with registry version 3
        for i in 4..7 {
            contexts.push(fake_signature_request_context_with_registry_version(
                Some(PreSigId(i)),
                &key_id,
                RegistryVersion::from(3),
            ));
        }
        let state = fake_state_with_contexts(contexts);
        assert_eq!(
            Some(RegistryVersion::from(2)),
            get_oldest_idkg_state_registry_version(&state)
        );
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

    #[test]
    fn test_range_len() {
        assert_eq!(range_len(Height::new(0), Height::new(0)), 1);
        assert_eq!(range_len(Height::new(0), Height::new(1)), 2);
        assert_eq!(range_len(Height::new(0), Height::new(10)), 11);
        assert_eq!(range_len(Height::new(5), Height::new(10)), 6);
        assert_eq!(range_len(Height::new(10), Height::new(10)), 1);
        assert_eq!(range_len(Height::new(10), Height::new(5)), 0);
        assert_eq!(range_len(Height::new(10), Height::new(0)), 0);
        assert_eq!(range_len(Height::new(1), Height::new(0)), 0);
    }
}
