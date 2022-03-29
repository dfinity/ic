//! Consensus utility functions
use crate::consensus::{membership::Membership, pool_reader::PoolReader, prelude::*};
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache, crypto::CryptoHashable, registry::RegistryClient,
    time_source::TimeSource,
};
use ic_interfaces_state_manager::StateManager;
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_helpers::subnet::{NotarizationDelaySettings, SubnetRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::replica_config::ReplicaConfig;
use ic_types::{
    consensus::Rank,
    crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript},
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// The acceptable gap between the finalized height and the certified height. If
/// the actual gap is greater than this, consensus starts slowing down the block
/// rate.
pub const ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP: u64 = 3;

/// The acceptable ratio between the length of the dkg interval and the gap
/// between a summary height and the current finalized tip that transpires
/// without the production the cup. This means that we will start slowing down
/// if we get approximately halfway through a dkg interval without producing the
/// cup for the last summary block.
pub const ACCEPTABLE_CUP_GAP_RATIO: f64 = 0.5;

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
    pub fn call_next<'a, T>(&self, calls: &[&'a dyn Fn() -> Vec<T>]) -> Vec<T> {
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
    let hash = ic_crypto::crypto_hash(hashable);
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

/// Return true if the given subnet id is the root subnet
pub fn is_root_subnet(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> Result<bool, String> {
    let root_subnet_id = registry_client
        .get_root_subnet_id(registry_version)
        .map_err(|e| format!("Encountered error retrieving root subnet id {:?}", e))?
        .ok_or(format!(
            "No value for root subnet id at registry version {:?}",
            registry_version
        ))?;
    Ok(root_subnet_id == subnet_id)
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
    let registry_version = match pool.registry_version(height) {
        Some(rv) => rv,
        _ => return false,
    };
    let block_maker_delay =
        match get_block_maker_delay(log, registry_client, subnet_id, registry_version, rank) {
            Some(delay) => delay,
            _ => return false,
        };
    match pool.get_round_start_time(height) {
        Some(start_time) => time_source.get_relative_time() >= start_time + block_maker_delay,
        None => false,
    }
}

/// Calculate the required delay for notary based on the rank of block to
/// notarize, adjusted by a multiplier depending the gap between finalized and
/// notarized heights, and adjusted by how far the certified height lags behind
/// the finalized height. Use membership and height to determine the
/// notarization settings that should be used.
pub fn get_adjusted_notary_delay(
    membership: &Membership,
    pool: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    log: &ReplicaLogger,
    height: Height,
    rank: Rank,
) -> Option<Duration> {
    Some(get_adjusted_notary_delay_from_settings(
        get_notarization_delay_settings(
            log,
            &*membership.registry_client,
            membership.subnet_id,
            pool.registry_version(height)?,
        )?,
        pool,
        state_manager,
        rank,
    ))
}

/// Calculate the required delay for notary based on the rank of block to
/// notarize, adjusted by a multiplier depending the gap between finalized and
/// notarized heights, and adjusted by how far the certified height lags behind
/// the finalized height.
pub fn get_adjusted_notary_delay_from_settings(
    settings: NotarizationDelaySettings,
    pool: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    rank: Rank,
) -> Duration {
    let NotarizationDelaySettings {
        unit_delay,
        initial_notary_delay,
        ..
    } = settings;
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

    let cup_gap = finalized_height.saturating_sub(pool.get_catch_up_height().get());
    let last_cup_dkg_info = pool
        .get_highest_catch_up_package()
        .content
        .block
        .as_ref()
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .clone();

    let last_interval_length = last_cup_dkg_info.interval_length;
    let missing_cup_interval_length = last_cup_dkg_info.next_interval_length;

    let acceptable_gap_size = last_interval_length.get()
        + (ACCEPTABLE_CUP_GAP_RATIO * missing_cup_interval_length.get() as f64).round() as u64;

    let cup_multiple = cup_gap.saturating_sub(acceptable_gap_size);

    let adjusted_delay = certified_adjusted_delay + unit_delay.as_millis() as u64 * cup_multiple;
    Duration::from_millis(adjusted_delay)
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
fn group_shares<C: Eq + Ord, S: Ord, Shares: Iterator<Item = Signed<C, S>>>(
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
    hex::encode(ic_crypto::crypto_hash(block).get().0)
}

/// Helper function to lookup replica version, and log errors if any.
pub fn lookup_replica_version(
    registry_client: &dyn RegistryClient,
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

/// Determine whether a replica upgrade is pending given the running replica
/// version and the block height.
pub fn is_upgrade_pending(
    height: Height,
    registry_client: &dyn RegistryClient,
    replica_config: &ReplicaConfig,
    log: &ReplicaLogger,
    pool: &PoolReader<'_>,
) -> Option<bool> {
    let registry_version = pool.registry_version(height)?;
    let replica_version = lookup_replica_version(
        registry_client,
        replica_config.subnet_id,
        log,
        registry_version,
    )?;

    Some(replica_version != ReplicaVersion::default())
}

/// Determine whether a replica upgrade is finalized, meaning the blockchain
/// advanced enough such that we can wait for a CUP and the upgrade will
/// execute. Note that it is important that we wait until the finalized
/// certified_height exceeds the CUP height since this is the condition for CUP
/// making.
pub fn is_upgrade_finalized(
    registry_client: &dyn RegistryClient,
    replica_config: &ReplicaConfig,
    log: &ReplicaLogger,
    pool: &PoolReader<'_>,
) -> Option<bool> {
    let finalized_tip = pool.get_finalized_tip();
    let finalized_certified_height = finalized_tip.context.certified_height;
    let registry_version = pool.registry_version(finalized_certified_height)?;
    let replica_version = lookup_replica_version(
        registry_client,
        replica_config.subnet_id,
        log,
        registry_version,
    )?;

    Some(replica_version != ReplicaVersion::default())
}

// Data we usually pull from the latest relevant DKG summary block.
struct DkgData {
    registry_version: RegistryVersion,
    low_threshold_transcript: NiDkgTranscript,
    high_threshold_transcript: NiDkgTranscript,
}

/// Return the registry version to be used for the given height.
/// Note that this can only look up for height that is greater than or equal
/// to the latest catch-up package height, otherwise an error is returned.
pub fn registry_version_at_height(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<RegistryVersion> {
    get_active_data_at(reader, height).map(|data| data.registry_version)
}

/// Return the current low transcript for the given height if it was found.
pub fn active_low_threshold_transcript(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<NiDkgTranscript> {
    get_active_data_at(reader, height).map(|data| data.low_threshold_transcript)
}

/// Return the current high transcript for the given height if it was found.
pub fn active_high_threshold_transcript(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<NiDkgTranscript> {
    get_active_data_at(reader, height).map(|data| data.high_threshold_transcript)
}

/// Return the active DKGData active at the given height if it was found.
fn get_active_data_at(reader: &dyn ConsensusPoolCache, height: Height) -> Option<DkgData> {
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
    get_active_data_at_given_summary(reader.catch_up_package().content.block.get_value(), height)
        .or_else(|| get_active_data_at_given_summary(&reader.summary_block(), height))
}

/// Return the active DKGData active at the given height using the given summary
/// block.
fn get_active_data_at_given_summary(summary_block: &Block, height: Height) -> Option<DkgData> {
    let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
    if dkg_summary.current_interval_includes(height) {
        Some(DkgData {
            registry_version: dkg_summary.registry_version,
            high_threshold_transcript: dkg_summary
                .current_transcript(&NiDkgTag::HighThreshold)
                .clone(),
            low_threshold_transcript: dkg_summary
                .current_transcript(&NiDkgTag::LowThreshold)
                .clone(),
        })
    } else if dkg_summary.next_interval_includes(height) {
        let get_transcript_for = |tag| {
            dkg_summary
                .next_transcript(&tag)
                .unwrap_or_else(|| dkg_summary.current_transcript(&tag))
                .clone()
        };
        Some(DkgData {
            registry_version: summary_block.context.registry_version,
            high_threshold_transcript: get_transcript_for(NiDkgTag::HighThreshold),
            low_threshold_transcript: get_transcript_for(NiDkgTag::LowThreshold),
        })
    } else {
        None
    }
}

/// Get the [`SubnetRecord`] of this subnet with the
/// specified [`RegistryVersion`]
pub(crate) fn get_subnet_record(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> Option<SubnetRecord> {
    registry_client
        .get_subnet_record(subnet_id, registry_version)
        .map_err(|err| warn!(logger, "Registry error: {:?}", err))
        .ok()?
        .or_else(|| {
            warn!(
                logger,
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                subnet_id,
                registry_version
            );
            None
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::types::ids::node_test_id;

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
            let crate::consensus::mocks::Dependencies {
                mut pool,
                state_manager,
                ..
            } = crate::consensus::mocks::dependencies(pool_config, 3);
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

            for _ in 0..(last_cup_dkg_info.next_interval_length.get() / 2 + 1) {
                pool.advance_round_normal_operation_no_cup();
            }

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
                Duration::from_secs(0)
            );

            state_manager.get_mut().checkpoint();
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(PoolReader::new(&pool).get_finalized_height());

            pool.advance_round_normal_operation_no_cup();

            assert_eq!(
                get_adjusted_notary_delay_from_settings(
                    settings,
                    &PoolReader::new(&pool),
                    state_manager.as_ref(),
                    Rank(0),
                ),
                Duration::from_secs(1)
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
}
