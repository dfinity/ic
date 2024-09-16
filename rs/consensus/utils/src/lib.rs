//! Consensus utility functions
use crate::{crypto::Aggregate, membership::Membership};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, warn, ReplicaLogger};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    consensus::{idkg::IDkgPayload, Block, HasCommittee, HasHeight, Threshold},
    crypto::{
        threshold_sig::ni_dkg::{NiDkgId, NiDkgReceivers, NiDkgTag, NiDkgTranscript},
        CryptoHash, CryptoHashable, Signed,
    },
    Height, RegistryVersion, ReplicaVersion, SubnetId,
};
use std::collections::{BTreeMap, BTreeSet};

pub mod crypto;
pub mod membership;
pub mod pool_reader;

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
pub fn active_low_threshold_nidkg_id(
    reader: &dyn ConsensusPoolCache,
    height: Height,
) -> Option<NiDkgId> {
    get_active_data_at(reader, height, |block, height| {
        get_transcript_data_at_given_summary(block, height, NiDkgTag::LowThreshold, |transcript| {
            transcript.dkg_id
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
            transcript.dkg_id
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

fn get_transcript_data_at_given_summary<T>(
    summary_block: &Block,
    height: Height,
    tag: NiDkgTag,
    getter: impl Fn(&NiDkgTranscript) -> T,
) -> Option<T> {
    let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
    if dkg_summary.current_interval_includes(height) {
        Some(getter(dkg_summary.current_transcript(&tag)))
    } else if dkg_summary.next_interval_includes(height) {
        let transcript = dkg_summary
            .next_transcript(&tag)
            .unwrap_or_else(|| dkg_summary.current_transcript(&tag));
        Some(getter(transcript))
    } else {
        None
    }
}

/// Return the oldest registry version of transcripts in the given IDKG summary payload that are
/// referenced by the given replicated state.
pub fn get_oldest_idkg_state_registry_version(
    idkg: &IDkgPayload,
    state: &ReplicatedState,
) -> Option<RegistryVersion> {
    state
        .signature_request_contexts()
        .values()
        .flat_map(|context| context.matched_pre_signature.as_ref())
        .flat_map(|(pre_sig_id, _)| idkg.available_pre_signatures.get(pre_sig_id))
        .flat_map(|pre_signature| pre_signature.get_refs())
        .flat_map(|transcript_ref| idkg.idkg_transcripts.get(&transcript_ref.transcript_id))
        .map(|transcript| transcript.registry_version)
        .min()
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use super::*;
    use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId, SchnorrKeyId};
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, SchnorrArguments, SignWithThresholdContext, ThresholdArguments,
    };
    use ic_test_utilities_state::ReplicatedStateBuilder;
    use ic_test_utilities_types::{
        ids::{node_test_id, subnet_test_id},
        messages::RequestBuilder,
    };
    use ic_types::{
        consensus::idkg::{
            common::PreSignatureRef, ecdsa::PreSignatureQuadrupleRef,
            schnorr::PreSignatureTranscriptRef, KeyTranscriptCreation, MaskedTranscript,
            MasterKeyTranscript, PreSigId, UnmaskedTranscript,
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

    fn empty_idkg_payload(key_id: MasterPublicKeyId) -> IDkgPayload {
        IDkgPayload::empty(
            Height::new(0),
            subnet_test_id(0),
            vec![MasterKeyTranscript::new(
                key_id,
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

    // Create a fake ecdsa pre-signature, it will use transcripts with ids
    // id, id+1, id+2, and id+3.
    fn fake_ecdsa_quadruple(id: u64, key_id: EcdsaKeyId) -> PreSignatureQuadrupleRef {
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
            key_id,
            kappa_unmasked_ref: UnmaskedTranscript::try_from((h, &kappa_unmasked)).unwrap(),
            lambda_masked_ref: MaskedTranscript::try_from((h, &lambda_masked)).unwrap(),
            kappa_times_lambda_ref: MaskedTranscript::try_from((h, &kappa_times_lambda)).unwrap(),
            key_times_lambda_ref: MaskedTranscript::try_from((h, &key_times_lambda)).unwrap(),
            key_unmasked_ref: UnmaskedTranscript::try_from((h, &key_unmasked)).unwrap(),
        }
    }

    // Create a fake schnorr pre-signature, it will use transcripts with ids
    // id and id+1.
    fn fake_schnorr_transcript(id: u64, key_id: SchnorrKeyId) -> PreSignatureTranscriptRef {
        let temp_rv = RegistryVersion::from(0);
        let blinder_unmasked = fake_transcript(fake_transcript_id(id), temp_rv);
        let mut key_unmasked = blinder_unmasked.clone();
        key_unmasked.transcript_id = fake_transcript_id(id + 1);
        let h = Height::from(0);
        PreSignatureTranscriptRef {
            key_id,
            blinder_unmasked_ref: UnmaskedTranscript::try_from((h, &blinder_unmasked)).unwrap(),
            key_unmasked_ref: UnmaskedTranscript::try_from((h, &key_unmasked)).unwrap(),
        }
    }

    fn fake_pre_signature(id: u64, key_id: &MasterPublicKeyId) -> PreSignatureRef {
        match key_id {
            MasterPublicKeyId::Ecdsa(key_id) => {
                PreSignatureRef::Ecdsa(fake_ecdsa_quadruple(id, key_id.clone()))
            }
            MasterPublicKeyId::Schnorr(key_id) => {
                PreSignatureRef::Schnorr(fake_schnorr_transcript(id, key_id.clone()))
            }
        }
    }

    fn fake_context(
        pre_signature_id: Option<PreSigId>,
        key_id: &MasterPublicKeyId,
    ) -> SignWithThresholdContext {
        SignWithThresholdContext {
            request: RequestBuilder::new().build(),
            args: match key_id {
                MasterPublicKeyId::Ecdsa(key_id) => ThresholdArguments::Ecdsa(EcdsaArguments {
                    message_hash: [0; 32],
                    key_id: key_id.clone(),
                }),
                MasterPublicKeyId::Schnorr(key_id) => {
                    ThresholdArguments::Schnorr(SchnorrArguments {
                        message: Arc::new(vec![1; 64]),
                        key_id: key_id.clone(),
                    })
                }
            },
            derivation_path: vec![],
            pseudo_random_id: [0; 32],
            matched_pre_signature: pre_signature_id.map(|qid| (qid, Height::from(0))),
            nonce: None,
            batch_time: UNIX_EPOCH,
        }
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
        vec![
            MasterPublicKeyId::Ecdsa(EcdsaKeyId::from_str("Secp256k1:some_key").unwrap()),
            MasterPublicKeyId::Schnorr(SchnorrKeyId::from_str("Ed25519:some_key").unwrap()),
        ]
    }

    // Create an IDKG payload with 10 pre-signatures, each using registry version 2, 3 or 4.
    fn idkg_payload_with_pre_sigs(key_id: &MasterPublicKeyId) -> IDkgPayload {
        let mut idkg = empty_idkg_payload(key_id.clone());
        let mut rvs = [
            RegistryVersion::from(2),
            RegistryVersion::from(3),
            RegistryVersion::from(4),
        ]
        .into_iter()
        .cycle();
        for i in (0..50).step_by(5) {
            let pre_sig = fake_pre_signature(i as u64, key_id);
            let rv = rvs.next().unwrap();
            for r in pre_sig.get_refs() {
                idkg.idkg_transcripts
                    .insert(r.transcript_id, fake_transcript(r.transcript_id, rv));
            }
            idkg.available_pre_signatures
                .insert(PreSigId(i as u64), pre_sig);
        }
        idkg
    }

    #[test]
    fn test_empty_state_should_return_no_registry_version() {
        for key_id in fake_key_ids() {
            println!("Running test for key ID {key_id}");
            let idkg = idkg_payload_with_pre_sigs(&key_id);
            let state = fake_state_with_contexts(vec![]);
            assert_eq!(None, get_oldest_idkg_state_registry_version(&idkg, &state));
        }
    }

    #[test]
    fn test_state_without_matches_should_return_no_registry_version() {
        for key_id in fake_key_ids() {
            println!("Running test for key ID {key_id}");
            let idkg = idkg_payload_with_pre_sigs(&key_id);
            let state = fake_state_with_contexts(vec![fake_context(None, &key_id)]);
            assert_eq!(None, get_oldest_idkg_state_registry_version(&idkg, &state));
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
        let idkg = idkg_payload_with_pre_sigs(&key_id);
        // create contexts for all pre-signatures, but only create a match for
        // pre-signatures with registry version >= 3 (not 2!). Thus the oldest
        // registry version referenced by the state should be 3.
        let contexts = idkg
            .available_pre_signatures
            .iter()
            .map(|(id, pre_sig)| {
                let t_id = pre_sig.key_unmasked().as_ref().transcript_id;
                let transcript = idkg.idkg_transcripts.get(&t_id).unwrap();
                (transcript.registry_version.get() >= 3).then_some(*id)
            })
            .map(|id| fake_context(id, &key_id))
            .collect();
        let state = fake_state_with_contexts(contexts);
        assert_eq!(
            Some(RegistryVersion::from(3)),
            get_oldest_idkg_state_registry_version(&idkg, &state)
        );

        let mut idkg_without_transcripts = idkg.clone();
        idkg_without_transcripts.idkg_transcripts = BTreeMap::new();
        assert_eq!(
            None,
            get_oldest_idkg_state_registry_version(&idkg_without_transcripts, &state)
        );

        let mut idkg_without_pre_sigs = idkg.clone();
        idkg_without_pre_sigs.available_pre_signatures = BTreeMap::new();
        assert_eq!(
            None,
            get_oldest_idkg_state_registry_version(&idkg_without_pre_sigs, &state)
        );
    }
}
