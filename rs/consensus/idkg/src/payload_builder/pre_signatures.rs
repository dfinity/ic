// TODO(CON-1530): Remove this once the new code is called
#![allow(dead_code)]
use crate::payload_builder::IDkgPayloadError;
use ic_interfaces_state_manager::Labeled;
use ic_logger::{ReplicaLogger, debug, error};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_replicated_state::{
    ReplicatedState, metadata_state::subnet_call_context_manager::IDkgSignWithThresholdContext,
};
use ic_types::{
    Height, NodeId, RegistryVersion,
    consensus::idkg::{
        self, HasIDkgMasterPublicKeyId, IDkgBlockReader, IDkgMasterPublicKeyId, IDkgUIDGenerator,
        PreSigId, TranscriptAttributes, UnmaskedTranscriptWithAttributes,
        common::{PreSignatureInCreation, PreSignatureRef},
        ecdsa::{PreSignatureQuadrupleRef, QuadrupleInCreation},
        schnorr::{PreSignatureTranscriptRef, TranscriptInCreation},
    },
    crypto::{
        AlgorithmId,
        canister_threshold_sig::idkg::{IDkgTranscript, IDkgTranscriptId},
    },
    messages::CallbackId,
};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    sync::Arc,
};

/// Update the pre-signatures in the payload by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from idkg pool;
/// - moving completed pre-signatures from "in creation" to "available".
///
/// Returns the newly created transcripts.
pub(super) fn update_pre_signatures_in_creation(
    payload: &mut idkg::IDkgPayload,
    mut transcripts: BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    height: Height,
    log: &ReplicaLogger,
) -> Result<Vec<IDkgTranscript>, IDkgPayloadError> {
    let mut newly_available = BTreeMap::new();
    let mut new_transcripts = Vec::new();
    for (pre_signature_id, pre_signature) in payload.pre_signatures_in_creation.iter_mut() {
        let Some(key_transcript) = &payload
            .key_transcripts
            .get(&pre_signature.key_id())
            .and_then(|key_transcript| key_transcript.current.as_ref())
        else {
            error!(
                every_n_seconds => 30,
                log,
                "The IDKG payload is missing a key transcript with key_id: {}",
                pre_signature.key_id());

            continue;
        };

        let (finished, transcripts) = match pre_signature {
            PreSignatureInCreation::Ecdsa(quadruple) => update_ecdsa_quadruple_in_creation(
                *pre_signature_id,
                quadruple,
                key_transcript,
                &mut transcripts,
                &mut payload.uid_generator,
                height,
                log,
            )?,
            PreSignatureInCreation::Schnorr(transcript) => update_schnorr_transcript_in_creation(
                *pre_signature_id,
                transcript,
                &mut transcripts,
                height,
                log,
            )?,
        };

        new_transcripts.extend(transcripts);
        if finished {
            newly_available.insert(*pre_signature_id, key_transcript.unmasked_transcript());
        }
    }

    for (pre_signature_id, key_unmasked) in newly_available {
        // the following unwraps are safe
        let pre_signature = match payload
            .pre_signatures_in_creation
            .remove(&pre_signature_id)
            .unwrap()
        {
            PreSignatureInCreation::Ecdsa(quadruple) => {
                let lambda_masked = quadruple.lambda_masked.unwrap();
                let kappa_unmasked = quadruple.kappa_unmasked.unwrap();
                let key_times_lambda = quadruple.key_times_lambda.unwrap();
                let kappa_times_lambda = quadruple.kappa_times_lambda.unwrap();
                PreSignatureRef::Ecdsa(PreSignatureQuadrupleRef::new(
                    quadruple.key_id.clone(),
                    kappa_unmasked,
                    lambda_masked,
                    kappa_times_lambda,
                    key_times_lambda,
                    key_unmasked,
                ))
            }
            PreSignatureInCreation::Schnorr(transcript) => {
                let blinder_unmasked = transcript.blinder_unmasked.unwrap();
                PreSignatureRef::Schnorr(PreSignatureTranscriptRef::new(
                    transcript.key_id.clone(),
                    blinder_unmasked,
                    key_unmasked,
                ))
            }
        };

        debug!(
            log,
            "update_pre_signatures_in_creation: making of pre-signature {:?} is complete",
            pre_signature_id
        );
        payload
            .available_pre_signatures
            .insert(pre_signature_id, pre_signature);
    }

    Ok(new_transcripts)
}

/// Update the given tECDSA quadruple by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from the pool;
///
/// Returns the newly created transcripts and if creation of this pre-signature has finished.
fn update_ecdsa_quadruple_in_creation(
    pre_signature_id: PreSigId,
    quadruple: &mut QuadrupleInCreation,
    key_transcript: &UnmaskedTranscriptWithAttributes,
    transcripts: &mut BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    uid_generator: &mut IDkgUIDGenerator,
    height: Height,
    log: &ReplicaLogger,
) -> Result<(bool, Vec<IDkgTranscript>), IDkgPayloadError> {
    let mut new_transcripts = Vec::new();
    let registry_version = key_transcript.registry_version();
    let receivers = key_transcript.receivers().clone();
    // Update quadruple with completed transcripts
    if quadruple.lambda_masked.is_none()
        && let Some(transcript) =
            transcripts.remove(&quadruple.lambda_config.as_ref().transcript_id)
    {
        debug!(
            log,
            "update_ecdsa_quadruple_in_creation: {:?} lamdba_masked transcript is made",
            pre_signature_id
        );
        quadruple.lambda_masked = Some(idkg::MaskedTranscript::try_from((height, &transcript))?);
        new_transcripts.push(transcript);
    }
    if quadruple.kappa_unmasked.is_none()
        && let Some(transcript) =
            transcripts.remove(&quadruple.kappa_unmasked_config.as_ref().transcript_id)
    {
        debug!(
            log,
            "update_ecdsa_quadruple_in_creation: {:?} kappa_unmasked transcript {:?} is \
                        made from unmasked config",
            pre_signature_id,
            transcript.get_type()
        );
        quadruple.kappa_unmasked = Some(idkg::UnmaskedTranscript::try_from((height, &transcript))?);
        new_transcripts.push(transcript);
    }
    if quadruple.key_times_lambda.is_none()
        && let Some(config) = &quadruple.key_times_lambda_config
        && let Some(transcript) = transcripts.remove(&config.as_ref().transcript_id)
    {
        debug!(
            log,
            "update_ecdsa_quadruple_in_creation: {:?} key_times_lambda transcript is made",
            pre_signature_id
        );
        quadruple.key_times_lambda = Some(idkg::MaskedTranscript::try_from((height, &transcript))?);
        new_transcripts.push(transcript);
    }
    if quadruple.kappa_times_lambda.is_none()
        && let Some(config) = &quadruple.kappa_times_lambda_config
        && let Some(transcript) = transcripts.remove(&config.as_ref().transcript_id)
    {
        debug!(
            log,
            "update_ecdsa_quadruple_in_creation: {:?} kappa_times_lambda transcript is made",
            pre_signature_id
        );
        quadruple.kappa_times_lambda =
            Some(idkg::MaskedTranscript::try_from((height, &transcript))?);
        new_transcripts.push(transcript);
    }
    // Check what to do in the next step
    if let (Some(lambda_masked), None) =
        (&quadruple.lambda_masked, &quadruple.key_times_lambda_config)
    {
        let lambda_config = quadruple.lambda_config.as_ref();
        if key_transcript.receivers() != lambda_config.receivers() {
            error!(
                log,
                "Key transcript has a different receiver set than lambda_config: {:?} {:?}",
                key_transcript,
                lambda_config
            );
        } else {
            quadruple.key_times_lambda_config = Some(idkg::UnmaskedTimesMaskedParams::new(
                uid_generator.next_transcript_id(),
                receivers.clone(),
                registry_version,
                (key_transcript, key_transcript.unmasked_transcript()),
                (lambda_config, *lambda_masked),
            ));
        }
    }
    if let (Some(lambda_masked), Some(kappa_unmasked), None) = (
        &quadruple.lambda_masked,
        &quadruple.kappa_unmasked,
        &quadruple.kappa_times_lambda_config,
    ) {
        let lambda_config = quadruple.lambda_config.as_ref();
        let kappa_config = quadruple.kappa_unmasked_config.as_ref();
        if kappa_config.receivers() != lambda_config.receivers() {
            error!(
                log,
                "kappa_config has a different receiver set than lambda_config: {:?} {:?}",
                kappa_config,
                lambda_config
            );
        } else {
            quadruple.kappa_times_lambda_config = Some(idkg::UnmaskedTimesMaskedParams::new(
                uid_generator.next_transcript_id(),
                receivers.clone(),
                registry_version,
                (kappa_config, *kappa_unmasked),
                (lambda_config, *lambda_masked),
            ));
        }
    }

    let finished = quadruple.kappa_unmasked.is_some()
        && quadruple.lambda_masked.is_some()
        && quadruple.key_times_lambda.is_some()
        && quadruple.kappa_times_lambda.is_some();
    Ok((finished, new_transcripts))
}

/// Update the given tSchnorr pre-signature by gathering ready results (new transcripts)
/// from the pool. Returns the newly created transcripts and if this pre-signature creation
/// is finished.
fn update_schnorr_transcript_in_creation(
    pre_signature_id: PreSigId,
    pre_signature: &mut TranscriptInCreation,
    transcripts: &mut BTreeMap<IDkgTranscriptId, IDkgTranscript>,
    height: Height,
    log: &ReplicaLogger,
) -> Result<(bool, Vec<IDkgTranscript>), IDkgPayloadError> {
    let mut new_transcripts = Vec::new();
    // Update pre_signature with completed transcripts
    if pre_signature.blinder_unmasked.is_none()
        && let Some(transcript) =
            transcripts.remove(&pre_signature.blinder_unmasked_config.as_ref().transcript_id)
    {
        debug!(
            log,
            "update_schnorr_transcript_in_creation: {:?} blinder_unmasked transcript is made",
            pre_signature_id
        );
        pre_signature.blinder_unmasked =
            Some(idkg::UnmaskedTranscript::try_from((height, &transcript))?);
        new_transcripts.push(transcript);
    }
    Ok((pre_signature.blinder_unmasked.is_some(), new_transcripts))
}

/// Purge all available but unmatched pre-signatures that are referencing a different key transcript
/// than the one currently used.
pub(super) fn purge_old_key_pre_signatures(
    idkg_payload: &mut idkg::IDkgPayload,
    all_signing_requests: &BTreeMap<CallbackId, IDkgSignWithThresholdContext<'_>>,
) {
    let matched_pre_signatures = all_signing_requests
        .values()
        .flat_map(|context| context.matched_pre_signature)
        .map(|(pre_sig_id, _)| pre_sig_id)
        .collect::<BTreeSet<_>>();

    idkg_payload.available_pre_signatures.retain(|id, pre_sig| {
        matched_pre_signatures.contains(id)
            || idkg_payload
                .key_transcripts
                .get(&pre_sig.key_id())
                .and_then(|key_transcript| key_transcript.current.as_ref())
                .is_some_and(|current_key_transcript| {
                    pre_sig.key_unmasked().as_ref().transcript_id
                        == current_key_transcript.transcript_id()
                })
    });
}

/// Creating new pre-signatures if necessary by updating pre_signatures_in_creation,
/// considering currently available pre-signatures, pre-signatures in creation, and
/// chain key configs.
pub(super) fn make_new_pre_signatures_if_needed(
    chain_key_config: &ChainKeyConfig,
    idkg_payload: &mut idkg::IDkgPayload,
    matched_pre_signatures_per_key_id: &BTreeMap<IDkgMasterPublicKeyId, usize>,
) {
    for (key_id, key_transcript) in &idkg_payload.key_transcripts {
        let Some(key_transcript) = key_transcript.current.as_ref() else {
            continue;
        };

        let matched_pre_signature = matched_pre_signatures_per_key_id
            .get(key_id)
            .copied()
            .unwrap_or_default();

        let unassigned_pre_signatures = idkg_payload
            .iter_pre_signature_ids(key_id)
            .count()
            .saturating_sub(matched_pre_signature);

        let node_ids: Vec<_> = key_transcript.receivers().iter().copied().collect();
        let new_pre_signatures = make_new_pre_signatures_if_needed_helper(
            &node_ids,
            key_transcript.registry_version(),
            chain_key_config,
            key_id,
            &mut idkg_payload.uid_generator,
            unassigned_pre_signatures,
        );

        idkg_payload
            .pre_signatures_in_creation
            .extend(new_pre_signatures);
    }
}

fn make_new_pre_signatures_if_needed_helper(
    subnet_nodes: &[NodeId],
    registry_version: RegistryVersion,
    chain_key_config: &ChainKeyConfig,
    key_id: &IDkgMasterPublicKeyId,
    uid_generator: &mut IDkgUIDGenerator,
    unassigned_pre_signatures: usize,
) -> BTreeMap<PreSigId, PreSignatureInCreation> {
    let mut new_pre_signatures = BTreeMap::new();

    let Some(pre_signatures_to_create) = chain_key_config
        .key_configs
        .iter()
        .find(|key_config| &key_config.key_id == key_id.inner())
        .and_then(|key_config| key_config.pre_signatures_to_create_in_advance)
        .map(|pre_sigs_to_create| pre_sigs_to_create as usize)
    else {
        return new_pre_signatures;
    };

    if pre_signatures_to_create <= unassigned_pre_signatures {
        return new_pre_signatures;
    }

    for _ in 0..(pre_signatures_to_create - unassigned_pre_signatures) {
        match key_id.inner() {
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => {
                let kappa_config = new_random_unmasked_config(
                    key_id,
                    subnet_nodes,
                    registry_version,
                    uid_generator,
                );
                let lambda_config =
                    new_random_config(key_id, subnet_nodes, registry_version, uid_generator);
                let pre_signature = PreSignatureInCreation::Ecdsa(QuadrupleInCreation::new(
                    ecdsa_key_id.clone(),
                    kappa_config,
                    lambda_config,
                ));
                new_pre_signatures.insert(uid_generator.next_pre_signature_id(), pre_signature);
            }
            MasterPublicKeyId::Schnorr(schnorr_key_id) => {
                let blinder_config = new_random_unmasked_config(
                    key_id,
                    subnet_nodes,
                    registry_version,
                    uid_generator,
                );
                let pre_signature = PreSignatureInCreation::Schnorr(TranscriptInCreation::new(
                    schnorr_key_id.clone(),
                    blinder_config,
                ));
                new_pre_signatures.insert(uid_generator.next_pre_signature_id(), pre_signature);
            }
            MasterPublicKeyId::VetKd(_vetkd_key_id) => {
                // vetKD does not have pre-signatures
            }
        };
    }

    new_pre_signatures
}

/// Count the number of pre-signatures for each key ID in the given state,
/// and all blocks above the state height.
pub(super) fn count_pre_signatures_total(
    state: &Labeled<Arc<ReplicatedState>>,
    block_reader: &dyn IDkgBlockReader,
) -> BTreeMap<IDkgMasterPublicKeyId, usize> {
    let mut total = state
        .get_ref()
        .pre_signature_stashes()
        .iter()
        .map(|(key_id, stash)| (key_id.clone(), stash.pre_signatures.len()))
        .collect::<BTreeMap<_, _>>();

    block_reader
        .iter_above(state.height())
        .flat_map(|idkg| idkg.available_pre_signatures.values())
        .for_each(|pre_sig| {
            *total.entry(pre_sig.key_id()).or_default() += 1;
        });

    total
}

/// A struct to keep track of the current fill level of a pre-signature stash for a given
/// key ID and transcript. The [Ord] implementation assigns a higher priority to stashes with
/// proportionally lower fill level.
/// Ties between stashes of the same fill level are broken by comparing the key IDs instead.
#[derive(Clone, Debug, Eq)]
struct PrioritizedStash<'a> {
    count: usize,
    max: usize,
    key_id: &'a IDkgMasterPublicKeyId,
    key_transcript: &'a UnmaskedTranscriptWithAttributes,
}

impl Ord for PrioritizedStash<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Stashes with zero max should receive the least priority
        if self.max == 0 && other.max == 0 {
            // Use key_id as a tie breaker
            return self.key_id.cmp(other.key_id);
        } else if self.max == 0 {
            return Ordering::Less;
        } else if other.max == 0 {
            return Ordering::Greater;
        }

        // Compare the fill level by cross-multiplying to avoid floating-point arithmetic
        let self_level = self.count * other.max;
        let other_level = other.count * self.max;

        // Reverse the order to make the emptiest stash the greatest priority
        let res = other_level.cmp(&self_level);

        if res == Ordering::Equal {
            // Use key_id as a tie breaker
            return self.key_id.cmp(other.key_id);
        }

        res
    }
}

impl PartialEq for PrioritizedStash<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for PrioritizedStash<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Create a new masked random transcript config and advance the
/// next_unused_transcript_id by one.
fn new_random_config(
    key_id: &IDkgMasterPublicKeyId,
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    uid_generator: &mut idkg::IDkgUIDGenerator,
) -> idkg::RandomTranscriptParams {
    let transcript_id = uid_generator.next_transcript_id();
    let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
    let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();

    idkg::RandomTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::from(key_id.inner()),
    )
}

/// Create a new random unmasked transcript config and advance the
/// next_unused_transcript_id by one.
pub fn new_random_unmasked_config(
    key_id: &IDkgMasterPublicKeyId,
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    uid_generator: &mut idkg::IDkgUIDGenerator,
) -> idkg::RandomUnmaskedTranscriptParams {
    let transcript_id = uid_generator.next_transcript_id();
    let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
    let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();

    idkg::RandomUnmaskedTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::from(key_id.inner()),
    )
}

/// Return a new [PreSignatureInCreation] for the given key ID and transcript
fn start_pre_signature_in_creation(
    key_id: &IDkgMasterPublicKeyId,
    key_transcript: &UnmaskedTranscriptWithAttributes,
    uid_generator: &mut IDkgUIDGenerator,
) -> PreSignatureInCreation {
    let registry_version = key_transcript.registry_version();
    let subnet_nodes: Vec<_> = key_transcript.receivers().iter().copied().collect();
    match key_id.inner() {
        MasterPublicKeyId::Ecdsa(ecdsa_key_id) => {
            let kappa_config =
                new_random_unmasked_config(key_id, &subnet_nodes, registry_version, uid_generator);
            let lambda_config =
                new_random_config(key_id, &subnet_nodes, registry_version, uid_generator);
            PreSignatureInCreation::Ecdsa(QuadrupleInCreation::new(
                ecdsa_key_id.clone(),
                kappa_config,
                lambda_config,
            ))
        }
        MasterPublicKeyId::Schnorr(schnorr_key_id) => {
            let blinder_config =
                new_random_unmasked_config(key_id, &subnet_nodes, registry_version, uid_generator);
            PreSignatureInCreation::Schnorr(TranscriptInCreation::new(
                schnorr_key_id.clone(),
                blinder_config,
            ))
        }
        MasterPublicKeyId::VetKd(_vetkd_key_id) => {
            // vetKD does not have pre-signatures
            unreachable!("Not an IDkg Key ID");
        }
    }
}

/// Create new pre-signatures for the emptiest pre-signature stashes
/// until all stashes are full, or the maximum number of pre-signatures
/// in creation is reached for this payload.
pub(super) fn make_new_pre_signatures_by_priority(
    chain_key_config: &ChainKeyConfig,
    // The payload that new pre-signatures should be started in
    idkg_payload: &mut idkg::IDkgPayload,
    // The total number of existing pre-signatures in the state and
    // the blockchain up to (including) the parent of this payload
    total_pre_signatures_up_to_parent: BTreeMap<IDkgMasterPublicKeyId, usize>,
) {
    let mut total_pre_signatures = total_pre_signatures_up_to_parent;
    // Add available and ongoing pre-signatures of this payload to the counter
    // tracking the stash sizes.
    idkg_payload
        .available_pre_signatures
        .values()
        .for_each(|pre_sig| {
            *total_pre_signatures.entry(pre_sig.key_id()).or_default() += 1;
        });
    idkg_payload
        .pre_signatures_in_creation
        .values()
        .for_each(|pre_sig| {
            *total_pre_signatures.entry(pre_sig.key_id()).or_default() += 1;
        });

    // Initialize the priority queue
    let mut priority_queue = BinaryHeap::new();
    for (key_id, key_transcript) in &idkg_payload.key_transcripts {
        let Some(key_transcript) = key_transcript.current.as_ref() else {
            continue;
        };
        let max_stash_size = chain_key_config
            .key_config(key_id.inner())
            .and_then(|config| config.pre_signatures_to_create_in_advance)
            .unwrap_or_default();
        priority_queue.push(PrioritizedStash {
            count: *total_pre_signatures.get(key_id).unwrap_or(&0),
            max: max_stash_size as usize,
            key_id,
            key_transcript,
        });
    }

    loop {
        // There are no key transcipts to generate pre-signatures for
        let Some(mut emptiest_stash) = priority_queue.pop() else {
            return;
        };

        // The emptiest stash is full -> all stashes are full
        if emptiest_stash.count >= emptiest_stash.max {
            return;
        }

        // The maximum number of transcripts that we want to work on in parallel
        // in any given payload.
        let max_capacity = chain_key_config
            .max_parallel_pre_signature_transcripts_in_creation
            .unwrap_or(20) as usize;

        // Each ongoing pre-signature in creation consumes some of the maximum capacity.
        // For instance, Schnorr pre-signatures consist of a single transcript, and
        // therefore consume 1 transcript in capacity. ECDSA pre-signatures require working
        // on two transcripts in parallel, and therefore consume 2 capacity points.
        let available_pre_sig_capacity =
            max_capacity.saturating_sub(idkg_payload.consumed_pre_sig_capacity());

        // There isn't enough capacity to create a pre-signature of the highest priority
        // in this payload. Note that the following situation may occur:
        // The emptiest stash asks for an ECDSA pre-signature, however, there is only
        // enough capacity to create a Schnorr pre-signature. In that case, we should not
        // start a new Schnorr pre-signature, and instead wait until enough capacity exists
        // in the payload to start the creation of a new ECDSA pre-signature, which has
        // the highest priority. This is to prevent the creation of ECDSA pre-signatures
        // being starved.
        if emptiest_stash.key_id.required_pre_sig_capacity() > available_pre_sig_capacity {
            return;
        }

        // If there is enough capacity, start the new pre-signature and add it to the payload.
        let uid_generator = &mut idkg_payload.uid_generator;
        let pre_signature = start_pre_signature_in_creation(
            emptiest_stash.key_id,
            emptiest_stash.key_transcript,
            uid_generator,
        );
        idkg_payload
            .pre_signatures_in_creation
            .insert(uid_generator.next_pre_signature_id(), pre_signature);

        // Re-insert the updated stash into the priority queue.
        emptiest_stash.count += 1;
        priority_queue.push(emptiest_stash);
    }
}

#[cfg(test)]
pub(super) mod test_utils {
    use super::*;
    use crate::test_utils::IDkgPayloadTestHelper;
    use ic_types::{
        NodeId, RegistryVersion,
        consensus::idkg::{self, IDkgMasterPublicKeyId, IDkgTranscriptParamsRef},
    };
    use std::collections::BTreeMap;

    pub fn create_new_pre_signature_in_creation(
        subnet_nodes: &[NodeId],
        registry_version: RegistryVersion,
        uid_generator: &mut idkg::IDkgUIDGenerator,
        key_id: IDkgMasterPublicKeyId,
        pre_signatures_in_creation: &mut BTreeMap<idkg::PreSigId, PreSignatureInCreation>,
    ) -> Vec<IDkgTranscriptParamsRef> {
        let pre_signature = match key_id.clone().into() {
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => {
                let kappa_config_ref = new_random_unmasked_config(
                    &key_id,
                    subnet_nodes,
                    registry_version,
                    uid_generator,
                );
                let lambda_config_ref =
                    new_random_config(&key_id, subnet_nodes, registry_version, uid_generator);
                PreSignatureInCreation::Ecdsa(QuadrupleInCreation::new(
                    ecdsa_key_id,
                    kappa_config_ref,
                    lambda_config_ref,
                ))
            }
            MasterPublicKeyId::Schnorr(schnorr_key_id) => {
                let blinder_config_ref = new_random_unmasked_config(
                    &key_id,
                    subnet_nodes,
                    registry_version,
                    uid_generator,
                );
                PreSignatureInCreation::Schnorr(TranscriptInCreation::new(
                    schnorr_key_id,
                    blinder_config_ref,
                ))
            }
            MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
        };
        let configs = pre_signature
            .iter_transcript_configs_in_creation()
            .cloned()
            .collect::<Vec<_>>();
        pre_signatures_in_creation.insert(uid_generator.next_pre_signature_id(), pre_signature);
        configs
    }

    /// Return a sorted list of IDs of all transcripts in creation
    pub fn config_ids(payload: &idkg::IDkgPayload) -> Vec<u64> {
        let mut arr = payload
            .iter_transcript_configs_in_creation()
            .map(|x| x.transcript_id.id())
            .collect::<Vec<_>>();
        arr.sort_unstable();
        arr
    }

    /// Return a sorted list of IDs of all completed transcripts,
    /// excluding the key transcript
    pub fn transcript_ids(payload: &idkg::IDkgPayload) -> Vec<u64> {
        let key_transcript = payload.single_key_transcript().current.as_ref().unwrap();
        let mut arr = payload
            .active_transcripts()
            .into_iter()
            .map(|x| x.transcript_id.id())
            .filter(|id| *id != key_transcript.transcript_id().id())
            .collect::<Vec<_>>();
        arr.sort_unstable();
        arr
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::{test_utils::*, *};
    use crate::{
        test_utils::{
            IDkgPayloadTestHelper, TestIDkgBlockReader, create_available_pre_signature,
            create_available_pre_signature_with_key_transcript, into_idkg_contexts,
            set_up_idkg_payload,
        },
        utils::block_chain_reader,
    };
    use assert_matches::assert_matches;
    use ic_consensus_mocks::{Dependencies, dependencies};
    use ic_consensus_utils::pool_reader::PoolReader;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CanisterThresholdSigTestEnvironment, IDkgParticipants, generate_key_transcript,
        mock_transcript, mock_unmasked_transcript_type,
    };
    use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types_private::SchnorrAlgorithm;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_consensus::idkg::*;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        SubnetId,
        batch::BatchPayload,
        consensus::{
            BlockPayload, DataPayload, HasHeight, HashedBlock, Payload,
            dkg::DkgDataPayload,
            idkg::{
                IDkgMasterPublicKeyId, IDkgPayload, IDkgTranscriptAttributes, UnmaskedTranscript,
                common::PreSignatureRef,
            },
        },
        crypto::canister_threshold_sig::idkg::IDkgTranscriptId,
    };
    use idkg::IDkgTranscriptOperationRef;
    use rand::prelude::SliceRandom;
    use strum::IntoEnumIterator;

    fn set_up(
        rng: &mut ReproducibleRng,
        subnet_id: SubnetId,
        key_ids: Vec<IDkgMasterPublicKeyId>,
        height: Height,
    ) -> (
        IDkgPayload,
        CanisterThresholdSigTestEnvironment,
        TestIDkgBlockReader,
    ) {
        let (mut idkg_payload, env, block_reader) = set_up_idkg_payload(
            rng, subnet_id, /*nodes_count=*/ 4, key_ids,
            /*should_create_key_transcript=*/ true,
        );
        idkg_payload
            .uid_generator
            .update_height(height)
            .expect("Should successfully update the height");

        (idkg_payload, env, block_reader)
    }

    #[test]
    fn test_count_pre_signatures_total() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                replica_config,
                ..
            } = dependencies(pool_config.clone(), 4);

            // Advance 4 rounds without IDkg
            let mut height = pool.advance_round_normal_operation_n(4);
            assert_eq!(height.get(), 4);

            // Create an IDkgPayload with available pre-signatures
            let key_ids = fake_master_public_key_ids_for_all_idkg_algorithms();
            let (mut idkg_payload, _, _) = set_up(
                &mut reproducible_rng(),
                replica_config.subnet_id,
                key_ids.clone(),
                height,
            );
            // create 3 pre-sigs for the first key, 1 for the second, none for the third
            for i in 0..3 {
                create_available_pre_signature(&mut idkg_payload, key_ids[0].clone(), i);
            }
            create_available_pre_signature(&mut idkg_payload, key_ids[1].clone(), 3);

            // add this payload 4 times.
            for _ in 0..4 {
                let mut block_proposal = pool.make_next_block();
                let block = block_proposal.content.as_mut();
                block.payload = Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Data(DataPayload {
                        batch: BatchPayload::default(),
                        dkg: DkgDataPayload::new_empty(Height::from(0)),
                        idkg: Some(idkg_payload.clone()),
                    }),
                );
                block_proposal.content =
                    HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.advance_round_with_block(&block_proposal);
                height = block_proposal.height();
            }
            assert_eq!(height.get(), 8);

            // Create the blockchain reader
            let pool_reader = PoolReader::new(&pool);
            let block_reader = block_chain_reader(
                &pool_reader,
                Height::from(0),
                pool_reader.get_finalized_tip(),
                None,
                &no_op_logger(),
            )
            .unwrap();

            // Create two pre-signature stashes, one for the first key, one for a new key
            let mut stashes = BTreeMap::new();
            // The first stash has 2 pre-signatures
            stashes.insert(key_ids[0].clone(), fake_pre_signature_stash(&key_ids[0], 2));
            let new_key_id = IDkgMasterPublicKeyId::try_from(key_id_with_name(
                key_ids[0].inner(),
                "some_new_key",
            ))
            .unwrap();
            // The second stash has 1 pre-signature
            stashes.insert(new_key_id.clone(), fake_pre_signature_stash(&new_key_id, 1));

            let mut state = ic_test_utilities_state::get_initial_state(0, 0);
            state
                .metadata
                .subnet_call_context_manager
                .pre_signature_stashes = stashes;

            // Create the certified state at height 6 (there are two more IDkgPayloads above)
            let certified_state =
                ic_interfaces_state_manager::Labeled::new(Height::new(6), Arc::new(state));

            // The entire blockchain should now contain pre-signatures for different keys as follows:
            // [ C ]--[ B1 ]--[ B2 ]--[ B3 ]--[ B4 ]--[   B5   ]---[   B6   ]---[   B7   ]---[   B8   ]
            //                                        [key0 x 3]   [key0 x 3]   [key0 x 3]   [key0 x 3]
            //                                        [key1 x 1]   [key1 x 1]   [key1 x 1]   [key1 x 1]
            //                                                         ||
            //                                            {State; key0 x 2; key3 x 1}

            // Count the total pre-signatures in and above the state for each key
            let count = count_pre_signatures_total(&certified_state, &block_reader);
            assert_eq!(count.len(), 3);
            // key0: 2 in the stash + 3 at height seven + 3 at height eight = 8
            assert_eq!(count[&key_ids[0]], 8);
            // key1: 0 in the stash + 1 at height seven + 1 at height eight = 2
            assert_eq!(count[&key_ids[1]], 2);
            // key2: No pre-signatures in the stash or the blockchain
            assert!(!count.contains_key(&key_ids[2]));
            // key3: 1 in the stash + 0 at height seven + 0 at height eight = 1
            assert_eq!(count[&new_key_id], 1);
        });
    }

    fn make_stash<'a>(
        count: usize,
        max: usize,
        key_id: &'a IDkgMasterPublicKeyId,
        key_transcript: &'a UnmaskedTranscriptWithAttributes,
    ) -> PrioritizedStash<'a> {
        PrioritizedStash {
            count,
            max,
            key_id,
            key_transcript,
        }
    }

    fn make_key_transcript() -> UnmaskedTranscriptWithAttributes {
        let mut rng = reproducible_rng();
        let alg = AlgorithmId::EcdsaSecp256k1;
        let transcript =
            mock_transcript(alg, None, mock_unmasked_transcript_type(&mut rng), &mut rng);
        UnmaskedTranscriptWithAttributes::new(
            IDkgTranscriptAttributes::new(BTreeSet::new(), alg, RegistryVersion::from(0)),
            UnmaskedTranscript::try_from((Height::from(0), &transcript)).unwrap(),
        )
    }

    #[test]
    fn test_emptier_stash_has_greater_priority() {
        let transcript = make_key_transcript();
        let id1 = fake_ecdsa_idkg_master_public_key_id();
        let id2 = fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519);

        let emptier = make_stash(1, 10, &id1, &transcript);
        let fuller = make_stash(5, 10, &id2, &transcript);

        // Emptier stash has greater priority
        assert_eq!(emptier.cmp(&fuller), Ordering::Greater);
        assert_eq!(fuller.cmp(&emptier), Ordering::Less);

        // switch the key_ids
        let emptier = make_stash(1, 10, &id2, &transcript);
        let fuller = make_stash(5, 10, &id1, &transcript);
        // Emptier stash should still have greater priority
        assert_eq!(emptier.cmp(&fuller), Ordering::Greater);
        assert_eq!(fuller.cmp(&emptier), Ordering::Less);
    }

    #[test]
    fn test_equal_ratios_uses_key_id_tiebreaker() {
        let transcript = make_key_transcript();
        let id1 = fake_ecdsa_idkg_master_public_key_id();
        let id2 = fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519);

        let stash1 = make_stash(2, 10, &id1, &transcript);
        let stash2 = make_stash(1, 5, &id2, &transcript);

        assert_eq!(id1.cmp(&id2), Ordering::Less);
        assert_eq!(stash1.cmp(&stash2), Ordering::Less);
        assert_eq!(stash2.cmp(&stash1), Ordering::Greater);

        // switch the key_ids
        let stash1 = make_stash(2, 10, &id2, &transcript);
        let stash2 = make_stash(1, 5, &id1, &transcript);
        // Order should be reversed
        assert_eq!(stash1.cmp(&stash2), Ordering::Greater);
        assert_eq!(stash2.cmp(&stash1), Ordering::Less);
    }

    #[test]
    fn test_stash_both_max_zero_orders_by_key_id() {
        let transcript = make_key_transcript();
        // both max = 0, order by key_id
        let id1 = fake_ecdsa_idkg_master_public_key_id();
        let id2 = fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519);

        let stash1 = make_stash(0, 0, &id1, &transcript);
        // counts shouldn't matter when max = 0
        let stash2 = make_stash(999, 0, &id2, &transcript);

        assert_eq!(id1.cmp(&id2), Ordering::Less);
        assert_eq!(stash1.cmp(&stash2), Ordering::Less);
        assert_eq!(stash2.cmp(&stash1), Ordering::Greater);

        // switch the key_ids
        let stash1 = make_stash(0, 0, &id2, &transcript);
        let stash2 = make_stash(999, 0, &id1, &transcript);
        // Order should be reversed
        assert_eq!(stash1.cmp(&stash2), Ordering::Greater);
        assert_eq!(stash2.cmp(&stash1), Ordering::Less);
    }

    #[test]
    fn test_zero_count_zero_max_has_lowest_priority() {
        let transcript = make_key_transcript();
        let id1 = fake_ecdsa_idkg_master_public_key_id();
        let id2 = fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519);
        let id3 = fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Bip340Secp256k1);

        let zero = make_stash(0, 0, &id1, &transcript);
        let nonzero = make_stash(2, 10, &id2, &transcript);
        let empty_nonzero = make_stash(0, 10, &id3, &transcript);

        // Stash with a max of zero has the lowest priority
        assert_eq!(zero.cmp(&nonzero), Ordering::Less);
        assert_eq!(nonzero.cmp(&zero), Ordering::Greater);
        assert_eq!(empty_nonzero.cmp(&nonzero), Ordering::Greater);
        assert_eq!(empty_nonzero.cmp(&zero), Ordering::Greater);

        // switch the key_ids
        let zero = make_stash(0, 0, &id2, &transcript);
        let nonzero = make_stash(2, 10, &id3, &transcript);
        let empty_nonzero = make_stash(0, 10, &id1, &transcript);
        // Stash with a max of zero should still have the lower priority
        assert_eq!(zero.cmp(&nonzero), Ordering::Less);
        assert_eq!(nonzero.cmp(&zero), Ordering::Greater);
        assert_eq!(empty_nonzero.cmp(&nonzero), Ordering::Greater);
        assert_eq!(empty_nonzero.cmp(&zero), Ordering::Greater);
    }

    #[test]
    fn test_max_zero_has_lowest_priority() {
        let transcript = make_key_transcript();
        let id1 = fake_ecdsa_idkg_master_public_key_id();
        let id2 = fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519);

        // Both stashes are over-filled
        let zero = make_stash(10, 0, &id1, &transcript);
        let nonzero = make_stash(15, 5, &id2, &transcript);

        // Stash with a max of zero has the lowest priority
        assert_eq!(zero.cmp(&nonzero), Ordering::Less);
        assert_eq!(nonzero.cmp(&zero), Ordering::Greater);

        // switch the key_ids
        let zero = make_stash(10, 0, &id2, &transcript);
        let nonzero = make_stash(15, 5, &id1, &transcript);
        // Stash with a max of zero should still have lower priority
        assert_eq!(zero.cmp(&nonzero), Ordering::Less);
        assert_eq!(nonzero.cmp(&zero), Ordering::Greater);
    }

    #[test]
    fn test_stash_equality() {
        let transcript = make_key_transcript();
        // All stashes have the same id
        let id = fake_ecdsa_idkg_master_public_key_id();

        // Both stashes have the same ratio
        let ratio1 = make_stash(1, 5, &id, &transcript);
        let ratio2 = make_stash(2, 10, &id, &transcript);

        // Both stashes have a count of 0
        let zero_count1 = make_stash(0, 5, &id, &transcript);
        let zero_count2 = make_stash(0, 10, &id, &transcript);

        // Both stashes have a max of 0
        let zero_max1 = make_stash(0, 0, &id, &transcript);
        let zero_max2 = make_stash(10, 0, &id, &transcript);

        for (a, b) in [
            (ratio1, ratio2),
            (zero_count1, zero_count2),
            (zero_max1, zero_max2),
        ] {
            assert_eq!(a.cmp(&b), Ordering::Equal);
            assert_eq!(b.cmp(&a), Ordering::Equal);
            assert_eq!(a.cmp(&a), Ordering::Equal);
            assert_eq!(b.cmp(&b), Ordering::Equal);
        }
    }

    #[test]
    fn sort_orders_as_specified() {
        fn make_key_id(i: u64) -> IDkgMasterPublicKeyId {
            let key_id = fake_ecdsa_idkg_master_public_key_id().inner().clone();
            key_id_with_name(&key_id, &format!("some_key{i}"))
                .try_into()
                .unwrap()
        }

        let ids = (0..6).map(make_key_id).collect::<Vec<_>>();
        let transcript = make_key_transcript();

        let expected = vec![
            make_stash(5, 0, &ids[3], &transcript),  // zero max
            make_stash(0, 0, &ids[4], &transcript),  // zero max but larger key_id than id 3
            make_stash(5, 10, &ids[2], &transcript), // ratio 0.5
            make_stash(2, 10, &ids[1], &transcript), // ratio 0.2
            make_stash(1, 5, &ids[2], &transcript),  // ratio 0.2 tie but larger key_id
            make_stash(1, 10, &ids[0], &transcript), // ratio 0.1 has highest priority
        ];

        let mut shuffled = expected.clone();

        shuffled.shuffle(&mut reproducible_rng());
        shuffled.sort();

        assert_eq!(expected, shuffled);
    }

    /// Make a [ChainKeyConfig] with the given payload and stash capacities
    fn make_config(
        payload_capacity: Option<u32>,
        stash_capacity: BTreeMap<IDkgMasterPublicKeyId, usize>,
    ) -> ChainKeyConfig {
        ChainKeyConfig {
            key_configs: stash_capacity
                .into_iter()
                .map(|(key_id, max)| KeyConfig {
                    key_id: key_id.inner().clone(),
                    pre_signatures_to_create_in_advance: Some(max as u32),
                    max_queue_size: 20,
                })
                .collect(),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: payload_capacity,
        }
    }

    #[test]
    fn test_payload_without_key_doesnt_start_pre_signature() {
        let key_ids = fake_master_public_key_ids_for_all_idkg_algorithms();
        let stash_capacity = key_ids.iter().cloned().map(|id| (id, 100)).collect();
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids,
            /*should_create_key_transcript=*/ false,
        );

        make_new_pre_signatures_by_priority(
            &make_config(Some(20), stash_capacity),
            &mut payload,
            BTreeMap::new(), // There are no pre-signatures in the stash
        );

        // There are no key transcripts, so no pre-signatures can be created even if there is capacity
        // in the payload and the stashes.
        assert!(payload.pre_signatures_in_creation.is_empty());
    }

    fn count_pre_sigs_in_creation(payload: &IDkgPayload) -> BTreeMap<IDkgMasterPublicKeyId, usize> {
        let mut map = BTreeMap::new();
        payload
            .pre_signatures_in_creation
            .values()
            .for_each(|pre_sig| {
                *map.entry(pre_sig.key_id()).or_default() += 1;
            });
        map
    }

    #[test]
    fn test_pre_signatures_are_started_up_to_payload_capacity() {
        let key_ids = fake_master_public_key_ids_for_all_idkg_algorithms();
        let stash_capacity: BTreeMap<_, _> = key_ids.iter().cloned().map(|id| (id, 100)).collect();
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids.clone(),
            /*should_create_key_transcript=*/ true,
        );

        let payload_capacity = 20;
        make_new_pre_signatures_by_priority(
            &make_config(Some(payload_capacity), stash_capacity.clone()),
            &mut payload,
            BTreeMap::new(), // There are no pre-signatures in the stash
        );

        // The entire payload capacity should be consumed
        assert_eq!(
            payload.consumed_pre_sig_capacity(),
            payload_capacity as usize
        );
        let count = count_pre_sigs_in_creation(&payload);
        // The same amount of pre-signatures should be started for each key
        assert_eq!(count.len(), key_ids.len());
        for key_id in key_ids {
            assert_eq!(count[&key_id], 5);
        }

        // The payload capacity was reduced (i.e. via proposal)
        let reduced_capacity = 10;
        // No new pre-signatures should be created (consumed capacity exceeds available capacity)
        let mut payload_2 = payload.clone();
        make_new_pre_signatures_by_priority(
            &make_config(Some(reduced_capacity), stash_capacity),
            &mut payload_2,
            BTreeMap::new(), // There are no pre-signatures in the stash
        );
        assert_eq!(payload, payload_2);
    }

    #[test]
    fn test_pre_signatures_are_started_up_to_stash_capacity() {
        let key_ids = fake_master_public_key_ids_for_all_idkg_algorithms();
        let stash_capacity: BTreeMap<_, usize> =
            key_ids.iter().cloned().map(|id| (id, 100)).collect();
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids.clone(),
            /*should_create_key_transcript=*/ true,
        );

        let payload_capacity = 20;
        make_new_pre_signatures_by_priority(
            &make_config(Some(payload_capacity), stash_capacity.clone()),
            &mut payload,
            stash_capacity, // All stashes are already filled to capacity
        );

        // No pre-signatures should be started
        assert_eq!(payload.consumed_pre_sig_capacity(), 0);
    }

    #[test]
    fn test_no_pre_signatures_are_started_if_stash_capacity_exceeded() {
        let key_ids = fake_master_public_key_ids_for_all_idkg_algorithms();
        let stash_capacity = key_ids.iter().cloned().map(|id| (id, 100)).collect();
        // The stash level is higher than the configured capacity
        let stash_level = key_ids.iter().cloned().map(|id| (id, 200)).collect();
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids.clone(),
            /*should_create_key_transcript=*/ true,
        );

        let payload_capacity = 20;
        make_new_pre_signatures_by_priority(
            &make_config(Some(payload_capacity), stash_capacity),
            &mut payload,
            stash_level,
        );

        // No pre-signatures should be started
        assert_eq!(payload.consumed_pre_sig_capacity(), 0);
    }

    #[test]
    fn test_no_pre_signatures_are_started_for_max_zero_stashes() {
        let key_ids = vec![
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Bip340Secp256k1),
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519),
        ];
        let stash_capacity =
            BTreeMap::from_iter([(key_ids[0].clone(), 100), (key_ids[1].clone(), 0)]);
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids.clone(),
            /*should_create_key_transcript=*/ true,
        );

        let payload_capacity = 20;
        make_new_pre_signatures_by_priority(
            &make_config(Some(payload_capacity), stash_capacity.clone()),
            &mut payload,
            BTreeMap::new(), // There are no pre-signatures in the stash
        );

        // New pre-signatures should be started up to the payload capacity
        assert_eq!(
            payload.consumed_pre_sig_capacity(),
            payload_capacity as usize
        );
        // All pre-signatures should be started for the nonzero stash
        let count = count_pre_sigs_in_creation(&payload);
        assert_eq!(count.len(), 1);
        assert_eq!(count[&key_ids[0]], 20);
    }

    #[test]
    fn test_ecdsa_pre_signatures_cannot_be_starved() {
        let key_ids = vec![
            fake_ecdsa_idkg_master_public_key_id(),
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519),
        ];
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids.clone(),
            /*should_create_key_transcript=*/ true,
        );

        // Setup: ECDSA stash is full, we should start 19 schnorr pre-signatures in creation
        let payload_capacity = 19;
        // Simulate a full ECDSA stash by setting the max size to 0, the Schnorr stash has a capacity of 100
        let stash_capacity =
            BTreeMap::from_iter([(key_ids[0].clone(), 0), (key_ids[1].clone(), 100)]);
        make_new_pre_signatures_by_priority(
            &make_config(Some(payload_capacity), stash_capacity),
            &mut payload,
            BTreeMap::new(), // There are no pre-signatures in the stash
        );

        // There should now be 19 ongoing Schnorr pre-signatures in the payload
        assert_eq!(
            payload.consumed_pre_sig_capacity(),
            payload_capacity as usize
        );
        let count = count_pre_sigs_in_creation(&payload);
        assert_eq!(count.len(), 1);
        assert_eq!(count[&key_ids[1]], 19);

        // Test: ECDSA stash has space (highest priority), but there is not enough capacity in the payload
        let payload_capacity = 20;
        // Now both stashes have a max size of 100
        let stash_capacity = key_ids.iter().cloned().map(|id| (id, 100)).collect();
        make_new_pre_signatures_by_priority(
            &make_config(Some(payload_capacity), stash_capacity),
            &mut payload, // The payload still contains the 19 ongoing Schnorr pre-signatures in creation
            BTreeMap::new(), // There are no pre-signatures in the stash
        );

        // The open capacity should not have been consumed by another Schnorr pre-signature
        // since it is lower priority.
        assert_eq!(
            payload.consumed_pre_sig_capacity(),
            (payload_capacity - 1) as usize
        );
        let count = count_pre_sigs_in_creation(&payload);
        assert_eq!(count.len(), 1);
        assert_eq!(count[&key_ids[1]], 19);
    }

    #[test]
    fn test_pre_signatures_are_started_for_the_emptiest_stash() {
        let key_ids = vec![
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Bip340Secp256k1),
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519),
        ];
        let stash_capacity = key_ids.iter().cloned().map(|id| (id, 100)).collect();
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids.clone(),
            /*should_create_key_transcript=*/ true,
        );

        make_new_pre_signatures_by_priority(
            // A capacity of `None` should default to 20
            &make_config(None, stash_capacity),
            &mut payload,
            BTreeMap::from_iter([
                // The first key already has some pre-signatures
                (key_ids[0].clone(), 50),
                (key_ids[1].clone(), 0),
            ]),
        );

        assert_eq!(payload.consumed_pre_sig_capacity(), 20);
        let count = count_pre_sigs_in_creation(&payload);
        assert_eq!(count.len(), 1);
        assert_eq!(count[&key_ids[1]], 20);
    }

    #[test]
    fn test_available_pre_signatures_are_considered_when_creating_new_ones() {
        let key_ids = vec![
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Bip340Secp256k1),
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519),
        ];
        let stash_capacity = key_ids.iter().cloned().map(|id| (id, 100)).collect();
        let (mut payload, _, _) = set_up_idkg_payload(
            &mut reproducible_rng(),
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids.clone(),
            /*should_create_key_transcript=*/ true,
        );

        // add 4 avaliable pre-signature for the second key into the payload
        for i in 0..4 {
            create_available_pre_signature(&mut payload, key_ids[1].clone(), i);
        }

        let payload_capacity = 20;
        make_new_pre_signatures_by_priority(
            &make_config(Some(payload_capacity), stash_capacity),
            &mut payload,
            key_ids.iter().cloned().map(|id| (id, 50)).collect(),
        );

        // We should create a total of 20 pre-signatures
        assert_eq!(
            payload.consumed_pre_sig_capacity(),
            payload_capacity as usize
        );
        let count = count_pre_sigs_in_creation(&payload);
        assert_eq!(count.len(), 2);
        // There are 4 more available pre-signatures for the second key in the payload already,
        // So we should create 4 more for the first key
        assert_eq!(count[&key_ids[0]], 12);
        assert_eq!(count[&key_ids[1]], 8);
    }

    #[test]
    fn test_schnorr_make_new_pre_signatures_if_needed_helper() {
        let nodes = &[node_test_id(0)];
        let registry_version = RegistryVersion::from(1);
        let subnet_id = subnet_test_id(1);
        let height = Height::new(10);
        let mut uid_generator = IDkgUIDGenerator::new(subnet_id, height);
        let pre_signatures_to_create_in_advance = 4;

        let mut create_pre_signatures = |key_id: &IDkgMasterPublicKeyId, unassigned| {
            let chain_key_config = ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: key_id.clone().into(),
                    pre_signatures_to_create_in_advance: Some(pre_signatures_to_create_in_advance),
                    max_queue_size: 1,
                }],
                ..ChainKeyConfig::default()
            };

            make_new_pre_signatures_if_needed_helper(
                nodes,
                registry_version,
                &chain_key_config,
                key_id,
                &mut uid_generator,
                unassigned,
            )
        };

        let key_id_bib340 =
            fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Bip340Secp256k1);
        let key_id_eddsa = fake_schnorr_idkg_master_public_key_id(SchnorrAlgorithm::Ed25519);

        for key_id in &[key_id_bib340, key_id_eddsa] {
            assert!(create_pre_signatures(key_id, 4).is_empty());
            let pre_sigs = create_pre_signatures(key_id, 1);
            assert_eq!(pre_sigs.len(), 3);
            for pre_sig in pre_sigs.values() {
                let PreSignatureInCreation::Schnorr(transcript) = pre_sig else {
                    panic!("Expected Schnorr pre-signature");
                };
                assert!(transcript.blinder_unmasked.is_none());
                assert_eq!(
                    MasterPublicKeyId::from(key_id.clone()),
                    MasterPublicKeyId::Schnorr(transcript.key_id.clone())
                );
                let config = transcript.blinder_unmasked_config.as_ref();
                assert_eq!(config.algorithm_id, AlgorithmId::from(key_id.inner()));
                assert_eq!(config.registry_version, registry_version);
                assert_eq!(config.dealers, config.receivers);
                assert_eq!(config.dealers, BTreeSet::from(*nodes));
                assert_eq!(
                    config.operation_type_ref,
                    IDkgTranscriptOperationRef::RandomUnmasked
                );
            }
        }
    }

    #[test]
    fn test_make_new_pre_signatures_if_needed_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_make_new_pre_signatures_if_needed(key_id);
        }
    }

    fn test_make_new_pre_signatures_if_needed(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let subnet_id = subnet_test_id(1);
        let height = Height::new(10);
        let (mut idkg_payload, _env, _block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], height);

        // 4 pre-signatures should be created in advance (in creation + unmatched available = 4)
        let pre_signatures_to_create_in_advance = 4;
        let chain_key_config = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: key_id.clone().into(),
                pre_signatures_to_create_in_advance: Some(pre_signatures_to_create_in_advance),
                max_queue_size: 1,
            }],
            ..ChainKeyConfig::default()
        };

        // Add 3 available pre-signatures
        for i in 0..3 {
            create_available_pre_signature(&mut idkg_payload, key_id.clone(), i);
        }

        // 2 available pre-signatures are already matched
        let pre_signature_already_matched = 2;

        // We expect 3 pre-signatures in creation to be added
        let expected_pre_signatures_in_creation = pre_signatures_to_create_in_advance as usize
            - (idkg_payload.available_pre_signatures.len() - pre_signature_already_matched);
        assert_eq!(expected_pre_signatures_in_creation, 3);

        make_new_pre_signatures_if_needed(
            &chain_key_config,
            &mut idkg_payload,
            &BTreeMap::from([(key_id.clone(), pre_signature_already_matched)]),
        );

        assert_eq!(
            idkg_payload.pre_signatures_in_creation.len()
                + idkg_payload.available_pre_signatures.len()
                - pre_signature_already_matched,
            pre_signatures_to_create_in_advance as usize
        );
        // Verify the generated transcript ids.
        let mut transcript_ids = BTreeSet::new();
        for pre_signature in idkg_payload.pre_signatures_in_creation.values() {
            match pre_signature {
                PreSignatureInCreation::Ecdsa(pre_sig) => {
                    assert_matches!(key_id.clone().into(), MasterPublicKeyId::Ecdsa(_));
                    let kappa_unmasked_config = pre_sig.kappa_unmasked_config.clone();
                    let kappa_transcript_id = kappa_unmasked_config.as_ref().transcript_id;
                    transcript_ids.insert(kappa_transcript_id);
                    transcript_ids.insert(pre_sig.lambda_config.as_ref().transcript_id);
                }
                PreSignatureInCreation::Schnorr(pre_sig) => {
                    assert_matches!(key_id.clone().into(), MasterPublicKeyId::Schnorr(_));
                    transcript_ids.insert(pre_sig.blinder_unmasked_config.as_ref().transcript_id);
                }
            }
        }
        let expected_transcript_ids = match key_id.inner() {
            MasterPublicKeyId::Ecdsa(_) => 2 * expected_pre_signatures_in_creation,
            MasterPublicKeyId::Schnorr(_) => expected_pre_signatures_in_creation,
            MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
        };
        assert_eq!(transcript_ids.len(), expected_transcript_ids);
        assert_eq!(
            idkg_payload.peek_next_transcript_id().id() as usize,
            expected_transcript_ids,
        );
    }

    #[test]
    fn test_update_schnorr_transcript_in_creation() {
        let mut rng = reproducible_rng();
        let env = CanisterThresholdSigTestEnvironment::new(4, &mut rng);
        let (_, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::AllNodesAsDealersAndReceivers,
            &mut rng,
        );
        let block_reader = TestIDkgBlockReader::new();
        let mut transcripts = BTreeMap::new();
        let height = Height::from(1);
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(0), height);

        for algorithm in SchnorrAlgorithm::iter() {
            let key_id = fake_schnorr_key_id(algorithm);
            let blinder_config = new_random_unmasked_config(
                &MasterPublicKeyId::Schnorr(key_id.clone())
                    .try_into()
                    .unwrap(),
                &receivers.get().iter().cloned().collect::<Vec<_>>(),
                env.newest_registry_version,
                &mut uid_generator,
            );
            let mut pre_sig = TranscriptInCreation::new(key_id, blinder_config);
            assert!(pre_sig.blinder_unmasked.is_none());

            let (finished, new_transcripts) = update_schnorr_transcript_in_creation(
                PreSigId(0),
                &mut pre_sig,
                &mut transcripts,
                height,
                &no_op_logger(),
            )
            .expect("Update should succeed");

            assert!(!finished);
            assert!(new_transcripts.is_empty());
            assert!(pre_sig.blinder_unmasked.is_none());

            let param = pre_sig.blinder_unmasked_config.as_ref();
            let blinder_unmasked_transcript = env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            );
            transcripts.insert(param.transcript_id, blinder_unmasked_transcript);

            let (finished, new_transcripts) = update_schnorr_transcript_in_creation(
                PreSigId(0),
                &mut pre_sig,
                &mut transcripts,
                height,
                &no_op_logger(),
            )
            .expect("Update should succeed");

            assert!(finished);
            assert_eq!(new_transcripts.len(), 1);

            let (finished, new_transcripts) = update_schnorr_transcript_in_creation(
                PreSigId(0),
                &mut pre_sig,
                &mut transcripts,
                height,
                &no_op_logger(),
            )
            .expect("Update should succeed");

            assert!(finished);
            assert!(new_transcripts.is_empty());
        }
    }

    #[test]
    fn test_ecdsa_update_pre_signatures_in_creation() {
        let mut rng = reproducible_rng();
        let subnet_id = subnet_test_id(1);
        let key_id = fake_ecdsa_idkg_master_public_key_id();
        let (mut payload, env, mut block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], Height::from(100));
        let mut transcripts = BTreeMap::new();

        // Start quadruple creation
        let [ref lambda_config_ref, ref kappa_unmasked_config_ref] =
            create_new_pre_signature_in_creation(
                &env.nodes.ids::<Vec<_>>(),
                env.newest_registry_version,
                &mut payload.uid_generator,
                key_id,
                &mut payload.pre_signatures_in_creation,
            )[..]
        else {
            panic!("Should return two configs");
        };

        // 0. No action case
        let cur_height = Height::new(1000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            transcripts.clone(),
            cur_height,
            &no_op_logger(),
        );
        assert!(result.unwrap().is_empty());

        // check if nothing has changed
        assert!(payload.available_pre_signatures.is_empty());
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert!(transcript_ids(&payload).is_empty());
        assert_eq!(config_ids(&payload), [0, 1]);

        // 1. When lambda_masked is ready, expect a new key_times_lambda config.
        let lambda_transcript = env.nodes.run_idkg_and_create_and_verify_transcript(
            &lambda_config_ref.translate(&block_reader).unwrap(),
            &mut rng,
        );
        transcripts.insert(lambda_config_ref.transcript_id, lambda_transcript);
        let cur_height = Height::new(2000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            transcripts.clone(),
            cur_height,
            &no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        for completed_transcript in result {
            block_reader.add_transcript(
                idkg::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        // check if new config is made
        assert!(payload.available_pre_signatures.is_empty());
        assert_eq!(payload.peek_next_transcript_id().id(), 3);
        let key_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 2, cur_height);
        assert_eq!(transcript_ids(&payload), [1]);
        assert_eq!(config_ids(&payload), [0, 2]);

        // 2. When kappa_unmasked and lambda_masked is ready, expect kappa_times_lambda
        // config.
        let kappa_unmasked_transcript = env.nodes.run_idkg_and_create_and_verify_transcript(
            &kappa_unmasked_config_ref.translate(&block_reader).unwrap(),
            &mut rng,
        );
        transcripts.insert(
            kappa_unmasked_config_ref.transcript_id,
            kappa_unmasked_transcript,
        );
        let cur_height = Height::new(3000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            transcripts.clone(),
            cur_height,
            &no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        for completed_transcript in result {
            block_reader.add_transcript(
                idkg::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        // check if new config is made
        assert!(payload.available_pre_signatures.is_empty());
        assert_eq!(payload.peek_next_transcript_id().id(), 4);
        let kappa_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 3, cur_height);
        assert_eq!(transcript_ids(&payload), [0, 1]);
        assert_eq!(config_ids(&payload), [2, 3]);

        // 3. When both kappa_times_lambda and key_times_lambda are ready, quadruple is
        // complete.
        let kappa_times_lambda_transcript = {
            let param = payload
                .iter_transcript_configs_in_creation()
                .find(|x| x.transcript_id == kappa_times_lambda_config_id)
                .unwrap()
                .clone();
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcripts.insert(kappa_times_lambda_config_id, kappa_times_lambda_transcript);
        let key_times_lambda_transcript = {
            let param = payload
                .iter_transcript_configs_in_creation()
                .find(|x| x.transcript_id == key_times_lambda_config_id)
                .unwrap()
                .clone();
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcripts.insert(key_times_lambda_config_id, key_times_lambda_transcript);
        let cur_height = Height::new(5000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            transcripts,
            cur_height,
            &no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 2);
        for completed_transcript in result {
            block_reader.add_transcript(
                idkg::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        // check if new config is made
        assert_eq!(payload.available_pre_signatures.len(), 1);
        assert_eq!(payload.pre_signatures_in_creation.len(), 0);
        assert_eq!(payload.peek_next_transcript_id().id(), 4);
        assert_eq!(transcript_ids(&payload), [0, 1, 2, 3]);
        assert!(config_ids(&payload).is_empty());
        let PreSignatureRef::Ecdsa(quadruple) =
            payload.available_pre_signatures.values().next().unwrap()
        else {
            panic!("Expected ECDSA pre-signature");
        };
        quadruple
            .translate(&block_reader)
            .expect("Translating should succeed");
    }

    #[test]
    fn test_schnorr_update_pre_signatures_in_creation_all_algorithms() {
        for algorithm in SchnorrAlgorithm::iter() {
            test_schnorr_update_pre_signatures_in_creation(algorithm)
        }
    }

    fn test_schnorr_update_pre_signatures_in_creation(algorithm: SchnorrAlgorithm) {
        let mut rng = reproducible_rng();
        let subnet_id = subnet_test_id(1);
        let key_id: IDkgMasterPublicKeyId = fake_schnorr_idkg_master_public_key_id(algorithm);
        let (mut payload, env, mut block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], Height::from(100));
        let mut transcripts = BTreeMap::new();

        // Start pre-signature creation
        let [ref blinder_config_ref] = create_new_pre_signature_in_creation(
            &env.nodes.ids::<Vec<_>>(),
            env.newest_registry_version,
            &mut payload.uid_generator,
            key_id.clone(),
            &mut payload.pre_signatures_in_creation,
        )[..] else {
            panic!("Should return one config");
        };

        // 0. No action case
        let cur_height = Height::new(1000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            transcripts.clone(),
            cur_height,
            &no_op_logger(),
        );
        assert!(result.unwrap().is_empty());

        // check if nothing has changed
        assert!(payload.available_pre_signatures.is_empty());
        assert_eq!(payload.peek_next_transcript_id().id(), 1);
        assert!(transcript_ids(&payload).is_empty());
        assert_eq!(config_ids(&payload), [0]);

        // 1. When blinder_unmasked is ready, pre-signature should be completed.
        let blinder_transcript = env.nodes.run_idkg_and_create_and_verify_transcript(
            &blinder_config_ref.translate(&block_reader).unwrap(),
            &mut rng,
        );
        transcripts.insert(blinder_config_ref.transcript_id, blinder_transcript);
        let cur_height = Height::new(2000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            transcripts.clone(),
            cur_height,
            &no_op_logger(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        for completed_transcript in result {
            block_reader.add_transcript(
                idkg::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        assert_eq!(payload.available_pre_signatures.len(), 1);
        assert_eq!(payload.pre_signatures_in_creation.len(), 0);
        assert_eq!(payload.peek_next_transcript_id().id(), 1);
        assert_eq!(transcript_ids(&payload), [0]);
        assert!(config_ids(&payload).is_empty());

        let PreSignatureRef::Schnorr(transcript) =
            payload.available_pre_signatures.values().next().unwrap()
        else {
            panic!("Expected Schnorr pre-signature");
        };
        assert_eq!(
            MasterPublicKeyId::Schnorr(transcript.key_id.clone()),
            key_id.clone().into()
        );
        let translated = transcript
            .translate(&block_reader)
            .expect("Translating should succeed");
        assert_eq!(
            translated.blinder_unmasked().algorithm_id,
            AlgorithmId::from(key_id.inner())
        );
    }

    fn get_current_unmasked_key_transcript(payload: &IDkgPayload) -> UnmaskedTranscript {
        let transcript = payload.single_key_transcript().current.clone();
        transcript.unwrap().unmasked_transcript()
    }

    #[test]
    fn test_matched_pre_signatures_are_not_purged_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_matched_pre_signatures_are_not_purged(key_id);
        }
    }

    fn test_matched_pre_signatures_are_not_purged(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let (mut payload, env, _) = set_up(
            &mut rng,
            subnet_test_id(1),
            vec![key_id.clone()],
            Height::from(100),
        );
        let key_transcript = get_current_unmasked_key_transcript(&payload);

        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::AllNodesAsDealersAndReceivers,
            &mut rng,
        );
        let transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::from(key_id.inner()),
            &mut rng,
        );
        let key_transcript2 =
            UnmaskedTranscript::try_from((Height::from(200), &transcript)).unwrap();

        // Create three pre-signatures, with the current, a different, no key transcript.
        let pre_sig_ids = vec![
            create_available_pre_signature_with_key_transcript(
                &mut payload,
                1,
                key_id.clone(),
                Some(key_transcript),
            ),
            create_available_pre_signature_with_key_transcript(
                &mut payload,
                2,
                key_id.clone(),
                Some(key_transcript2),
            ),
            create_available_pre_signature_with_key_transcript(
                &mut payload,
                3,
                key_id.clone(),
                None,
            ),
        ];

        // All three pre-signatures are matched with a context
        let contexts = BTreeMap::from_iter(pre_sig_ids.into_iter().map(|id| {
            fake_signature_request_context_with_pre_sig(
                request_id(id.id(), Height::from(300)),
                key_id.clone(),
                Some(id),
            )
        }));
        let contexts = into_idkg_contexts(&contexts);

        // None of them should be purged
        assert_eq!(payload.available_pre_signatures.len(), 3);
        purge_old_key_pre_signatures(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 3);
    }

    #[test]
    fn test_unmatched_pre_signatures_of_current_key_are_not_purged_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_unmatched_pre_signatures_of_current_key_are_not_purged(key_id);
        }
    }

    fn test_unmatched_pre_signatures_of_current_key_are_not_purged(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let height = Height::from(100);
        let (mut payload, _, _) = set_up(&mut rng, subnet_test_id(1), vec![key_id.clone()], height);
        let key_transcript = get_current_unmasked_key_transcript(&payload);

        // Create three pre-signatures of the current key transcript
        for i in 0..3 {
            create_available_pre_signature_with_key_transcript(
                &mut payload,
                i,
                key_id.clone(),
                Some(key_transcript),
            );
        }

        // None of them are matched to a context
        let contexts = BTreeMap::from_iter([fake_signature_request_context_with_pre_sig(
            request_id(1, height),
            key_id.clone(),
            None,
        )]);
        let contexts = into_idkg_contexts(&contexts);

        // None of them should be purged
        assert_eq!(payload.available_pre_signatures.len(), 3);
        purge_old_key_pre_signatures(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 3);
    }

    #[test]
    fn test_unmatched_pre_signatures_of_different_key_are_purged_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_unmatched_pre_signatures_of_different_key_are_purged(key_id);
        }
    }

    fn test_unmatched_pre_signatures_of_different_key_are_purged(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let (mut payload, env, _) = set_up(
            &mut rng,
            subnet_test_id(1),
            vec![key_id.clone()],
            Height::from(100),
        );

        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::AllNodesAsDealersAndReceivers,
            &mut rng,
        );
        let transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::from(key_id.inner()),
            &mut rng,
        );
        let other_key_transcript =
            UnmaskedTranscript::try_from((Height::from(200), &transcript)).unwrap();

        // Create two pre-signatures of the other key transcript
        let pre_sig_ids = (0..2)
            .map(|i| {
                create_available_pre_signature_with_key_transcript(
                    &mut payload,
                    i,
                    key_id.clone(),
                    Some(other_key_transcript),
                )
            })
            .collect::<Vec<_>>();

        // The first one is matched to a context
        let contexts = BTreeMap::from_iter([fake_signature_request_context_with_pre_sig(
            request_id(1, Height::from(300)),
            key_id.clone(),
            Some(pre_sig_ids[0]),
        )]);
        let contexts = into_idkg_contexts(&contexts);

        // The second one should be purged
        assert_eq!(payload.available_pre_signatures.len(), 2);
        purge_old_key_pre_signatures(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 1);

        assert_eq!(
            payload.available_pre_signatures.into_keys().next().unwrap(),
            pre_sig_ids[0]
        );
    }
}
