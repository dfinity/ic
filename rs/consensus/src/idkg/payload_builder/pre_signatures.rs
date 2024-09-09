use super::IDkgPayloadError;

use crate::idkg::{pre_signer::IDkgTranscriptBuilder, utils::algorithm_for_key_id};
use ic_logger::{debug, error, ReplicaLogger};
use ic_management_canister_types::MasterPublicKeyId;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithThresholdContext;
use ic_types::{
    consensus::idkg::{
        self,
        common::{PreSignatureInCreation, PreSignatureRef},
        ecdsa::{PreSignatureQuadrupleRef, QuadrupleInCreation},
        schnorr::{PreSignatureTranscriptRef, TranscriptInCreation},
        HasMasterPublicKeyId, IDkgUIDGenerator, PreSigId, TranscriptAttributes,
        UnmaskedTranscriptWithAttributes,
    },
    crypto::canister_threshold_sig::idkg::IDkgTranscript,
    messages::CallbackId,
    Height, NodeId, RegistryVersion,
};

use std::collections::{BTreeMap, BTreeSet};

/// Update the pre-signatures in the payload by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from idkg pool;
/// - moving completed pre-signatures from "in creation" to "available".
///
/// Returns the newly created transcripts.
pub(super) fn update_pre_signatures_in_creation(
    payload: &mut idkg::IDkgPayload,
    transcript_cache: &dyn IDkgTranscriptBuilder,
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
                transcript_cache,
                &mut payload.uid_generator,
                height,
                log,
            )?,
            PreSignatureInCreation::Schnorr(transcript) => update_schnorr_transcript_in_creation(
                *pre_signature_id,
                transcript,
                transcript_cache,
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
    transcript_cache: &dyn IDkgTranscriptBuilder,
    uid_generator: &mut IDkgUIDGenerator,
    height: Height,
    log: &ReplicaLogger,
) -> Result<(bool, Vec<IDkgTranscript>), IDkgPayloadError> {
    let mut new_transcripts = Vec::new();
    let registry_version = key_transcript.registry_version();
    let receivers = key_transcript.receivers().clone();
    // Update quadruple with completed transcripts
    if quadruple.lambda_masked.is_none() {
        if let Some(transcript) = transcript_cache
            .get_completed_transcript(quadruple.lambda_config.as_ref().transcript_id)
        {
            debug!(
                log,
                "update_ecdsa_quadruple_in_creation: {:?} lamdba_masked transcript is made",
                pre_signature_id
            );
            quadruple.lambda_masked =
                Some(idkg::MaskedTranscript::try_from((height, &transcript))?);
            new_transcripts.push(transcript);
        }
    }
    if quadruple.kappa_unmasked.is_none() {
        if let Some(transcript) = transcript_cache
            .get_completed_transcript(quadruple.kappa_unmasked_config.as_ref().transcript_id)
        {
            debug!(
                log,
                "update_ecdsa_quadruple_in_creation: {:?} kappa_unmasked transcript {:?} is \
                        made from unmasked config",
                pre_signature_id,
                transcript.get_type()
            );
            quadruple.kappa_unmasked =
                Some(idkg::UnmaskedTranscript::try_from((height, &transcript))?);
            new_transcripts.push(transcript);
        }
    }
    if quadruple.key_times_lambda.is_none() {
        if let Some(config) = &quadruple.key_times_lambda_config {
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                debug!(
                    log,
                    "update_ecdsa_quadruple_in_creation: {:?} key_times_lambda transcript is made",
                    pre_signature_id
                );
                quadruple.key_times_lambda =
                    Some(idkg::MaskedTranscript::try_from((height, &transcript))?);
                new_transcripts.push(transcript);
            }
        }
    }
    if quadruple.kappa_times_lambda.is_none() {
        if let Some(config) = &quadruple.kappa_times_lambda_config {
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
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
        }
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
    transcript_cache: &dyn IDkgTranscriptBuilder,
    height: Height,
    log: &ReplicaLogger,
) -> Result<(bool, Vec<IDkgTranscript>), IDkgPayloadError> {
    let mut new_transcripts = Vec::new();
    // Update pre_signature with completed transcripts
    if pre_signature.blinder_unmasked.is_none() {
        if let Some(transcript) = transcript_cache
            .get_completed_transcript(pre_signature.blinder_unmasked_config.as_ref().transcript_id)
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
    }
    Ok((pre_signature.blinder_unmasked.is_some(), new_transcripts))
}

/// Purge all available but unmatched pre-signatures that are referencing a different key transcript
/// than the one currently used.
pub(super) fn purge_old_key_pre_signatures(
    idkg_payload: &mut idkg::IDkgPayload,
    all_signing_requests: &BTreeMap<CallbackId, SignWithThresholdContext>,
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
    matched_pre_signatures_per_key_id: &BTreeMap<MasterPublicKeyId, usize>,
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
    key_id: &MasterPublicKeyId,
    uid_generator: &mut IDkgUIDGenerator,
    unassigned_pre_signatures: usize,
) -> BTreeMap<PreSigId, PreSignatureInCreation> {
    let mut new_pre_signatures = BTreeMap::new();

    let Some(pre_signatures_to_create) = chain_key_config
        .key_configs
        .iter()
        .find(|key_config| &key_config.key_id == key_id)
        .map(|key_config| key_config.pre_signatures_to_create_in_advance as usize)
    else {
        return new_pre_signatures;
    };

    if pre_signatures_to_create <= unassigned_pre_signatures {
        return new_pre_signatures;
    }

    for _ in 0..(pre_signatures_to_create - unassigned_pre_signatures) {
        let pre_signature = match key_id {
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => {
                let kappa_config = new_random_unmasked_config(
                    key_id,
                    subnet_nodes,
                    registry_version,
                    uid_generator,
                );
                let lambda_config =
                    new_random_config(key_id, subnet_nodes, registry_version, uid_generator);
                PreSignatureInCreation::Ecdsa(QuadrupleInCreation::new(
                    ecdsa_key_id.clone(),
                    kappa_config,
                    lambda_config,
                ))
            }
            MasterPublicKeyId::Schnorr(schnorr_key_id) => {
                let blinder_config = new_random_unmasked_config(
                    key_id,
                    subnet_nodes,
                    registry_version,
                    uid_generator,
                );
                PreSignatureInCreation::Schnorr(TranscriptInCreation::new(
                    schnorr_key_id.clone(),
                    blinder_config,
                ))
            }
        };
        new_pre_signatures.insert(uid_generator.next_pre_signature_id(), pre_signature);
    }

    new_pre_signatures
}

/// Create a new masked random transcript config and advance the
/// next_unused_transcript_id by one.
fn new_random_config(
    key_id: &MasterPublicKeyId,
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
        algorithm_for_key_id(key_id),
    )
}

/// Create a new random unmasked transcript config and advance the
/// next_unused_transcript_id by one.
pub fn new_random_unmasked_config(
    key_id: &MasterPublicKeyId,
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
        algorithm_for_key_id(key_id),
    )
}

#[cfg(test)]
pub(super) mod test_utils {
    use crate::idkg::test_utils::IDkgPayloadTestHelper;

    use super::*;

    use std::collections::BTreeMap;

    use ic_types::{
        consensus::idkg::{self, IDkgTranscriptParamsRef},
        NodeId, RegistryVersion,
    };

    pub fn create_new_pre_signature_in_creation(
        subnet_nodes: &[NodeId],
        registry_version: RegistryVersion,
        uid_generator: &mut idkg::IDkgUIDGenerator,
        key_id: MasterPublicKeyId,
        pre_signatures_in_creation: &mut BTreeMap<idkg::PreSigId, PreSignatureInCreation>,
    ) -> Vec<IDkgTranscriptParamsRef> {
        let pre_signature = match key_id.clone() {
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
    use super::test_utils::*;
    use super::*;

    use crate::idkg::test_utils::{
        create_available_pre_signature, create_available_pre_signature_with_key_transcript,
        fake_ecdsa_master_public_key_id, fake_master_public_key_ids_for_all_algorithms,
        fake_schnorr_key_id, fake_schnorr_master_public_key_id,
        fake_signature_request_context_with_pre_sig, set_up_idkg_payload, IDkgPayloadTestHelper,
        TestIDkgBlockReader, TestIDkgTranscriptBuilder,
    };
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types::SchnorrAlgorithm;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::idkg::{common::PreSignatureRef, IDkgPayload, UnmaskedTranscript},
        crypto::canister_threshold_sig::idkg::IDkgTranscriptId,
        SubnetId,
    };
    use idkg::IDkgTranscriptOperationRef;
    use strum::IntoEnumIterator;

    fn set_up(
        rng: &mut ReproducibleRng,
        subnet_id: SubnetId,
        key_ids: Vec<MasterPublicKeyId>,
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
    fn test_schnorr_make_new_pre_signatures_if_needed_helper() {
        let nodes = &[node_test_id(0)];
        let registry_version = RegistryVersion::from(1);
        let subnet_id = subnet_test_id(1);
        let height = Height::new(10);
        let mut uid_generator = IDkgUIDGenerator::new(subnet_id, height);
        let pre_signatures_to_create_in_advance = 4;

        let mut create_pre_signatures = |key_id: &MasterPublicKeyId, unassigned| {
            let chain_key_config = ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: key_id.clone(),
                    pre_signatures_to_create_in_advance,
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

        let key_id_bib340 = fake_schnorr_master_public_key_id(SchnorrAlgorithm::Bip340Secp256k1);
        let key_id_eddsa = fake_schnorr_master_public_key_id(SchnorrAlgorithm::Ed25519);

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
                    key_id,
                    &MasterPublicKeyId::Schnorr(transcript.key_id.clone())
                );
                let config = transcript.blinder_unmasked_config.as_ref();
                assert_eq!(config.algorithm_id, algorithm_for_key_id(key_id));
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
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_make_new_pre_signatures_if_needed(key_id);
        }
    }

    fn test_make_new_pre_signatures_if_needed(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let subnet_id = subnet_test_id(1);
        let height = Height::new(10);
        let (mut idkg_payload, _env, _block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], height);

        // 4 pre-signatures should be created in advance (in creation + unmatched available = 4)
        let pre_signatures_to_create_in_advance = 4;
        let chain_key_config = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: key_id.clone(),
                pre_signatures_to_create_in_advance,
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
                    assert_matches!(key_id, MasterPublicKeyId::Ecdsa(_));
                    let kappa_unmasked_config = pre_sig.kappa_unmasked_config.clone();
                    let kappa_transcript_id = kappa_unmasked_config.as_ref().transcript_id;
                    transcript_ids.insert(kappa_transcript_id);
                    transcript_ids.insert(pre_sig.lambda_config.as_ref().transcript_id);
                }
                PreSignatureInCreation::Schnorr(pre_sig) => {
                    assert_matches!(key_id, MasterPublicKeyId::Schnorr(_));
                    transcript_ids.insert(pre_sig.blinder_unmasked_config.as_ref().transcript_id);
                }
            }
        }
        let expected_transcript_ids = match key_id {
            MasterPublicKeyId::Ecdsa(_) => 2 * expected_pre_signatures_in_creation,
            MasterPublicKeyId::Schnorr(_) => expected_pre_signatures_in_creation,
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
        let transcript_builder = TestIDkgTranscriptBuilder::new();
        let height = Height::from(1);
        let mut uid_generator = IDkgUIDGenerator::new(subnet_test_id(0), height);

        for algorithm in SchnorrAlgorithm::iter() {
            let key_id = fake_schnorr_key_id(algorithm);
            let blinder_config = new_random_unmasked_config(
                &MasterPublicKeyId::Schnorr(key_id.clone()),
                &receivers.get().iter().cloned().collect::<Vec<_>>(),
                env.newest_registry_version,
                &mut uid_generator,
            );
            let mut pre_sig = TranscriptInCreation::new(key_id, blinder_config);
            assert!(pre_sig.blinder_unmasked.is_none());

            let (finished, new_transcripts) = update_schnorr_transcript_in_creation(
                PreSigId(0),
                &mut pre_sig,
                &transcript_builder,
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
            transcript_builder.add_transcript(param.transcript_id, blinder_unmasked_transcript);

            let (finished, new_transcripts) = update_schnorr_transcript_in_creation(
                PreSigId(0),
                &mut pre_sig,
                &transcript_builder,
                height,
                &no_op_logger(),
            )
            .expect("Update should succeed");

            assert!(finished);
            assert_eq!(new_transcripts.len(), 1);

            let (finished, new_transcripts) = update_schnorr_transcript_in_creation(
                PreSigId(0),
                &mut pre_sig,
                &transcript_builder,
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
        let key_id = fake_ecdsa_master_public_key_id();
        let (mut payload, env, mut block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], Height::from(100));
        let transcript_builder = TestIDkgTranscriptBuilder::new();

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
            &transcript_builder,
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
        transcript_builder.add_transcript(lambda_config_ref.transcript_id, lambda_transcript);
        let cur_height = Height::new(2000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            &transcript_builder,
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
        transcript_builder.add_transcript(
            kappa_unmasked_config_ref.transcript_id,
            kappa_unmasked_transcript,
        );
        let cur_height = Height::new(3000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            &transcript_builder,
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
        transcript_builder
            .add_transcript(kappa_times_lambda_config_id, kappa_times_lambda_transcript);
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
        transcript_builder.add_transcript(key_times_lambda_config_id, key_times_lambda_transcript);
        let cur_height = Height::new(5000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            &transcript_builder,
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
        let key_id = fake_schnorr_master_public_key_id(algorithm);
        let (mut payload, env, mut block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], Height::from(100));
        let transcript_builder = TestIDkgTranscriptBuilder::new();

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
            &transcript_builder,
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
        transcript_builder.add_transcript(blinder_config_ref.transcript_id, blinder_transcript);
        let cur_height = Height::new(2000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_pre_signatures_in_creation(
            &mut payload,
            &transcript_builder,
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
            key_id
        );
        let translated = transcript
            .translate(&block_reader)
            .expect("Translating should succeed");
        assert_eq!(
            translated.blinder_unmasked().algorithm_id,
            algorithm_for_key_id(&key_id)
        );
    }

    fn get_current_unmasked_key_transcript(payload: &IDkgPayload) -> UnmaskedTranscript {
        let transcript = payload.single_key_transcript().current.clone();
        transcript.unwrap().unmasked_transcript()
    }

    #[test]
    fn test_matched_pre_signatures_are_not_purged_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_matched_pre_signatures_are_not_purged(key_id);
        }
    }

    fn test_matched_pre_signatures_are_not_purged(key_id: MasterPublicKeyId) {
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
            algorithm_for_key_id(&key_id),
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
            fake_signature_request_context_with_pre_sig(id.id() as u8, key_id.clone(), Some(id))
        }));

        // None of them should be purged
        assert_eq!(payload.available_pre_signatures.len(), 3);
        purge_old_key_pre_signatures(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 3);
    }

    #[test]
    fn test_unmatched_pre_signatures_of_current_key_are_not_purged_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_unmatched_pre_signatures_of_current_key_are_not_purged(key_id);
        }
    }

    fn test_unmatched_pre_signatures_of_current_key_are_not_purged(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let (mut payload, _, _) = set_up(
            &mut rng,
            subnet_test_id(1),
            vec![key_id.clone()],
            Height::from(100),
        );
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
            1,
            key_id.clone(),
            None,
        )]);

        // None of them should be purged
        assert_eq!(payload.available_pre_signatures.len(), 3);
        purge_old_key_pre_signatures(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 3);
    }

    #[test]
    fn test_unmatched_pre_signatures_of_different_key_are_purged_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_unmatched_pre_signatures_of_different_key_are_purged(key_id);
        }
    }

    fn test_unmatched_pre_signatures_of_different_key_are_purged(key_id: MasterPublicKeyId) {
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
            algorithm_for_key_id(&key_id),
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
            1,
            key_id.clone(),
            Some(pre_sig_ids[0]),
        )]);

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
