use super::EcdsaPayloadError;

use crate::ecdsa::pre_signer::EcdsaTranscriptBuilder;
use ic_logger::{debug, error, ReplicaLogger};
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId};
use ic_registry_subnet_features::EcdsaConfig;
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
use ic_types::{
    consensus::idkg::{
        self,
        common::{PreSignatureInCreation, PreSignatureRef},
        ecdsa::{PreSignatureQuadrupleRef, QuadrupleInCreation},
        EcdsaUIDGenerator, HasMasterPublicKeyId, QuadrupleId, TranscriptAttributes,
    },
    crypto::{canister_threshold_sig::idkg::IDkgTranscript, AlgorithmId},
    messages::CallbackId,
    Height, NodeId, RegistryVersion,
};

use std::collections::{BTreeMap, BTreeSet};

/// Update the quadruples in the payload by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from ecdsa pool;
/// - moving completed quadruples from "in creation" to "available".
/// Returns the newly created transcripts.
pub(super) fn update_quadruples_in_creation(
    payload: &mut idkg::EcdsaPayload,
    transcript_cache: &dyn EcdsaTranscriptBuilder,
    height: Height,
    log: &ReplicaLogger,
) -> Result<Vec<IDkgTranscript>, EcdsaPayloadError> {
    let mut newly_available = BTreeMap::new();
    let mut new_transcripts = Vec::new();
    for (quadruple_id, pre_signature) in payload.pre_signatures_in_creation.iter_mut() {
        let Some(key_transcript) = &payload
            .key_transcripts
            .get(&pre_signature.key_id())
            .and_then(|key_transcript| key_transcript.current.as_ref())
        else {
            error!(
                every_n_seconds => 30,
                log,
                "The ECDSA payload is missing a key transcript with key_id: {}",
                pre_signature.key_id());

            continue;
        };

        let PreSignatureInCreation::Ecdsa(quadruple) = pre_signature else {
            //TODO(CON-1261): Implement Schnorr pre-signature state machine
            continue;
        };

        let registry_version = key_transcript.registry_version();
        let receivers = key_transcript.receivers().clone();
        // Update quadruple with completed transcripts
        if quadruple.lambda_masked.is_none() {
            if let Some(transcript) = transcript_cache
                .get_completed_transcript(quadruple.lambda_config.as_ref().transcript_id)
            {
                debug!(
                    log,
                    "update_quadruples_in_creation: {:?} lamdba_masked transcript is made",
                    quadruple_id
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
                    "update_quadruples_in_creation: {:?} kappa_unmasked transcript {:?} is \
                            made from unmasked config",
                    quadruple_id,
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
                        "update_quadruples_in_creation: {:?} key_times_lambda transcript is made",
                        quadruple_id
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
                        "update_quadruples_in_creation: {:?} kappa_times_lambda transcript is made",
                        quadruple_id
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
                    payload.uid_generator.next_transcript_id(),
                    receivers.clone(),
                    registry_version,
                    (*key_transcript, key_transcript.unmasked_transcript()),
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
                    payload.uid_generator.next_transcript_id(),
                    receivers.clone(),
                    registry_version,
                    (kappa_config, *kappa_unmasked),
                    (lambda_config, *lambda_masked),
                ));
            }
        }
        if let (
            Some(_kappa_unmasked),
            Some(_lambda_masked),
            Some(_key_times_lambda),
            Some(_kappa_times_lambda),
        ) = (
            &quadruple.kappa_unmasked,
            &quadruple.lambda_masked,
            &quadruple.key_times_lambda,
            &quadruple.kappa_times_lambda,
        ) {
            newly_available.insert(quadruple_id.clone(), key_transcript.unmasked_transcript());
        }
    }

    for (quadruple_id, key_unmasked) in newly_available {
        // the following unwraps are safe
        match payload
            .pre_signatures_in_creation
            .remove(&quadruple_id)
            .unwrap()
        {
            PreSignatureInCreation::Ecdsa(quadruple) => {
                let lambda_masked = quadruple.lambda_masked.unwrap();
                let kappa_unmasked = quadruple.kappa_unmasked.unwrap();
                let key_times_lambda = quadruple.key_times_lambda.unwrap();
                let kappa_times_lambda = quadruple.kappa_times_lambda.unwrap();
                debug!(
                    log,
                    "update_quadruples_in_creation: making of quadruple {:?} is complete",
                    quadruple_id
                );
                payload.available_pre_signatures.insert(
                    quadruple_id,
                    PreSignatureRef::Ecdsa(PreSignatureQuadrupleRef::new(
                        quadruple.key_id.clone(),
                        kappa_unmasked,
                        lambda_masked,
                        kappa_times_lambda,
                        key_times_lambda,
                        key_unmasked,
                    )),
                );
            }
            PreSignatureInCreation::Schnorr(_) => {
                //TODO(CON-1261): Implement Schnorr pre-signature state machine
            }
        }
    }

    Ok(new_transcripts)
}

/// Purge all available but unmatched quadruples that are referencing a different key transcript
/// than the one currently used.
pub(super) fn purge_old_key_quadruples(
    ecdsa_payload: &mut idkg::EcdsaPayload,
    all_signing_requests: &BTreeMap<CallbackId, SignWithEcdsaContext>,
) {
    let matched_quadruples = all_signing_requests
        .values()
        .flat_map(|context| context.matched_quadruple.clone())
        .map(|(quadruple_id, _)| quadruple_id)
        .collect::<BTreeSet<_>>();

    ecdsa_payload
        .available_pre_signatures
        .retain(|id, quadruple| {
            matched_quadruples.contains(id)
                || ecdsa_payload
                    .key_transcripts
                    .get(&quadruple.key_id())
                    .and_then(|key_transcript| key_transcript.current.as_ref())
                    .is_some_and(|current_key_transcript| {
                        quadruple.key_unmasked().as_ref().transcript_id
                            == current_key_transcript.transcript_id()
                    })
        });
}

/// Creating new quadruples if necessary by updating quadruples_in_creation,
/// considering currently available quadruples, quadruples in creation, and
/// ecdsa configs.
pub(super) fn make_new_quadruples_if_needed(
    ecdsa_config: &EcdsaConfig,
    ecdsa_payload: &mut idkg::EcdsaPayload,
    matched_quadruples_per_key_id: &BTreeMap<MasterPublicKeyId, usize>,
) {
    for (key_id, key_transcript) in &ecdsa_payload.key_transcripts {
        let Some(key_transcript) = key_transcript.current.as_ref() else {
            continue;
        };

        let matched_quadruples = matched_quadruples_per_key_id
            .get(key_id)
            .copied()
            .unwrap_or_default();

        let unassigned_quadruples = ecdsa_payload
            .iter_pre_signature_ids(key_id)
            .count()
            .saturating_sub(matched_quadruples);

        let MasterPublicKeyId::Ecdsa(key_id) = key_id else {
            //TODO(CON-1254): Make pre-signature type creation configurable
            continue;
        };

        let node_ids: Vec<_> = key_transcript.receivers().iter().copied().collect();
        let new_quadruples = make_new_quadruples_if_needed_helper(
            &node_ids,
            key_transcript.registry_version(),
            ecdsa_config,
            key_id,
            &mut ecdsa_payload.uid_generator,
            unassigned_quadruples,
        );

        ecdsa_payload
            .pre_signatures_in_creation
            .extend(new_quadruples);
    }
}

fn make_new_quadruples_if_needed_helper(
    subnet_nodes: &[NodeId],
    registry_version: RegistryVersion,
    ecdsa_config: &EcdsaConfig,
    key_id: &EcdsaKeyId,
    uid_generator: &mut EcdsaUIDGenerator,
    unassigned_quadruples: usize,
) -> BTreeMap<QuadrupleId, PreSignatureInCreation> {
    let mut new_quadruples = BTreeMap::new();

    let quadruples_to_create = ecdsa_config.quadruples_to_create_in_advance as usize;
    if quadruples_to_create > unassigned_quadruples {
        for _ in 0..(quadruples_to_create - unassigned_quadruples) {
            let kappa_config =
                new_random_unmasked_config(subnet_nodes, registry_version, uid_generator);
            let lambda_config = new_random_config(subnet_nodes, registry_version, uid_generator);
            new_quadruples.insert(
                uid_generator.next_quadruple_id(),
                PreSignatureInCreation::Ecdsa(QuadrupleInCreation::new(
                    key_id.clone(),
                    kappa_config,
                    lambda_config,
                )),
            );
        }
    }

    new_quadruples
}

/// Create a new masked random transcript config and advance the
/// next_unused_transcript_id by one.
fn new_random_config(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    uid_generator: &mut idkg::EcdsaUIDGenerator,
) -> idkg::RandomTranscriptParams {
    let transcript_id = uid_generator.next_transcript_id();
    let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
    let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();

    idkg::RandomTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::ThresholdEcdsaSecp256k1,
    )
}

/// Create a new random unmasked transcript config and advance the
/// next_unused_transcript_id by one.
#[allow(dead_code)]
pub fn new_random_unmasked_config(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    uid_generator: &mut idkg::EcdsaUIDGenerator,
) -> idkg::RandomUnmaskedTranscriptParams {
    let transcript_id = uid_generator.next_transcript_id();
    let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
    let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();

    idkg::RandomUnmaskedTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::ThresholdEcdsaSecp256k1,
    )
}

#[cfg(test)]
pub(super) mod test_utils {
    use crate::ecdsa::test_utils::{create_sig_inputs, EcdsaPayloadTestHelper};

    use super::*;

    use std::collections::BTreeMap;

    use ic_management_canister_types::EcdsaKeyId;
    use ic_types::{
        consensus::idkg::{self, EcdsaPayload, QuadrupleId, UnmaskedTranscript},
        NodeId, RegistryVersion,
    };

    pub fn create_new_quadruple_in_creation(
        subnet_nodes: &[NodeId],
        registry_version: RegistryVersion,
        uid_generator: &mut idkg::EcdsaUIDGenerator,
        key_id: EcdsaKeyId,
        quadruples_in_creation: &mut BTreeMap<idkg::QuadrupleId, PreSignatureInCreation>,
    ) -> (
        idkg::RandomUnmaskedTranscriptParams,
        idkg::RandomTranscriptParams,
    ) {
        let kappa_config_ref =
            new_random_unmasked_config(subnet_nodes, registry_version, uid_generator);
        let lambda_config_ref = new_random_config(subnet_nodes, registry_version, uid_generator);
        quadruples_in_creation.insert(
            uid_generator.next_quadruple_id(),
            PreSignatureInCreation::Ecdsa(QuadrupleInCreation::new(
                key_id,
                kappa_config_ref.clone(),
                lambda_config_ref.clone(),
            )),
        );
        (kappa_config_ref, lambda_config_ref)
    }

    pub fn create_available_quadruple(
        ecdsa_payload: &mut EcdsaPayload,
        key_id: EcdsaKeyId,
        caller: u8,
    ) -> QuadrupleId {
        create_available_quadruple_with_key_transcript(
            ecdsa_payload,
            caller,
            key_id,
            /*key_transcript=*/ None,
        )
    }

    pub fn create_available_quadruple_with_key_transcript(
        ecdsa_payload: &mut EcdsaPayload,
        caller: u8,
        _key_id: EcdsaKeyId,
        key_transcript: Option<UnmaskedTranscript>,
    ) -> QuadrupleId {
        let sig_inputs = create_sig_inputs(caller);
        let quadruple_id = ecdsa_payload.uid_generator.next_quadruple_id();
        let mut quadruple_ref = sig_inputs.sig_inputs_ref.presig_quadruple_ref.clone();
        if let Some(transcript) = key_transcript {
            quadruple_ref.key_unmasked_ref = transcript;
        }
        ecdsa_payload
            .available_pre_signatures
            .insert(quadruple_id.clone(), PreSignatureRef::Ecdsa(quadruple_ref));

        for (t_ref, transcript) in sig_inputs.idkg_transcripts {
            ecdsa_payload
                .idkg_transcripts
                .insert(t_ref.transcript_id, transcript);
        }

        quadruple_id
    }

    /// Return a sorted list of IDs of all transcripts in creation
    pub fn config_ids(payload: &idkg::EcdsaPayload) -> Vec<u64> {
        let mut arr = payload
            .iter_transcript_configs_in_creation()
            .map(|x| x.transcript_id.id())
            .collect::<Vec<_>>();
        arr.sort_unstable();
        arr
    }

    /// Return a sorted list of IDs of all completed transcripts,
    /// excluding the key transcript
    pub fn transcript_ids(payload: &idkg::EcdsaPayload) -> Vec<u64> {
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

    use crate::ecdsa::test_utils::{
        fake_ecdsa_key_id, fake_sign_with_ecdsa_context_with_quadruple, set_up_ecdsa_payload,
        EcdsaPayloadTestHelper, TestEcdsaBlockReader, TestEcdsaTranscriptBuilder,
    };
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types::EcdsaKeyId;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        consensus::idkg::{common::PreSignatureRef, EcdsaPayload, UnmaskedTranscript},
        crypto::canister_threshold_sig::idkg::IDkgTranscriptId,
        SubnetId,
    };

    fn set_up(
        rng: &mut ReproducibleRng,
        subnet_id: SubnetId,
        ecdsa_key_ids: Vec<EcdsaKeyId>,
        height: Height,
    ) -> (
        EcdsaPayload,
        CanisterThresholdSigTestEnvironment,
        TestEcdsaBlockReader,
    ) {
        let (mut ecdsa_payload, env, block_reader) = set_up_ecdsa_payload(
            rng,
            subnet_id,
            /*nodes_count=*/ 4,
            ecdsa_key_ids,
            /*should_create_key_transcript=*/ true,
        );
        ecdsa_payload
            .uid_generator
            .update_height(height)
            .expect("Should successfully update the height");

        (ecdsa_payload, env, block_reader)
    }

    #[test]
    fn test_ecdsa_make_new_quadruples_if_needed() {
        let mut rng = reproducible_rng();
        let subnet_id = subnet_test_id(1);
        let height = Height::new(10);
        let key_id = fake_ecdsa_key_id();
        let (mut ecdsa_payload, _env, _block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], height);

        // 4 Quadruples should be created in advance (in creation + unmatched available = 4)
        let quadruples_to_create_in_advance = 4;
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance,
            ..EcdsaConfig::default()
        };

        // Add 3 available quadruples
        for i in 0..3 {
            create_available_quadruple(&mut ecdsa_payload, key_id.clone(), i);
        }

        // 2 available quadruples are already matched
        let quadruples_already_matched = 2;

        // We expect 3 quadruples in creation to be added
        let expected_quadruples_in_creation = quadruples_to_create_in_advance as usize
            - (ecdsa_payload.available_pre_signatures.len() - quadruples_already_matched);
        assert_eq!(expected_quadruples_in_creation, 3);

        make_new_quadruples_if_needed(
            &ecdsa_config,
            &mut ecdsa_payload,
            &BTreeMap::from([(
                MasterPublicKeyId::Ecdsa(key_id.clone()),
                quadruples_already_matched,
            )]),
        );

        assert_eq!(
            ecdsa_payload.pre_signatures_in_creation.len()
                + ecdsa_payload.available_pre_signatures.len()
                - quadruples_already_matched,
            quadruples_to_create_in_advance as usize
        );
        // Verify the generated transcript ids.
        let mut transcript_ids = BTreeSet::new();
        for pre_signature in ecdsa_payload.pre_signatures_in_creation.values() {
            let PreSignatureInCreation::Ecdsa(quadruple) = pre_signature else {
                panic!("Expected ECDSA pre-signature");
            };
            let kappa_unmasked_config = quadruple.kappa_unmasked_config.clone();
            let kappa_transcript_id = kappa_unmasked_config.as_ref().transcript_id;
            transcript_ids.insert(kappa_transcript_id);
            transcript_ids.insert(quadruple.lambda_config.as_ref().transcript_id);
        }
        assert_eq!(transcript_ids.len(), 2 * expected_quadruples_in_creation);
        assert_eq!(
            transcript_ids,
            BTreeSet::from([
                IDkgTranscriptId::new(subnet_id, /*id=*/ 0, height),
                IDkgTranscriptId::new(subnet_id, /*id=*/ 1, height),
                IDkgTranscriptId::new(subnet_id, /*id=*/ 2, height),
                IDkgTranscriptId::new(subnet_id, /*id=*/ 3, height),
                IDkgTranscriptId::new(subnet_id, /*id=*/ 4, height),
                IDkgTranscriptId::new(subnet_id, /*id=*/ 5, height),
            ])
        );
        assert_eq!(
            ecdsa_payload.peek_next_transcript_id().id() as usize,
            2 * expected_quadruples_in_creation,
        );
    }

    #[test]
    fn test_ecdsa_update_quadruples_in_creation() {
        let mut rng = reproducible_rng();
        let subnet_id = subnet_test_id(1);
        let key_id = fake_ecdsa_key_id();
        let (mut payload, env, mut block_reader) =
            set_up(&mut rng, subnet_id, vec![key_id.clone()], Height::from(100));
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        // Start quadruple creation
        let (kappa_unmasked_config_ref, lambda_config_ref) = create_new_quadruple_in_creation(
            &env.nodes.ids::<Vec<_>>(),
            env.newest_registry_version,
            &mut payload.uid_generator,
            key_id,
            &mut payload.pre_signatures_in_creation,
        );

        // 0. No action case
        let cur_height = Height::new(1000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_quadruples_in_creation(
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
        let lambda_transcript = {
            let param = lambda_config_ref.as_ref();
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder
            .add_transcript(lambda_config_ref.as_ref().transcript_id, lambda_transcript);
        let cur_height = Height::new(2000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_quadruples_in_creation(
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
        let kappa_unmasked_transcript = {
            let param = kappa_unmasked_config_ref.as_ref();
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder.add_transcript(
            kappa_unmasked_config_ref.as_ref().transcript_id,
            kappa_unmasked_transcript,
        );
        let cur_height = Height::new(3000);
        let update_res = payload.uid_generator.update_height(cur_height);
        assert!(update_res.is_ok());
        let result = update_quadruples_in_creation(
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
        let result = update_quadruples_in_creation(
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

    fn get_current_unmasked_key_transcript(payload: &EcdsaPayload) -> UnmaskedTranscript {
        let transcript = payload.single_key_transcript().current.clone();
        transcript.unwrap().unmasked_transcript()
    }

    #[test]
    fn test_matched_quadruples_are_not_purged() {
        let mut rng = reproducible_rng();
        let key_id = fake_ecdsa_key_id();
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
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let key_transcript2 =
            UnmaskedTranscript::try_from((Height::from(200), &transcript)).unwrap();

        // Create three quadruples, with the current, a different, no key transcript.
        let quadruple_ids = vec![
            create_available_quadruple_with_key_transcript(
                &mut payload,
                1,
                key_id.clone(),
                Some(key_transcript),
            ),
            create_available_quadruple_with_key_transcript(
                &mut payload,
                2,
                key_id.clone(),
                Some(key_transcript2),
            ),
            create_available_quadruple_with_key_transcript(&mut payload, 3, key_id.clone(), None),
        ];

        // All three quadruples are matched with a context
        let contexts = BTreeMap::from_iter(quadruple_ids.into_iter().map(|id| {
            fake_sign_with_ecdsa_context_with_quadruple(id.id() as u8, key_id.clone(), Some(id))
        }));

        // None of them should be purged
        assert_eq!(payload.available_pre_signatures.len(), 3);
        purge_old_key_quadruples(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 3);
    }

    #[test]
    fn test_unmatched_quadruples_of_current_key_are_not_purged() {
        let mut rng = reproducible_rng();
        let key_id = fake_ecdsa_key_id();
        let (mut payload, _, _) = set_up(
            &mut rng,
            subnet_test_id(1),
            vec![key_id.clone()],
            Height::from(100),
        );
        let key_transcript = get_current_unmasked_key_transcript(&payload);

        // Create three quadruples of the current key transcript
        for i in 0..3 {
            create_available_quadruple_with_key_transcript(
                &mut payload,
                i,
                key_id.clone(),
                Some(key_transcript),
            );
        }

        // None of them are matched to a context
        let contexts = BTreeMap::from_iter([fake_sign_with_ecdsa_context_with_quadruple(
            1,
            key_id.clone(),
            None,
        )]);

        // None of them should be purged
        assert_eq!(payload.available_pre_signatures.len(), 3);
        purge_old_key_quadruples(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 3);
    }

    #[test]
    fn test_unmatched_quadruples_of_different_key_are_purged() {
        let mut rng = reproducible_rng();
        let key_id = fake_ecdsa_key_id();
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
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let other_key_transcript =
            UnmaskedTranscript::try_from((Height::from(200), &transcript)).unwrap();

        // Create two quadruples of the other key transcript
        let quadruple_ids = (0..2)
            .map(|i| {
                create_available_quadruple_with_key_transcript(
                    &mut payload,
                    i,
                    key_id.clone(),
                    Some(other_key_transcript),
                )
            })
            .collect::<Vec<_>>();

        // The first one is matched to a context
        let contexts = BTreeMap::from_iter([fake_sign_with_ecdsa_context_with_quadruple(
            1,
            key_id.clone(),
            Some(quadruple_ids[0].clone()),
        )]);

        // The second one should be purged
        assert_eq!(payload.available_pre_signatures.len(), 2);
        purge_old_key_quadruples(&mut payload, &contexts);
        assert_eq!(payload.available_pre_signatures.len(), 1);

        assert_eq!(
            payload.available_pre_signatures.into_keys().next().unwrap(),
            quadruple_ids[0]
        );
    }
}
