use super::EcdsaPayloadError;

use crate::ecdsa::pre_signer::EcdsaTranscriptBuilder;
use ic_logger::{debug, error, ReplicaLogger};
use ic_registry_subnet_features::EcdsaConfig;
use ic_types::{
    consensus::ecdsa::{self, TranscriptAttributes},
    crypto::{canister_threshold_sig::idkg::IDkgTranscript, AlgorithmId},
    Height, NodeId, RegistryVersion,
};

use std::collections::BTreeSet;

/// Update the quadruples in the payload by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from ecdsa pool;
/// - moving completed quadruples from "in creation" to "available".
/// Returns the newly created transcripts.
pub(super) fn update_quadruples_in_creation(
    payload: &mut ecdsa::EcdsaPayload,
    transcript_cache: &dyn EcdsaTranscriptBuilder,
    height: Height,
    log: &ReplicaLogger,
) -> Result<Vec<IDkgTranscript>, EcdsaPayloadError> {
    let mut newly_available = Vec::new();
    let mut new_transcripts = Vec::new();
    if let Some(key_transcript) = &payload.key_transcript.current {
        let registry_version = key_transcript.registry_version();
        let receivers = key_transcript.receivers().clone();
        for (key, quadruple) in payload.quadruples_in_creation.iter_mut() {
            // Update quadruple with completed transcripts
            if quadruple.kappa_masked.is_none() {
                if let Some(transcript) = transcript_cache
                    .get_completed_transcript(quadruple.kappa_config.as_ref().transcript_id)
                {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_masked transcript is made", key
                    );
                    quadruple.kappa_masked =
                        Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                    new_transcripts.push(transcript);
                }
            }
            if quadruple.lambda_masked.is_none() {
                if let Some(transcript) = transcript_cache
                    .get_completed_transcript(quadruple.lambda_config.as_ref().transcript_id)
                {
                    debug!(
                        log,
                        "update_quadruples_in_creation: {:?} lamdba_masked transcript is made", key
                    );
                    quadruple.lambda_masked =
                        Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                    new_transcripts.push(transcript);
                }
            }
            if quadruple.kappa_unmasked.is_none() {
                if let Some(config) = &quadruple.unmask_kappa_config {
                    if let Some(transcript) =
                        transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
                    {
                        debug!(
                        log,
                        "update_quadruples_in_creation: {:?} kappa_unmasked transcript {:?} is made",
                        key,
                        transcript.get_type()
                    );
                        quadruple.kappa_unmasked =
                            Some(ecdsa::UnmaskedTranscript::try_from((height, &transcript))?);
                        new_transcripts.push(transcript);
                    }
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
                        key
                    );
                        quadruple.key_times_lambda =
                            Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
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
                        key
                    );
                        quadruple.kappa_times_lambda =
                            Some(ecdsa::MaskedTranscript::try_from((height, &transcript))?);
                        new_transcripts.push(transcript);
                    }
                }
            }
            // Check what to do in the next step
            if let (Some(kappa_masked), None) =
                (&quadruple.kappa_masked, &quadruple.unmask_kappa_config)
            {
                let kappa_config = quadruple.kappa_config.as_ref();
                quadruple.unmask_kappa_config = Some(ecdsa::ReshareOfMaskedParams::new(
                    payload.uid_generator.next_transcript_id(),
                    receivers.clone(),
                    registry_version,
                    kappa_config,
                    *kappa_masked,
                ));
            }
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
                    quadruple.key_times_lambda_config =
                        Some(ecdsa::UnmaskedTimesMaskedParams::new(
                            payload.uid_generator.next_transcript_id(),
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
                let kappa_config = quadruple.kappa_config.as_ref();
                let lambda_config = quadruple.lambda_config.as_ref();
                if kappa_config.receivers() != lambda_config.receivers() {
                    error!(
                        log,
                        "kappa_config has a different receiver set than lambda_config: {:?} {:?}",
                        kappa_config,
                        lambda_config
                    );
                } else {
                    quadruple.kappa_times_lambda_config =
                        Some(ecdsa::UnmaskedTimesMaskedParams::new(
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
                newly_available.push(*key);
            }
        }
        for key in newly_available.into_iter() {
            // the following unwraps are safe
            let quadruple = payload.quadruples_in_creation.remove(&key).unwrap();
            let lambda_masked = quadruple.lambda_masked.unwrap();
            let kappa_unmasked = quadruple.kappa_unmasked.unwrap();
            let key_times_lambda = quadruple.key_times_lambda.unwrap();
            let kappa_times_lambda = quadruple.kappa_times_lambda.unwrap();
            debug!(
                log,
                "update_quadruples_in_creation: making of quadruple {:?} is complete", key
            );
            payload.available_quadruples.insert(
                key,
                ecdsa::PreSignatureQuadrupleRef::new(
                    kappa_unmasked,
                    lambda_masked,
                    kappa_times_lambda,
                    key_times_lambda,
                ),
            );
        }
    }

    Ok(new_transcripts)
}

/// Creating new quadruples if necessary by updating quadruples_in_creation,
/// considering currently available quadruples, quadruples in creation, and
/// ecdsa configs.
pub(super) fn make_new_quadruples_if_needed(
    ecdsa_config: &EcdsaConfig,
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
) {
    if let Some(key_transcript) = &ecdsa_payload.key_transcript.current {
        let node_ids: Vec<_> = key_transcript.receivers().iter().copied().collect();
        make_new_quadruples_if_needed_helper(
            &node_ids,
            key_transcript.registry_version(),
            ecdsa_config,
            ecdsa_payload,
        )
    }
}

fn make_new_quadruples_if_needed_helper(
    subnet_nodes: &[NodeId],
    registry_version: RegistryVersion,
    ecdsa_config: &EcdsaConfig,
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
) {
    let unassigned_quadruples = ecdsa_payload.unassigned_quadruple_ids().count();
    let quadruples_to_create = ecdsa_config.quadruples_to_create_in_advance as usize;
    if quadruples_to_create > unassigned_quadruples {
        let quadruples_in_creation = &mut ecdsa_payload.quadruples_in_creation;
        let uid_generator = &mut ecdsa_payload.uid_generator;
        for _ in 0..(quadruples_to_create - unassigned_quadruples) {
            let kappa_config = new_random_config(subnet_nodes, registry_version, uid_generator);
            let lambda_config = new_random_config(subnet_nodes, registry_version, uid_generator);
            quadruples_in_creation.insert(
                uid_generator.next_quadruple_id(),
                ecdsa::QuadrupleInCreation::new(kappa_config, lambda_config),
            );
        }
    }
}

/// Create a new random transcript config and advance the
/// next_unused_transcript_id by one.
fn new_random_config(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    uid_generator: &mut ecdsa::EcdsaUIDGenerator,
) -> ecdsa::RandomTranscriptParams {
    let transcript_id = uid_generator.next_transcript_id();
    let dealers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();
    let receivers = subnet_nodes.iter().copied().collect::<BTreeSet<_>>();

    ecdsa::RandomTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::ThresholdEcdsaSecp256k1,
    )
}

#[cfg(test)]
pub(super) mod test_utils {
    use crate::ecdsa::test_utils::create_sig_inputs;

    use super::*;

    use std::collections::BTreeMap;

    use ic_types::{
        consensus::ecdsa::{self, EcdsaPayload, QuadrupleId},
        NodeId, RegistryVersion,
    };

    pub fn create_new_quadruple_in_creation(
        subnet_nodes: &[NodeId],
        registry_version: RegistryVersion,
        uid_generator: &mut ecdsa::EcdsaUIDGenerator,
        quadruples_in_creation: &mut BTreeMap<ecdsa::QuadrupleId, ecdsa::QuadrupleInCreation>,
    ) -> (ecdsa::RandomTranscriptParams, ecdsa::RandomTranscriptParams) {
        let kappa_config_ref = new_random_config(subnet_nodes, registry_version, uid_generator);
        let lambda_config_ref = new_random_config(subnet_nodes, registry_version, uid_generator);
        quadruples_in_creation.insert(
            uid_generator.next_quadruple_id(),
            ecdsa::QuadrupleInCreation::new(kappa_config_ref.clone(), lambda_config_ref.clone()),
        );
        (kappa_config_ref, lambda_config_ref)
    }

    pub fn create_available_quadruple(ecdsa_payload: &mut EcdsaPayload, caller: u8) -> QuadrupleId {
        let sig_inputs = create_sig_inputs(caller);
        let quadruple_id = ecdsa_payload.uid_generator.next_quadruple_id();
        let quadruple_ref = &sig_inputs.sig_inputs_ref.presig_quadruple_ref;
        ecdsa_payload
            .available_quadruples
            .insert(quadruple_id, quadruple_ref.clone());

        quadruple_id
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::test_utils::*;
    use super::*;

    use crate::ecdsa::test_utils::{
        set_up_ecdsa_payload, EcdsaPayloadTestHelper, TestEcdsaBlockReader,
        TestEcdsaTranscriptBuilder,
    };
    use ic_crypto_test_utils_canister_threshold_sigs::CanisterThresholdSigTestEnvironment;
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::types::ids::subnet_test_id;
    use ic_types::{
        consensus::ecdsa::EcdsaPayload, crypto::canister_threshold_sig::idkg::IDkgTranscriptId,
        SubnetId,
    };

    fn set_up(
        rng: &mut ReproducibleRng,
        subnet_id: SubnetId,
        height: Height,
    ) -> (
        EcdsaPayload,
        CanisterThresholdSigTestEnvironment,
        TestEcdsaBlockReader,
    ) {
        let (mut ecdsa_payload, env, block_reader) = set_up_ecdsa_payload(
            rng, subnet_id, /*nodes_count=*/ 4, /*should_create_key_transcript=*/ true,
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
        let quadruples_to_create_in_advance = 3;
        let subnet_id = subnet_test_id(1);
        let height = Height::new(10);
        let (mut ecdsa_payload, env, _block_reader) = set_up(&mut rng, subnet_id, height);
        let ecdsa_config = EcdsaConfig {
            quadruples_to_create_in_advance,
            ..EcdsaConfig::default()
        };

        make_new_quadruples_if_needed_helper(
            &env.nodes.ids::<Vec<_>>(),
            env.newest_registry_version,
            &ecdsa_config,
            &mut ecdsa_payload,
        );

        assert_eq!(
            ecdsa_payload.quadruples_in_creation.len(),
            quadruples_to_create_in_advance as usize
        );
        // Verify the generated transcript ids.
        let mut transcript_ids = BTreeSet::new();
        for quadruple in &ecdsa_payload.quadruples_in_creation {
            transcript_ids.insert(quadruple.1.kappa_config.as_ref().transcript_id);
            transcript_ids.insert(quadruple.1.lambda_config.as_ref().transcript_id);
        }
        assert_eq!(
            transcript_ids.len(),
            2 * quadruples_to_create_in_advance as usize
        );
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
            ecdsa_payload.peek_next_transcript_id().id() as u32,
            2 * quadruples_to_create_in_advance,
        );
    }

    #[test]
    fn test_ecdsa_update_quadruples_in_creation() {
        let mut rng = reproducible_rng();
        let subnet_id = subnet_test_id(1);
        let (mut payload, env, mut block_reader) = set_up(&mut rng, subnet_id, Height::from(100));
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        // Start quadruple creation
        let (kappa_config_ref, lambda_config_ref) = create_new_quadruple_in_creation(
            &env.nodes.ids::<Vec<_>>(),
            env.newest_registry_version,
            &mut payload.uid_generator,
            &mut payload.quadruples_in_creation,
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
        let config_ids = |payload: &ecdsa::EcdsaPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id.id())
                .collect::<Vec<_>>();
            arr.sort_unstable();
            arr
        };

        // check if nothing has changed
        assert!(payload.available_quadruples.is_empty());
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 2);
        assert_eq!(config_ids(&payload), [0, 1]);

        // 1. When kappa_masked is ready, expect a new kappa_unmasked config.
        let kappa_transcript = {
            let param = kappa_config_ref.as_ref();
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder
            .add_transcript(kappa_config_ref.as_ref().transcript_id, kappa_transcript);
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
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        // check if new config is made
        assert!(payload.available_quadruples.is_empty());
        let kappa_unmasked_config_id = IDkgTranscriptId::new(subnet_id, 2, cur_height);
        assert_eq!(payload.peek_next_transcript_id().id(), 3);
        assert_eq!(config_ids(&payload), [1, 2]);

        // 2. When lambda_masked is ready, expect a new key_times_lambda config.
        let lambda_transcript = {
            let param = lambda_config_ref.as_ref(); //env.params_for_random_sharing(algorithm);
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder
            .add_transcript(lambda_config_ref.as_ref().transcript_id, lambda_transcript);
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
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        // check if new config is made
        assert!(payload.available_quadruples.is_empty());
        assert_eq!(payload.peek_next_transcript_id().id(), 4);
        let key_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 3, cur_height);
        assert_eq!(config_ids(&payload), [2, 3]);

        // 3. When kappa_unmasked and lambda_masked is ready, expect kappa_times_lambda
        // config.
        let kappa_unmasked_transcript = {
            let param = payload
                .iter_transcript_configs_in_creation()
                .find(|x| x.transcript_id == kappa_unmasked_config_id)
                .unwrap()
                .clone();
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder.add_transcript(kappa_unmasked_config_id, kappa_unmasked_transcript);
        let cur_height = Height::new(4000);
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
                ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
                completed_transcript,
            );
        }
        // check if new config is made
        assert!(payload.available_quadruples.is_empty());
        assert_eq!(payload.peek_next_transcript_id().id(), 5);
        let kappa_times_lambda_config_id = IDkgTranscriptId::new(subnet_id, 4, cur_height);
        assert_eq!(config_ids(&payload), [3, 4]);

        // 4. When both kappa_times_lambda and key_times_lambda are ready, quadruple is
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
        // check if new config is made
        assert_eq!(payload.available_quadruples.len(), 1);
        assert_eq!(payload.peek_next_transcript_id().id(), 5);
        assert!(config_ids(&payload).is_empty());
    }
}
