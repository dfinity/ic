use std::collections::BTreeSet;

use ic_logger::{info, ReplicaLogger};
use ic_types::{
    consensus::ecdsa::{self, EcdsaBlockReader, TranscriptAttributes},
    crypto::{canister_threshold_sig::idkg::IDkgTranscript, AlgorithmId},
    Height, NodeId, RegistryVersion,
};

use crate::ecdsa::pre_signer::EcdsaTranscriptBuilder;

use super::EcdsaPayloadError;

pub(super) fn get_created_key_transcript(
    key_transcript: &ecdsa::EcdsaKeyTranscript,
    block_reader: &dyn EcdsaBlockReader,
) -> Result<Option<ecdsa::UnmaskedTranscriptWithAttributes>, EcdsaPayloadError> {
    if let ecdsa::KeyTranscriptCreation::Created(unmasked) = &key_transcript.next_in_creation {
        let transcript = block_reader.transcript(unmasked.as_ref())?;
        Ok(Some(ecdsa::UnmaskedTranscriptWithAttributes::new(
            transcript.to_attributes(),
            *unmasked,
        )))
    } else {
        Ok(None)
    }
}

/// Update configuration and data about the next ECDSA key transcript.
/// Returns the newly created transcript, if any.
///
/// Note that when creating next key transcript we must use the registry version
/// that is going to be put into the next DKG summary.
pub(super) fn update_next_key_transcript(
    receivers: &[NodeId],
    registry_version: RegistryVersion,
    ecdsa_payload: &mut ecdsa::EcdsaPayload,
    transcript_cache: &dyn EcdsaTranscriptBuilder,
    height: Height,
    log: &ReplicaLogger,
) -> Result<Option<IDkgTranscript>, EcdsaPayloadError> {
    let mut new_transcript = None;
    match (
        &ecdsa_payload.key_transcript.current,
        &ecdsa_payload.key_transcript.next_in_creation,
    ) {
        (Some(transcript), ecdsa::KeyTranscriptCreation::Begin) => {
            // We have an existing key transcript, need to reshare it to create next
            // Create a new reshare config when there is none
            let dealers = transcript.receivers();
            let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
            info!(
                log,
                "Reshare ECDSA key transcript from dealers {:?} to receivers {:?}, height = {}",
                dealers,
                receivers,
                height,
            );
            ecdsa_payload.key_transcript.next_in_creation =
                ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(
                    ecdsa::ReshareOfUnmaskedParams::new(
                        ecdsa_payload.uid_generator.next_transcript_id(),
                        receivers_set,
                        registry_version,
                        transcript,
                        transcript.unmasked_transcript(),
                    ),
                );
        }

        (Some(_), ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(config)) => {
            // check if the next key transcript has been made
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                info!(
                    log,
                    "ECDSA key transcript created from ReshareOfUnmasked {:?} \
                    registry_version {} height = {}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                    height,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, &transcript))?;
                ecdsa_payload.key_transcript.next_in_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript);
            }
        }

        (None, ecdsa::KeyTranscriptCreation::Begin) => {
            // The first ECDSA key transcript has to be created, starting from a random
            // config. Here receivers and dealers are the same set.
            let transcript_id = ecdsa_payload.uid_generator.next_transcript_id();
            let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
            let dealers_set = receivers_set.clone();
            ecdsa_payload.key_transcript.next_in_creation =
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(
                    ecdsa::RandomTranscriptParams::new(
                        transcript_id,
                        dealers_set,
                        receivers_set,
                        registry_version,
                        AlgorithmId::ThresholdEcdsaSecp256k1,
                    ),
                );
        }

        (None, ecdsa::KeyTranscriptCreation::RandomTranscriptParams(config)) => {
            // Check if the random transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                let receivers_set = receivers.iter().copied().collect::<BTreeSet<_>>();
                let transcript_ref = ecdsa::MaskedTranscript::try_from((height, &transcript))?;
                ecdsa_payload.key_transcript.next_in_creation =
                    ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(
                        ecdsa::ReshareOfMaskedParams::new(
                            ecdsa_payload.uid_generator.next_transcript_id(),
                            receivers_set,
                            registry_version,
                            &transcript,
                            transcript_ref,
                        ),
                    );
                new_transcript = Some(transcript);
            }
        }

        (None, ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(config)) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                info!(
                    log,
                    "ECDSA key transcript created from ReshareOfMasked {:?} \
                    registry_version {} height = {}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                    height,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, &transcript))?;
                ecdsa_payload.key_transcript.next_in_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript);
            }
        }

        (None, ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, config))) => {
            // Check if the unmasked transcript has been created
            if let Some(transcript) =
                transcript_cache.get_completed_transcript(config.as_ref().transcript_id)
            {
                // next_unused_transcript_id is not updated, since the transcript_id specified
                // by the reshared param will be used.
                info!(
                    log,
                    "ECDSA Key transcript created from XnetReshareOfUnmasked {:?}, \
                    registry_version {}, height = {}",
                    config.as_ref().transcript_id,
                    transcript.registry_version,
                    height,
                );
                let transcript_ref = ecdsa::UnmaskedTranscript::try_from((height, &transcript))?;
                ecdsa_payload.key_transcript.next_in_creation =
                    ecdsa::KeyTranscriptCreation::Created(transcript_ref);
                new_transcript = Some(transcript);
            }
        }

        (_, ecdsa::KeyTranscriptCreation::Created(_)) => {
            // valid case that we can ignore
        }

        (None, ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(_)) => {
            unreachable!("Unexpected ReshareOfUnmaskedParams for key transcript creation");
        }

        _ => {
            unreachable!("Unexpected next_key_transcript configuration reached!");
        }
    }

    Ok(new_transcript)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_crypto_test_utils_canister_threshold_sigs::{
        dummy_values::dummy_initial_idkg_dealing_for_tests, generate_key_transcript, node::Nodes,
        CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types::EcdsaKeyId;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        crypto::{canister_threshold_sig::idkg::IDkgTranscript, AlgorithmId},
        Height,
    };

    use crate::ecdsa::test_utils::{
        create_reshare_unmasked_transcript_param, fake_ecdsa_key_id, set_up_ecdsa_payload,
        EcdsaPayloadTestHelper, TestEcdsaBlockReader, TestEcdsaTranscriptBuilder,
    };

    use super::*;

    #[test]
    fn get_created_key_transcript_returns_some_test() {
        let mut block_reader = TestEcdsaBlockReader::new();
        let mut rng = reproducible_rng();
        let key_transcript = create_key_transcript(&mut rng);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::from(0), &key_transcript)).unwrap();
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript.clone());

        let current_key_transcript = ecdsa::EcdsaKeyTranscript {
            current: None,
            next_in_creation: ecdsa::KeyTranscriptCreation::Created(key_transcript_ref),
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
        };

        let created_key_transcript =
            get_created_key_transcript(&current_key_transcript, &block_reader)
                .expect("Should not fail");

        assert_eq!(
            created_key_transcript,
            Some(ecdsa::UnmaskedTranscriptWithAttributes::new(
                key_transcript.to_attributes(),
                key_transcript_ref
            ))
        );
    }

    #[test]
    fn get_created_key_transcript_returns_none_test() {
        let block_reader = TestEcdsaBlockReader::new();

        let key_transcript = ecdsa::EcdsaKeyTranscript {
            current: None,
            next_in_creation: ecdsa::KeyTranscriptCreation::Begin,
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
        };

        let created_key_transcript =
            get_created_key_transcript(&key_transcript, &block_reader).expect("Should not fail");

        assert!(created_key_transcript.is_none());
    }

    fn create_key_transcript(rng: &mut ReproducibleRng) -> IDkgTranscript {
        let env = CanisterThresholdSigTestEnvironment::new(4, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
        generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            rng,
        )
    }

    #[test]
    fn test_ecdsa_update_next_key_transcript() {
        let mut rng = reproducible_rng();
        let (mut payload, env, mut block_reader) = set_up_ecdsa_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            vec![fake_ecdsa_key_id()],
            /*should_create_key_transcript=*/ false,
        );
        let registry_version = env.newest_registry_version;
        let subnet_nodes: Vec<_> = env.nodes.ids();
        let config_ids = |payload: &ecdsa::EcdsaPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id.id())
                .collect::<Vec<_>>();
            arr.sort_unstable();
            arr
        };
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        // 1. Nothing initially, masked transcript creation should start
        let cur_height = Height::new(10);
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.peek_next_transcript_id().id(), 1);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [0]);

        // 2. Masked random transcript is created, should start reshare of the masked
        // transcript.
        let cur_height = Height::new(20);
        let masked_transcript = {
            let param = match &payload.single_key_transcript().next_in_creation {
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(param) => param.clone(),
                other => panic!("Unexpected state: {:?}", other,),
            };
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder
            .add_transcript(masked_transcript.transcript_id, masked_transcript.clone());
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, masked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [1]);

        // 3. Unmasked transcript is created, should complete the boot strap sequence
        let cur_height = Height::new(30);
        let unmasked_transcript = {
            let param = match &payload.single_key_transcript().next_in_creation {
                ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(param) => param.clone(),
                other => panic!("Unexpected state: {:?}", other,),
            };
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder.add_transcript(
            unmasked_transcript.transcript_id,
            unmasked_transcript.clone(),
        );
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        let current_key_transcript = ecdsa::UnmaskedTranscriptWithAttributes::new(
            completed_transcript.to_attributes(),
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap(),
        );
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        ecdsa::TranscriptRef::new(cur_height, unmasked_transcript.transcript_id);
        match &payload.single_key_transcript().next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            other => panic!("Unexpected state: {:?}", other,),
        }

        // 4. Reshare the current key transcript to get the next one
        let cur_height = Height::new(40);
        payload.key_transcript.current = Some(current_key_transcript.clone());
        payload.key_transcript.next_in_creation = ecdsa::KeyTranscriptCreation::Begin;
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.peek_next_transcript_id().id(), 3);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [2]);

        // 5. Reshare completes to get the next unmasked transcript
        let cur_height = Height::new(50);
        let unmasked_transcript = {
            let param = match &payload.single_key_transcript().next_in_creation {
                ecdsa::KeyTranscriptCreation::ReshareOfUnmaskedParams(param) => param.clone(),
                other => panic!("Unexpected state: {:?}", other,),
            };
            env.nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder.add_transcript(
            unmasked_transcript.transcript_id,
            unmasked_transcript.clone(),
        );
        let result = update_next_key_transcript(
            &subnet_nodes,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        assert_eq!(payload.peek_next_transcript_id().id(), 3);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        match &payload.single_key_transcript().next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            other => panic!("Unexpected state: {:?}", other,),
        }
    }

    #[test]
    fn test_ecdsa_update_next_key_transcript_xnet_target_subnet() {
        let mut rng = reproducible_rng();
        let (mut payload, env, mut block_reader) = set_up_ecdsa_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 8,
            vec![fake_ecdsa_key_id()],
            /*should_create_key_transcript=*/ false,
        );

        let registry_version = env.newest_registry_version;
        let (subnet_nodes, target_subnet_nodes) = env.nodes.partition(|(index, _node)| *index < 4);
        assert_eq!(subnet_nodes.len(), 4);
        assert_eq!(subnet_nodes.len(), target_subnet_nodes.len());
        let (subnet_nodes_ids, target_subnet_nodes_ids): (Vec<_>, Vec<_>) =
            (subnet_nodes.ids(), target_subnet_nodes.ids());
        let config_ids = |payload: &ecdsa::EcdsaPayload| {
            let mut arr = payload
                .iter_transcript_configs_in_creation()
                .map(|x| x.transcript_id.id())
                .collect::<Vec<_>>();
            arr.sort_unstable();
            arr
        };
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        // 1. Nothing initially, masked transcript creation should start
        let cur_height = Height::new(10);
        let result = update_next_key_transcript(
            &subnet_nodes_ids,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.peek_next_transcript_id().id(), 1);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [0]);

        // 2. Masked random transcript is created, should start reshare of the masked
        // transcript.
        let cur_height = Height::new(20);
        let masked_transcript = {
            let param = match &payload.single_key_transcript().next_in_creation {
                ecdsa::KeyTranscriptCreation::RandomTranscriptParams(param) => param.clone(),
                other => panic!("Unexpected state: {:?}", other,),
            };
            subnet_nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder
            .add_transcript(masked_transcript.transcript_id, masked_transcript.clone());
        let result = update_next_key_transcript(
            &subnet_nodes_ids,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, masked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [1]);

        // 3. Unmasked transcript is created, should complete the boot strap sequence
        let cur_height = Height::new(30);
        let unmasked_transcript = {
            let param = match &payload.single_key_transcript().next_in_creation {
                ecdsa::KeyTranscriptCreation::ReshareOfMaskedParams(param) => param.clone(),
                other => panic!("Unexpected state: {:?}", other,),
            };
            subnet_nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder.add_transcript(
            unmasked_transcript.transcript_id,
            unmasked_transcript.clone(),
        );
        let result = update_next_key_transcript(
            &subnet_nodes_ids,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, completed_transcript.transcript_id),
            completed_transcript,
        );
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        ecdsa::TranscriptRef::new(cur_height, unmasked_transcript.transcript_id);
        match &payload.single_key_transcript().next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            other => panic!("Unexpected state: {:?}", other,),
        }

        // 4. Reshare the created transcript to a different set of nodes
        let reshare_params = create_reshare_unmasked_transcript_param(
            &unmasked_transcript,
            &target_subnet_nodes_ids,
            registry_version,
        );
        let (params, transcript) =
            ecdsa::unpack_reshare_of_unmasked_params(cur_height, &reshare_params).unwrap();
        block_reader.add_transcript(
            ecdsa::TranscriptRef::new(cur_height, transcript.transcript_id),
            transcript,
        );
        payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((
                Box::new(dummy_initial_idkg_dealing_for_tests(
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &mut rng,
                )),
                params,
            ));
        let result = update_next_key_transcript(
            &subnet_nodes_ids,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        matches!(result, Ok(None));
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 1);
        assert_eq!(config_ids(&payload), [reshare_params.transcript_id().id()]);

        // 5. Complete the reshared transcript creation. This should cause the key to
        // move to created state.
        let cur_height = Height::new(50);
        let unmasked_transcript = {
            let param = match &payload.single_key_transcript().next_in_creation {
                ecdsa::KeyTranscriptCreation::XnetReshareOfUnmaskedParams((_, param)) => {
                    param.clone()
                }
                other => panic!("Unexpected state: {:?}", other,),
            };

            let all_nodes: Nodes = subnet_nodes
                .into_iter()
                .chain(target_subnet_nodes)
                .collect();
            all_nodes.run_idkg_and_create_and_verify_transcript(
                &param.as_ref().translate(&block_reader).unwrap(),
                &mut rng,
            )
        };
        transcript_builder.add_transcript(
            unmasked_transcript.transcript_id,
            unmasked_transcript.clone(),
        );
        let result = update_next_key_transcript(
            &target_subnet_nodes_ids,
            registry_version,
            &mut payload,
            &transcript_builder,
            cur_height,
            &no_op_logger(),
        );
        let completed_transcript = result.unwrap().unwrap();
        assert_eq!(completed_transcript, unmasked_transcript);
        assert_eq!(payload.peek_next_transcript_id().id(), 2);
        assert_eq!(payload.iter_transcript_configs_in_creation().count(), 0);
        assert!(config_ids(&payload).is_empty());
        let current_key_transcript =
            ecdsa::UnmaskedTranscript::try_from((cur_height, &unmasked_transcript)).unwrap();
        match &payload.single_key_transcript().next_in_creation {
            ecdsa::KeyTranscriptCreation::Created(unmasked) => {
                assert_eq!(*unmasked.as_ref(), *current_key_transcript.as_ref());
            }
            other => panic!("Unexpected state: {:?}", other,),
        }
    }
}
