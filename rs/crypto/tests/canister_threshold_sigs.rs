use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_crypto::get_tecdsa_master_public_key;
use ic_crypto_internal_threshold_sig_ecdsa::{EccScalar, IDkgDealingInternal, MEGaCiphertext};
use ic_crypto_tecdsa::derive_tecdsa_public_key;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils::dkg::dummy_idkg_transcript_id_for_tests;
use ic_crypto_test_utils_canister_threshold_sigs::node::Node;
use ic_crypto_test_utils_canister_threshold_sigs::node::Nodes;
use ic_crypto_test_utils_canister_threshold_sigs::IDkgParticipants;
use ic_crypto_test_utils_canister_threshold_sigs::{
    build_params_from_previous, generate_key_transcript, generate_presig_quadruple, node_id,
    random_crypto_component_not_in_receivers, random_dealer_id, random_dealer_id_excluding,
    random_node_id_excluding, random_receiver_for_inputs, random_receiver_id,
    random_receiver_id_excluding, run_tecdsa_protocol, sig_share_from_each_receiver,
    swap_two_dealings_in_transcript, CanisterThresholdSigTestEnvironment, IntoBuilder,
};
use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
use ic_interfaces::crypto::{IDkgProtocol, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgOpenTranscriptError,
    IDkgVerifyComplaintError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError,
    ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgComplaint, IDkgDealers, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptOperation, IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, ThresholdEcdsaSigInputs};
use ic_types::crypto::{AlgorithmId, BasicSigOf, CryptoError};
use ic_types::{NodeId, NodeIndex, Randomness};
use maplit::hashset;
use rand::distributions::uniform::SampleRange;
use rand::prelude::*;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;

mod create_dealing {
    use super::*;
    use ic_interfaces::crypto::BasicSigVerifier;

    #[test]
    fn should_create_signed_dealing_with_correct_public_key() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);

        let dealing = dealer
            .create_dealing(&params)
            .expect("could not create dealing");
        assert_eq!(dealing.dealer_id(), dealer.id());

        let verification_result = dealer.verify_basic_sig(
            &dealing.signature.signature,
            &dealing.content,
            dealer.id(),
            params.registry_version(),
        );
        assert_eq!(verification_result, Ok(()));
    }

    #[test]
    fn should_fail_create_dealing_if_registry_missing_mega_pubkey() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);

        let new_node_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let crypto_not_in_registry = Node::new(new_node_id, Arc::clone(&env.registry), &mut rng);
        env.nodes.insert(crypto_not_in_registry);
        let (dealers, receivers_with_new_node_id) = {
            let (random_dealers, random_receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
            let mut receivers_ids = random_receivers.get().clone();
            receivers_ids.insert(new_node_id);
            let receivers_with_new_node_id =
                IDkgReceivers::new(receivers_ids).expect("valid receivers");
            (random_dealers, receivers_with_new_node_id)
        };

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers_with_new_node_id,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);

        let result = dealer.create_dealing(&params);
        assert_matches!(result, Err(IDkgCreateDealingError::PublicKeyNotFound { node_id, .. }) if node_id==new_node_id);
    }

    #[test]
    fn should_fail_create_dealing_if_node_isnt_a_dealer() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let bad_dealer_id = random_node_id_excluding(params.dealers().get(), &mut rng);
        let bad_dealer = Node::new(bad_dealer_id, Arc::clone(&env.registry), &mut rng);

        let result = bad_dealer.create_dealing(&params);
        let err = result.unwrap_err();
        assert_matches!(err, IDkgCreateDealingError::NotADealer { node_id } if node_id==bad_dealer_id);
    }

    #[test]
    fn should_fail_create_reshare_dealing_if_transcript_isnt_loaded() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);

        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);
        let initial_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let initial_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&initial_params, &mut rng);

        let reshare_params = build_params_from_previous(
            initial_params,
            IDkgTranscriptOperation::ReshareOfMasked(initial_transcript.clone()),
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&reshare_params, &mut rng);

        // We don't call `load_transcript`...

        let result = dealer.create_dealing(&reshare_params);
        let err = result.unwrap_err();
        assert_matches!(err, IDkgCreateDealingError::SecretSharesNotFound { .. });

        // Now, load the transcript and make sure it succeeds
        dealer.load_transcript_or_panic(&initial_transcript);
        let result = dealer.create_dealing(&reshare_params);
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_fail_to_create_dealing_when_kappa_unmasked_not_retained() {
        let mut rng = reproducible_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let masked_key_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let masked_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&masked_key_params, &mut rng);

        let unmasked_key_params = build_params_from_previous(
            masked_key_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
            &mut rng,
        );

        let unmasked_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, &mut rng);
        let quadruple = generate_presig_quadruple(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &unmasked_key_transcript,
            &mut rng,
        );

        let inputs = {
            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };

            let hashed_message = rng.gen::<[u8; 32]>();
            let seed = Randomness::from(rng.gen::<[u8; 32]>());

            ThresholdEcdsaSigInputs::new(
                &derivation_path,
                &hashed_message,
                seed,
                quadruple,
                unmasked_key_transcript.clone(),
            )
            .expect("failed to create signature inputs")
        };

        let reshare_params = build_params_from_previous(
            unmasked_key_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(
                inputs.presig_quadruple().kappa_unmasked().clone(),
            ),
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&reshare_params, &mut rng);
        dealer.load_input_transcripts(&inputs);

        // make sure creating dealings succeeds with all the transcripts
        let result = dealer.create_dealing(&reshare_params);
        assert_matches!(result, Ok(_));

        // Do not include kappa unmasked in retained transcripts
        let active_transcripts = hashset!(
            masked_key_transcript,
            unmasked_key_transcript,
            inputs.presig_quadruple().lambda_masked().clone(),
            inputs.presig_quadruple().kappa_times_lambda().clone(),
            inputs.presig_quadruple().key_times_lambda().clone(),
        );
        assert_eq!(
            dealer.retain_active_transcripts(&active_transcripts),
            Ok(())
        );

        // Create dealing should now fail
        let result = dealer.create_dealing(&reshare_params);
        assert_matches!(
            result,
            Err(IDkgCreateDealingError::SecretSharesNotFound { .. })
        );
    }

    #[test]
    fn should_fail_to_create_dealing_when_reshared_unmasked_key_transcript_not_retained() {
        let mut rng = reproducible_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let masked_key_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let masked_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&masked_key_params, &mut rng);

        let unmasked_key_params = build_params_from_previous(
            masked_key_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
            &mut rng,
        );

        let unmasked_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, &mut rng);

        let reshare_params = build_params_from_previous(
            unmasked_key_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_key_transcript.clone()),
            &mut rng,
        );

        let dealer = env.nodes.random_dealer(&reshare_params, &mut rng);
        dealer.load_transcript_or_panic(&masked_key_transcript);
        dealer.load_transcript_or_panic(&unmasked_key_transcript);

        // make sure creating dealings succeeds with all the transcripts
        let result = dealer.create_dealing(&reshare_params);
        assert_matches!(result, Ok(_));

        // Do not include shared unmasked key transcript in retained transcripts
        let active_transcripts = hashset!(masked_key_transcript,);
        assert_eq!(
            dealer.retain_active_transcripts(&active_transcripts),
            Ok(())
        );

        // Create dealing should now fail
        let result = dealer.create_dealing(&reshare_params);
        assert_matches!(
            result,
            Err(IDkgCreateDealingError::SecretSharesNotFound { .. })
        );
    }
}

mod create_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::CorruptBytesCollection;

    #[test]
    fn should_create_transcript() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
        let batch_signed_dealings = env
            .nodes
            .support_dealings_from_all_receivers(signed_dealings, &params);

        let creator = env.nodes.random_receiver(params.receivers(), &mut rng);
        let result = creator.create_transcript(&params, &batch_signed_dealings);

        assert_matches!(result, Ok(transcript) if transcript.transcript_id == params.transcript_id())
    }

    #[test]
    fn should_fail_create_transcript_without_enough_dealings() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..30);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);

        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let dealings: BTreeMap<NodeId, SignedIDkgDealing> = env
            .nodes
            .dealers(&params)
            .take(params.collection_threshold().get() as usize - 1) // NOTE: Not enough!
            .map(|dealer| {
                let dealing = env.nodes.create_and_verify_signed_dealing(&params, dealer);
                (dealer.id(), dealing)
            })
            .collect();

        let batch_signed_dealings = env
            .nodes
            .support_dealings_from_all_receivers(dealings.clone(), &params);
        let creator = env.nodes.random_receiver(params.receivers(), &mut rng);

        let result = creator.create_transcript(&params, &batch_signed_dealings);

        let err = result.unwrap_err();
        assert_matches!(
            err,
            IDkgCreateTranscriptError::UnsatisfiedCollectionThreshold { threshold, dealing_count }
            if (threshold as usize)==(params.collection_threshold().get() as usize) && dealing_count==dealings.len()
        );
    }

    #[test]
    fn should_fail_create_transcript_with_disallowed_dealer() {
        const MIN_NUM_NODES: usize = 2;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
        let batch_signed_dealings = env
            .nodes
            .support_dealings_from_all_receivers(signed_dealings, &params);

        let params_with_removed_dealer = {
            let mut dealers = params.dealers().get().clone();
            let removed_dealer_id = random_dealer_id(&params, &mut rng);
            assert!(dealers.remove(&removed_dealer_id));
            IDkgTranscriptParams::new(
                params.transcript_id(),
                dealers,
                params.receivers().get().clone(),
                params.registry_version(),
                params.algorithm_id(),
                params.operation_type().clone(),
            )
            .expect("valid IDkgTranscriptParams")
        };
        let creator = env.nodes.random_receiver(params.receivers(), &mut rng);
        let result = creator.create_transcript(&params_with_removed_dealer, &batch_signed_dealings);

        assert_matches!(
            result,
            Err(IDkgCreateTranscriptError::DealerNotAllowed { .. })
        );
    }

    #[test]
    fn should_fail_create_transcript_with_signature_by_disallowed_receiver() {
        const MIN_NUM_NODES: usize = 2; // Need enough to be able to remove one
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            &mut rng,
        );

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
        let batch_signed_dealings = env
            .nodes
            .support_dealings_from_all_receivers(signed_dealings, &params);

        // Remove one of the original receivers from the params
        // so that we have a valid sig on the dealing, but `create_transcript` will not
        // consider them eligible to sign
        let (removed_receiver_id, modified_params) = {
            let mut modified_receivers = params.receivers().get().clone();
            let removed_node_id = random_receiver_id(&params, &mut rng);
            assert!(modified_receivers.remove(&removed_node_id));
            let modified_params = IDkgTranscriptParams::new(
                params.transcript_id(),
                params.dealers().get().clone(),
                modified_receivers,
                params.registry_version(),
                params.algorithm_id(),
                params.operation_type().clone(),
            )
            .expect("failed to create new params");
            (removed_node_id, modified_params)
        };

        let creator = env
            .nodes
            .random_receiver(modified_params.receivers(), &mut rng);
        let result = creator.create_transcript(&modified_params, &batch_signed_dealings);
        let err = result.unwrap_err();
        assert_matches!(
            err,
            IDkgCreateTranscriptError::SignerNotAllowed {
                node_id
            }
            if node_id == removed_receiver_id
        );
    }

    #[test]
    fn should_fail_create_transcript_without_enough_signatures() {
        const MIN_NUM_NODES: usize = 4; // Needs to be enough for >=1 signature
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            &mut rng,
        );

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
        let insufficient_supporters: Nodes = env
            .nodes
            .into_receivers(params.receivers())
            .take(params.verification_threshold().get() as usize - 1) // Not enough!
            .collect();

        let insufficient_batch_signed_dealings =
            insufficient_supporters.support_dealings_from_all_receivers(signed_dealings, &params);

        let creator = insufficient_supporters.random_receiver(params.receivers(), &mut rng);
        let result = creator.create_transcript(&params, &insufficient_batch_signed_dealings);
        let err = result.unwrap_err();
        assert_matches!(
            err,
            IDkgCreateTranscriptError::UnsatisfiedVerificationThreshold { threshold, signature_count, .. }
            if threshold == params.verification_threshold().get() && signature_count == (threshold as usize - 1)
        );
    }

    #[test]
    fn should_fail_create_transcript_with_all_signatures_bad_in_all_dealings() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let creator = env.nodes.random_receiver(params.receivers(), &mut rng);
        let batch_signed_dealings = env.nodes.create_batch_signed_dealings(&params);
        let corrupted_dealings = batch_signed_dealings
            .into_iter()
            .map(|mut dealing| {
                dealing.flip_a_bit_in_all();
                dealing
            })
            .collect();

        let result = creator.create_transcript(&params, &corrupted_dealings);

        assert_matches!(
            result,
            Err(IDkgCreateTranscriptError::InvalidSignatureBatch {
                crypto_error: CryptoError::SignatureVerification { .. }
            })
        );
    }

    #[test]
    fn should_fail_create_transcript_with_all_signatures_bad_in_one_dealing() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let creator = env.nodes.random_receiver(params.receivers(), &mut rng);
        let mut batch_signed_dealings = env.nodes.create_batch_signed_dealings(&params);
        batch_signed_dealings.insert_or_update({
            let mut corrupted_dealing = batch_signed_dealings
                .iter()
                .next()
                .expect("at least one dealing to corrupt")
                .clone();
            corrupted_dealing.flip_a_bit_in_all();
            corrupted_dealing
        });

        let result = creator.create_transcript(&params, &batch_signed_dealings);

        assert_matches!(
            result,
            Err(IDkgCreateTranscriptError::InvalidSignatureBatch {
                crypto_error: CryptoError::SignatureVerification { .. }
            })
        );
    }

    #[test]
    fn should_fail_create_transcript_with_one_bad_signature_in_one_dealing() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let creator = env.nodes.random_receiver(params.receivers(), &mut rng);
        let mut batch_signed_dealings = env.nodes.create_batch_signed_dealings(&params);
        batch_signed_dealings.insert_or_update({
            let mut corrupted_dealing = batch_signed_dealings
                .iter()
                .next()
                .expect("at least one dealing to corrupt")
                .clone();
            corrupted_dealing.flip_a_bit_in_one();
            corrupted_dealing
        });

        let result = creator.create_transcript(&params, &batch_signed_dealings);

        assert_matches!(
            result,
            Err(IDkgCreateTranscriptError::InvalidSignatureBatch {
                crypto_error: CryptoError::SignatureVerification { .. }
            })
        );
    }
}

mod load_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::node::Node;

    #[test]
    fn should_return_ok_from_load_transcript_if_not_a_receiver() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let not_participating_node_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let not_participating_node = Node::new(
            not_participating_node_id,
            Arc::clone(&env.registry),
            &mut rng,
        );

        assert!(!transcript
            .receivers
            .get()
            .contains(&not_participating_node_id));
        let result = not_participating_node.load_transcript(&transcript);
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_run_load_transcript_successfully_if_already_loaded() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let loader = env.nodes.random_receiver(params.receivers(), &mut rng);

        assert_matches!(loader.load_transcript(&transcript), Ok(_));
        assert_matches!(loader.load_transcript(&transcript), Ok(_));
    }

    #[test]
    fn should_load_transcript_without_returning_complaints() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let loader = env.nodes.random_receiver(params.receivers(), &mut rng);

        let result = loader.load_transcript(&transcript);

        assert_matches!(result, Ok(complaints) if complaints.is_empty());
    }
}

mod verify_complaint {
    use super::*;

    #[test]
    fn should_verify_complaint() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(2..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);

        let result = env
            .nodes
            .random_receiver(params.receivers(), &mut rng)
            .verify_complaint(&transcript, complainer.id(), &complaint);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_return_valid_and_correct_complaints_on_load_transcript_with_invalid_dealings() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let num_of_complaints = rng.gen_range(1..=transcript.verified_dealings.len());
        let (complainer, corrupted_dealing_indices, complaints) =
            generate_complaints(&mut transcript, num_of_complaints, &params, &env, &mut rng);

        for complaint in &complaints {
            assert_eq!(complaint.transcript_id, transcript.transcript_id);
            assert_eq!(
                env.nodes
                    .random_receiver(params.receivers(), &mut rng)
                    .verify_complaint(&transcript, complainer.id(), complaint),
                Ok(())
            );
        }
        // Ensure the complaints' dealer IDs are correct
        for index in corrupted_dealing_indices {
            let dealer_id = transcript
                .dealer_id_for_index(index)
                .expect("cannot find dealer ID for index");
            let dealer_for_index_exists_in_complaints = complaints
                .iter()
                .any(|complaint| complaint.dealer_id == dealer_id);
            assert!(dealer_for_index_exists_in_complaints);
        }
    }

    #[test]
    fn should_fail_to_verify_complaint_against_wrong_complainer_id() {
        const MIN_NUM_NODES: usize = 2; //1 complainer and 1 other receiver
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            &mut rng,
        );
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);

        let wrong_complainer_id =
            random_receiver_id_excluding(params.receivers(), complainer.id(), &mut rng);

        assert_matches!(
            env.nodes
                .random_receiver(params.receivers(), &mut rng)
                .verify_complaint(&transcript, wrong_complainer_id, &complaint,),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        );
    }

    #[test]
    fn should_fail_to_verify_complaint_with_wrong_transcript_id() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(2..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);

        let other_transcript_id = env
            .params_for_random_sharing(
                &dealers,
                &receivers,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &mut rng,
            )
            .transcript_id();
        assert_ne!(other_transcript_id, params.transcript_id());
        let complaint = complaint
            .into_builder()
            .with_transcript_id(other_transcript_id)
            .build();

        let result = env
            .nodes
            .random_receiver(params.receivers(), &mut rng)
            .verify_complaint(&transcript, complainer.id(), &complaint);

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs)
        );
    }

    #[test]
    /// This test creates >=2 dealings, corrupts 2 of them to generate 2 valid
    /// complaints, then switches the dealer IDs for those valid complaints to make
    /// them invalid, and then tests that verification fails with `InvalidComplaint`
    /// for both complaints.
    /// We must create at least 4 dealings to ensure the collection threshold
    /// is at least 2, so that we have sufficient number of dealings included
    /// in the final transcript.
    fn should_fail_to_verify_complaint_with_wrong_dealer_id() {
        const MIN_NUM_NODES: usize = 4;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        assert!(params.collection_threshold().get() >= 2);
        let num_of_dealings_to_corrupt = 2;

        let (complainer, _, complaints) = generate_complaints(
            &mut transcript,
            num_of_dealings_to_corrupt,
            &params,
            &env,
            &mut rng,
        );
        let complainer_id = complainer.id();

        let mut complaint_1 = complaints.get(0).unwrap().clone();
        let mut complaint_2 = complaints.get(1).unwrap().clone();
        std::mem::swap(&mut complaint_1.dealer_id, &mut complaint_2.dealer_id);

        assert_matches!(
            complainer.verify_complaint(&transcript, complainer_id, &complaint_1,),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        );
        assert_matches!(
            complainer.verify_complaint(&transcript, complainer_id, &complaint_2,),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        );
    }

    #[test]
    /// This test creates >=4 dealings, corrupts 2 of them to generate 2 valid
    /// complaints, then switches the internal complaints for those valid
    /// complaints to make them invalid, and then tests that verification fails
    /// with `InvalidComplaint` for both complaints.
    /// We must create at least 4 dealings to ensure the collection threshold
    /// is at least 2, so that we have sufficient number of dealings included
    /// in the final transcript.
    fn should_fail_to_verify_complaint_with_wrong_internal_complaint() {
        const MIN_NUM_NODES: usize = 4; //needs at least 4 dealers
        let mut rng = reproducible_rng();
        let num_of_dealings_to_corrupt = 2;
        let subnet_size = rng.gen_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        assert!(params.collection_threshold().get() as usize >= num_of_dealings_to_corrupt);
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let (complainer, _, complaints) = generate_complaints(
            &mut transcript,
            num_of_dealings_to_corrupt,
            &params,
            &env,
            &mut rng,
        );
        let complainer_id = complainer.id();

        let mut complaint_1 = complaints.get(0).unwrap().clone();
        let mut complaint_2 = complaints.get(1).unwrap().clone();
        std::mem::swap(
            &mut complaint_1.internal_complaint_raw,
            &mut complaint_2.internal_complaint_raw,
        );

        assert_matches!(
            complainer.verify_complaint(&transcript, complainer_id, &complaint_1,),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        );
        assert_matches!(
            complainer.verify_complaint(&transcript, complainer_id, &complaint_2,),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        );
    }
}

mod verify_transcript {
    use super::*;

    #[test]
    fn should_run_idkg_successfully_for_random_dealing() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);

        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        // Transcript should have correct dealer indexes
        check_dealer_indexes(&params, &transcript);
    }

    #[test]
    fn should_run_idkg_successfully_for_reshare_of_random_dealing() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let initial_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let initial_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&initial_params, &mut rng);

        // Initial transcript should have correct dealer indexes
        check_dealer_indexes(&initial_params, &initial_transcript);

        let reshare_params = build_params_from_previous(
            initial_params,
            IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
            &mut rng,
        );
        let reshare_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&reshare_params, &mut rng);

        // Reshare transcript should have correct dealer indexes
        check_dealer_indexes(&reshare_params, &reshare_transcript);
    }

    #[test]
    fn should_run_idkg_successfully_for_reshare_of_unmasked_dealing() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let initial_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let initial_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&initial_params, &mut rng);

        // Initial transcript should have correct dealer indexes
        check_dealer_indexes(&initial_params, &initial_transcript);

        let unmasked_params = build_params_from_previous(
            initial_params,
            IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
            &mut rng,
        );
        let unmasked_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&unmasked_params, &mut rng);

        let reshare_params = build_params_from_previous(
            unmasked_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
            &mut rng,
        );
        let reshare_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&reshare_params, &mut rng);

        check_dealer_indexes(&reshare_params, &reshare_transcript);
    }

    #[test]
    fn should_run_idkg_successfully_for_multiplication_of_dealings() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let masked_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let masked_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&masked_params, &mut rng);

        // Masked transcript should have correct dealer indexes
        check_dealer_indexes(&masked_params, &masked_transcript);

        let unmasked_transcript = {
            let masked_random_params = env.params_for_random_sharing(
                &dealers,
                &receivers,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &mut rng,
            );
            let masked_random_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&masked_random_params, &mut rng);

            let unmasked_params = build_params_from_previous(
                masked_random_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_random_transcript),
                &mut rng,
            );
            let unmasked_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_params, &mut rng);

            // Unmasked transcript should have correct dealer indexes
            check_dealer_indexes(&unmasked_params, &unmasked_transcript);

            unmasked_transcript
        };

        let multiplication_params = build_params_from_previous(
            masked_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
            &mut rng,
        );
        let multiplication_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&multiplication_params, &mut rng);

        // Multiplication transcript should have correct dealer indexes
        check_dealer_indexes(&multiplication_params, &multiplication_transcript);
    }

    #[test]
    fn should_include_the_expected_number_of_dealings_in_a_transcript() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let random_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let random_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&random_params, &mut rng);

        assert_eq!(
            random_transcript.verified_dealings.len(),
            random_params.collection_threshold().get() as usize
        );

        let unmasked_params = build_params_from_previous(
            random_params.clone(),
            IDkgTranscriptOperation::ReshareOfMasked(random_transcript.clone()),
            &mut rng,
        );
        let unmasked_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&unmasked_params, &mut rng);

        assert_eq!(
            unmasked_transcript.verified_dealings.len(),
            unmasked_params.collection_threshold().get() as usize
        );

        let reshare_params = build_params_from_previous(
            unmasked_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript.clone()),
            &mut rng,
        );
        let reshare_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&reshare_params, &mut rng);

        assert_eq!(
            reshare_transcript.verified_dealings.len(),
            reshare_params.collection_threshold().get() as usize
        );

        let multiplication_params = build_params_from_previous(
            random_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, random_transcript),
            &mut rng,
        );
        let multiplication_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&multiplication_params, &mut rng);

        assert_eq!(
            multiplication_transcript.verified_dealings.len(),
            multiplication_params.collection_threshold().get() as usize
        );
    }

    #[test]
    fn should_create_quadruple_successfully_with_new_key() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        generate_presig_quadruple(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &key_transcript,
            &mut rng,
        );
    }

    #[test]
    fn should_verify_transcript_accept_random_transcript_with_dealings_swapped() {
        /*
        This behavior may seem strange but it follows from how random dealings
        are combined, and the fact that we are really checking that the
        transcript is *consistent* with the set of dealings, rather than
        checking that there is a 1:1 correspondence between the dealings
        and the transcript
         */
        const MIN_NUM_NODES: usize = 4;
        let mut rng = reproducible_rng();

        let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let dealers = env
            .nodes
            .dealers(&params)
            .take(params.collection_threshold().get() as usize)
            .choose_multiple(&mut rng, 2);

        let transcript =
            swap_two_dealings_in_transcript(&params, transcript, &env, dealers[0], dealers[1]);

        let r = env
            .nodes
            .random_receiver(params.receivers(), &mut rng)
            .verify_transcript(&params, &transcript);

        assert_matches!(r, Ok(()));
    }

    //TODO CRP-2110: This test is currently ignored because it's flaky and the fix is not trivial.
    #[ignore]
    #[test]
    fn should_verify_transcript_reject_reshared_transcript_with_dealings_swapped() {
        const MIN_NUM_NODES: usize = 4;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );

        let masked_key_params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let masked_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&masked_key_params, &mut rng);

        let params = build_params_from_previous(
            masked_key_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
            &mut rng,
        );

        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let dealers = env
            .nodes
            .dealers(&params)
            .take(params.collection_threshold().get() as usize)
            .choose_multiple(&mut rng, 2);

        let transcript =
            swap_two_dealings_in_transcript(&params, transcript, &env, dealers[0], dealers[1]);

        let r = env
            .nodes
            .random_receiver(params.receivers(), &mut rng)
            .verify_transcript(&params, &transcript);

        assert_matches!(r, Err(IDkgVerifyTranscriptError::InvalidTranscript));
    }

    #[test]
    fn should_verify_transcript_reject_random_transcript_with_dealing_replaced() {
        const MIN_NUM_NODES: usize = 4;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let dealers = env
            .nodes
            .dealers(&params)
            .take(params.collection_threshold().get() as usize)
            .choose_multiple(&mut rng, 2);
        let dealer0 = dealers[0];
        let dealer1 = dealers[1];
        let dealer0_idx = transcript.index_for_dealer_id(dealer0.id()).unwrap();
        let dealer1_idx = transcript.index_for_dealer_id(dealer1.id()).unwrap();

        let dealing = transcript
            .verified_dealings
            .get(&dealer0_idx)
            .expect("Dealing exists")
            .clone();

        let dealing_resigned = dealing
            .content
            .into_builder()
            .with_dealer_id(dealer1.id())
            .build_with_signature(&params, dealer1, dealer1.id());

        let dealing = env
            .nodes
            .support_dealing_from_all_receivers(dealing_resigned, &params);

        assert!(transcript
            .verified_dealings
            .insert(dealer1_idx, dealing)
            .is_some());

        let r = env
            .nodes
            .random_receiver(params.receivers(), &mut rng)
            .verify_transcript(&params, &transcript);

        assert_matches!(r, Err(IDkgVerifyTranscriptError::InvalidTranscript));
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_insufficient_dealings() {
        const MIN_NUM_NODES: usize = 4;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        while transcript.verified_dealings.len() >= params.collection_threshold().get() as usize {
            transcript.verified_dealings.pop_first();
        }

        let r = env
            .nodes
            .random_receiver(params.receivers(), &mut rng)
            .verify_transcript(&params, &transcript);

        assert_matches!(r, Err(IDkgVerifyTranscriptError::InvalidArgument(msg))
                        if msg.starts_with("failed to verify transcript against params: insufficient number of dealings"));
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_corrupted_internal_data() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(4..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );

        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let raw_len = transcript.internal_transcript_raw.len();
        let corrupted_idx = rng.gen::<usize>() % raw_len;
        transcript.internal_transcript_raw[corrupted_idx] ^= 1;

        let r = env
            .nodes
            .random_receiver(params.receivers(), &mut rng)
            .verify_transcript(&params, &transcript);

        // Since the corruption is randomized, we might corrupt the CBOR or the commitments
        // and thus different errors may result
        match r {
            Err(IDkgVerifyTranscriptError::InvalidTranscript) => {}

            Err(IDkgVerifyTranscriptError::SerializationError(msg)) => {
                assert!(msg.starts_with("failed to deserialize internal transcript"))
            }
            Err(e) => panic!("Unexpected error {:?}", e),
            Ok(()) => panic!("Unexpected success"),
        }
    }
}

mod sign_share {
    use super::*;
    use ic_protobuf::log::log_entry::v1::LogEntry;
    use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
    use proptest::array::uniform5;
    use proptest::prelude::{any, Strategy};
    use rand_chacha::ChaCha20Rng;
    use slog::Level;
    use std::collections::HashSet;

    #[test]
    fn should_create_signature_share_successfully_with_new_key() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let quadruple = generate_presig_quadruple(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &key_transcript,
            &mut rng,
        );

        let inputs = {
            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };

            let hashed_message = rng.gen::<[u8; 32]>();
            let seed = Randomness::from(rng.gen::<[u8; 32]>());

            ThresholdEcdsaSigInputs::new(
                &derivation_path,
                &hashed_message,
                seed,
                quadruple,
                key_transcript,
            )
            .expect("failed to create signature inputs")
        };

        let receiver = env.nodes.random_receiver(inputs.receivers(), &mut rng);
        receiver.load_input_transcripts(&inputs);
        let result = receiver.sign_share(&inputs);
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_log_public_key_successfully() {
        let mut rng = reproducible_rng();

        let subnet_size: usize = 1;
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let quadruple = generate_presig_quadruple(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &key_transcript,
            &mut rng,
        );

        let inputs = {
            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };

            let hashed_message = rng.gen::<[u8; 32]>();
            let seed = Randomness::from(rng.gen::<[u8; 32]>());

            ThresholdEcdsaSigInputs::new(
                &derivation_path,
                &hashed_message,
                seed,
                quadruple,
                key_transcript,
            )
            .expect("failed to create signature inputs")
        };

        let signer = env.nodes.into_random_receiver(inputs.receivers(), &mut rng);

        signer.load_input_transcripts(&inputs);

        let _result = signer.sign_share(&inputs);
        let logs = signer.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Info, "MASTER tECDSA PUBLIC KEY: ");
    }

    #[test]
    fn should_log_same_public_key_successfully_for_multiple_quadruples_and_inputs() {
        let mut rng = reproducible_rng();

        const SUBNET_SIZE: usize = 1;
        const NUM_SIGNATURES: usize = 2;
        let env = CanisterThresholdSigTestEnvironment::new(SUBNET_SIZE, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut inputs: Vec<ThresholdEcdsaSigInputs> = Vec::new();
        for _ in 0..NUM_SIGNATURES {
            let quadruple = generate_presig_quadruple(
                &env,
                &dealers,
                &receivers,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &key_transcript,
                &mut rng,
            );

            let sig_inputs = {
                let derivation_path = ExtendedDerivationPath {
                    caller: PrincipalId::new_user_test_id(1),
                    derivation_path: vec![],
                };

                let hashed_message = rng.gen::<[u8; 32]>();
                let seed = Randomness::from(rng.gen::<[u8; 32]>());

                ThresholdEcdsaSigInputs::new(
                    &derivation_path,
                    &hashed_message,
                    seed,
                    quadruple,
                    key_transcript.clone(),
                )
                .expect("failed to create signature inputs")
            };
            inputs.push(sig_inputs);
        }

        let first_input = inputs.first().expect("missing inputs");
        let signer = env
            .nodes
            .into_random_receiver(first_input.receivers(), &mut rng);
        signer.load_input_transcripts(first_input);

        for i in 0..NUM_SIGNATURES {
            let _result = signer.sign_share(inputs.get(i).expect("missing input"));
        }

        let logs = signer.drain_logs();
        let logged_public_keys = parse_logged_public_keys(&logs);
        assert_eq!(NUM_SIGNATURES, logged_public_keys.len());
        let first_public_key = logged_public_keys
            .first()
            .expect("missing logged public key");
        assert!(first_public_key.contains("MASTER tECDSA PUBLIC KEY: "));
        for i in 1..NUM_SIGNATURES {
            assert_eq!(
                first_public_key,
                logged_public_keys
                    .get(i)
                    .expect("missing logged public key")
            )
        }
    }

    fn parse_logged_public_keys(logs: &Vec<LogEntry>) -> Vec<String> {
        let mut logged_public_keys: Vec<String> = Vec::new();
        for log in logs {
            if log.message.contains("MASTER tECDSA PUBLIC KEY: ") {
                logged_public_keys.push(log.message.clone());
            }
        }
        logged_public_keys
    }

    #[test]
    fn should_fail_create_signature_if_not_receiver() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let quadruple = generate_presig_quadruple(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &key_transcript,
            &mut rng,
        );

        let inputs = {
            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };

            let hashed_message = rng.gen::<[u8; 32]>();
            let seed = Randomness::from(rng.gen::<[u8; 32]>());

            ThresholdEcdsaSigInputs::new(
                &derivation_path,
                &hashed_message,
                seed,
                quadruple,
                key_transcript,
            )
            .expect("failed to create signature inputs")
        };

        let bad_signer_id = random_node_id_excluding(inputs.receivers().get(), &mut rng);
        let bad_crypto_component = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(bad_signer_id)
            .with_rng(rng)
            .build();

        let result = bad_crypto_component.sign_share(&inputs);
        let err = result.unwrap_err();
        assert_matches!(err, ThresholdEcdsaSignShareError::NotAReceiver);
    }

    #[test]
    fn should_fail_to_sign_when_input_transcripts_not_retained() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let quadruple = generate_presig_quadruple(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &key_transcript,
            &mut rng,
        );

        let inputs = {
            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };

            let hashed_message = rng.gen::<[u8; 32]>();
            let seed = Randomness::from(rng.gen::<[u8; 32]>());

            ThresholdEcdsaSigInputs::new(
                &derivation_path,
                &hashed_message,
                seed,
                quadruple,
                key_transcript,
            )
            .expect("failed to create signature inputs")
        };

        let receiver = env.nodes.random_receiver(inputs.receivers(), &mut rng);
        receiver.load_input_transcripts(&inputs);
        assert_matches!(receiver.sign_share(&inputs), Ok(_));
        let another_key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let active_transcripts = hashset!(another_key_transcript);
        assert_eq!(
            receiver.retain_active_transcripts(&active_transcripts),
            Ok(())
        );

        let result = receiver.sign_share(&inputs);
        assert_matches!(
            result,
            Err(ThresholdEcdsaSignShareError::SecretSharesNotFound { .. })
        );
    }

    #[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
    struct SignerState {
        retain_key_transcript: bool,
        retain_kappa_unmasked: bool,
        retain_lambda_masked: bool,
        retain_kappa_times_lambda: bool,
        retain_key_times_lambda: bool,
    }

    impl SignerState {
        fn is_retain_some(&self) -> bool {
            self.retain_key_transcript
                || self.retain_kappa_unmasked
                || self.retain_lambda_masked
                || self.retain_kappa_times_lambda
                || self.retain_key_times_lambda
        }

        fn transcripts_to_retain(
            &self,
            sig_inputs: &ThresholdEcdsaSigInputs,
        ) -> HashSet<IDkgTranscript> {
            let mut transcripts = HashSet::with_capacity(5);
            if self.retain_key_transcript {
                assert!(transcripts.insert(sig_inputs.key_transcript().clone()));
            }
            if self.retain_kappa_unmasked {
                assert!(transcripts.insert(sig_inputs.presig_quadruple().kappa_unmasked().clone()));
            }
            if self.retain_lambda_masked {
                assert!(transcripts.insert(sig_inputs.presig_quadruple().lambda_masked().clone()));
            }
            if self.retain_kappa_times_lambda {
                assert!(
                    transcripts.insert(sig_inputs.presig_quadruple().kappa_times_lambda().clone())
                );
            }
            if self.retain_key_times_lambda {
                assert!(
                    transcripts.insert(sig_inputs.presig_quadruple().key_times_lambda().clone())
                );
            }
            transcripts
        }

        fn should_be_able_to_sign_share(&self) -> bool {
            self.retain_lambda_masked
                && self.retain_kappa_times_lambda
                && self.retain_key_times_lambda
        }
    }

    fn arb_signer_state_with_at_least_one_retained_transcript() -> impl Strategy<Value = SignerState>
    {
        uniform5(any::<bool>()).prop_filter_map(
            "At least one transcript must be retained",
            |array| {
                let state = SignerState {
                    retain_key_transcript: array[0],
                    retain_kappa_unmasked: array[1],
                    retain_lambda_masked: array[2],
                    retain_kappa_times_lambda: array[3],
                    retain_key_times_lambda: array[4],
                };
                if state.is_retain_some() {
                    Some(state)
                } else {
                    None
                }
            },
        )
    }

    #[test]
    fn should_be_able_to_sign_share_depending_on_which_transcript_is_retained() {
        use proptest::collection::vec;
        use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
        let mut rng = reproducible_rng();
        let subnet_size = 4;
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            derivation_path: vec![],
        };
        let hashed_message = rng.gen::<[u8; 32]>();
        let seed = Randomness::from(rng.gen::<[u8; 32]>());

        const CHACHA_SEED_LEN: usize = 32;
        let mut runner = TestRunner::new_with_rng(
            Config::with_cases(10),
            TestRng::from_seed(RngAlgorithm::ChaCha, &rng.gen::<[u8; CHACHA_SEED_LEN]>()),
        );
        // retain_active_transcripts is a no-op when the parameter active_transcripts is empty
        let result = runner.run(
            &(
                arb_signer_state_with_at_least_one_retained_transcript(),
                vec(0..=255u8, CHACHA_SEED_LEN),
            ),
            |(signer_state, rng_seed)| {
                let mut inner_rng = ChaCha20Rng::from_seed(
                    rng_seed[..]
                        .try_into()
                        .expect("Failed to convert seed to array"),
                );
                let key_transcript = generate_key_transcript(
                    &env,
                    &dealers,
                    &receivers,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &mut inner_rng,
                );
                let quadruple = generate_presig_quadruple(
                    &env,
                    &dealers,
                    &receivers,
                    AlgorithmId::ThresholdEcdsaSecp256k1,
                    &key_transcript,
                    &mut inner_rng,
                );

                let inputs = ThresholdEcdsaSigInputs::new(
                    &derivation_path,
                    &hashed_message,
                    seed,
                    quadruple,
                    key_transcript,
                )
                .expect("failed to create signature inputs");

                let receiver = env
                    .nodes
                    .random_receiver(inputs.receivers(), &mut inner_rng);
                receiver.load_input_transcripts(&inputs);
                assert_matches!(
                    receiver.sign_share(&inputs),
                    Ok(_),
                    "{} failed to sign share with all transcripts loaded for state {:?}",
                    receiver.id(),
                    signer_state
                );

                let active_transcripts = signer_state.transcripts_to_retain(&inputs);
                assert_eq!(
                    receiver.retain_active_transcripts(&active_transcripts),
                    Ok(()),
                    "{} failed to retain transcripts specified in {:?}",
                    receiver.id(),
                    signer_state
                );

                let result = receiver.sign_share(&inputs);

                if signer_state.should_be_able_to_sign_share() {
                    assert_matches!(
                        result,
                        Ok(_),
                        "{} should have been able to sign a share with state {:?}",
                        receiver.id(),
                        signer_state
                    );
                } else {
                    assert_matches!(
                        result,
                        Err(ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }),
                        "{} should not have been able to sign a share with state {:?}",
                        receiver.id(),
                        signer_state
                    );
                }
                Ok(())
            },
        );
        assert_eq!(result, Ok(()));
    }
}

mod verify_sig_share {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::CorruptBytes;
    use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaVerifySigShareError;
    use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaSigShare;

    #[test]
    fn should_verify_sig_share_successfully() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, &mut rng);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);

        let result = verifier.verify_sig_share(signer_id, &inputs, &sig_share);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_fail_verifying_inputs_with_wrong_hashed_message() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let inputs_with_wrong_hash = inputs
            .clone()
            .into_builder()
            .corrupt_hashed_message()
            .build();
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, &mut rng);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);

        let result = verifier.verify_sig_share(signer_id, &inputs_with_wrong_hash, &sig_share);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
        );
    }

    #[test]
    fn should_fail_verifying_inputs_with_wrong_nonce() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let inputs_with_wrong_nonce = inputs.clone().into_builder().corrupt_nonce().build();
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, &mut rng);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);

        let result = verifier.verify_sig_share(signer_id, &inputs_with_wrong_nonce, &sig_share);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
        );
    }

    #[test]
    fn should_fail_verifying_corrupted_sig_share() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let (signer_id, corrupted_sig_share) = {
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs, &mut rng);
            (signer_id, sig_share.clone_with_bit_flipped())
        };
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);

        let result = verifier.verify_sig_share(signer_id, &inputs, &corrupted_sig_share);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
        );
    }

    #[test]
    fn should_verify_sig_share_from_another_signer_when_threshold_1() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(2..=3, &mut rng);
        assert_eq!(inputs.key_transcript().reconstruction_threshold().get(), 1);
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, &mut rng);
        let other_signer_id = random_receiver_id_excluding(inputs.receivers(), signer_id, &mut rng);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);

        let result = verifier.verify_sig_share(other_signer_id, &inputs, &sig_share);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_fail_verifying_sig_share_from_another_signer() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(4..10, &mut rng);
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, &mut rng);
        let other_signer_id = random_receiver_id_excluding(inputs.receivers(), signer_id, &mut rng);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);

        let result = verifier.verify_sig_share(other_signer_id, &inputs, &sig_share);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
        );
    }

    #[test]
    fn should_fail_verifying_sig_share_for_unknown_signer() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, &mut rng);
        let unknown_signer_id = NodeId::from(PrincipalId::new_node_test_id(1));
        assert_ne!(signer_id, unknown_signer_id);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);

        let result = verifier.verify_sig_share(unknown_signer_id, &inputs, &sig_share);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifySigShareError::InvalidArgumentMissingSignerInTranscript {signer_id})
            if signer_id == unknown_signer_id
        );
    }

    #[test]
    fn should_fail_deserializing_sig_share() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);
        let signer_id = random_receiver_for_inputs(&inputs, &mut rng);
        let invalid_sig_share = ThresholdEcdsaSigShare {
            sig_share_raw: Vec::new(),
        };

        let result = verifier.verify_sig_share(signer_id, &inputs, &invalid_sig_share);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifySigShareError::SerializationError { .. })
        )
    }

    #[test]
    fn should_fail_when_key_internal_transcript_raw_switched() {
        let mut rng = reproducible_rng();
        let (env, inputs, dealers, receivers) = environment_with_sig_inputs(1..10, &mut rng);
        let (signer_id, sig_share) = signature_share_from_random_receiver(&env, &inputs, &mut rng);
        let verifier = env.nodes.random_receiver(inputs.receivers(), &mut rng);
        let inputs_with_other_key_internal_transcript_raw = {
            let another_key_transcript = generate_key_transcript(
                &env,
                &dealers,
                &receivers,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &mut rng,
            );
            assert_ne!(inputs.key_transcript(), &another_key_transcript);
            let key_transcript_with_other_internal_raw = IDkgTranscript {
                internal_transcript_raw: another_key_transcript.internal_transcript_raw,
                ..inputs.key_transcript().clone()
            };
            ThresholdEcdsaSigInputs::new(
                inputs.derivation_path(),
                inputs.hashed_message(),
                *inputs.nonce(),
                inputs.presig_quadruple().clone(),
                key_transcript_with_other_internal_raw,
            )
            .expect("invalid ECDSA inputs")
        };

        let result = verifier.verify_sig_share(
            signer_id,
            &inputs_with_other_key_internal_transcript_raw,
            &sig_share,
        );

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
        );
    }

    fn signature_share_from_random_receiver<R: RngCore + CryptoRng>(
        env: &CanisterThresholdSigTestEnvironment,
        inputs: &ThresholdEcdsaSigInputs,
        rng: &mut R,
    ) -> (NodeId, ThresholdEcdsaSigShare) {
        let signer = env.nodes.random_receiver(inputs.receivers(), rng);
        signer.load_input_transcripts(inputs);
        let sig_share = signer
            .sign_share(inputs)
            .expect("failed to generate sig share");
        (signer.id(), sig_share)
    }
}

mod retain_active_transcripts {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn should_be_nop_when_transcripts_empty() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let retainer = env.nodes.random_node(&mut rng);
        let public_keys_before_retaining = retainer.current_node_public_keys().unwrap();
        assert!(public_keys_before_retaining
            .idkg_dealing_encryption_public_key
            .is_some());

        let empty_transcripts = HashSet::new();

        assert_eq!(
            retainer.retain_active_transcripts(&empty_transcripts),
            Ok(())
        );
        assert_eq!(
            public_keys_before_retaining,
            retainer.current_node_public_keys().unwrap()
        );
    }

    #[test]
    fn should_retain_active_transcripts_successfully() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);

        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);

        let retainer = env.nodes.random_receiver(params.receivers(), &mut rng);

        let active_transcripts = hashset!(transcript);
        assert_eq!(
            retainer.retain_active_transcripts(&active_transcripts),
            Ok(())
        );
    }
}

mod load_transcript_with_openings {
    use super::*;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgOpening;

    #[test]
    fn should_load_transcript_without_openings_when_none_required() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let loader = env.nodes.random_receiver(params.receivers(), &mut rng);
        let openings = BTreeMap::new();

        let result = loader.load_transcript_with_openings(&transcript, &openings);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_load_with_enough_openings() {
        const MIN_NUM_NODES: usize = 2;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            &mut rng,
        );
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let reconstruction_threshold =
            usize::try_from(transcript.reconstruction_threshold().get()).expect("invalid number");
        let number_of_openings = reconstruction_threshold;

        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let complaint_with_openings = generate_and_verify_openings_for_complaint(
            number_of_openings,
            &transcript,
            &env,
            complainer,
            complaint,
        );

        let result =
            complainer.load_transcript_with_openings(&transcript, &complaint_with_openings);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_fail_because_not_enough_openings() {
        const MIN_NUM_NODES: usize = 2;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            &mut rng,
        );
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let mut transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, &mut rng);
        let reconstruction_threshold =
            usize::try_from(transcript.reconstruction_threshold().get()).expect("invalid number");
        let number_of_openings = reconstruction_threshold - 1;

        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let complaint_with_openings = generate_and_verify_openings_for_complaint(
            number_of_openings,
            &transcript,
            &env,
            complainer,
            complaint,
        );

        let result =
            complainer.load_transcript_with_openings(&transcript, &complaint_with_openings);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InsufficientOpenings { .. })
        );
    }

    fn generate_and_verify_openings_for_complaint(
        number_of_openings: usize,
        transcript: &IDkgTranscript,
        env: &CanisterThresholdSigTestEnvironment,
        complainer: &Node,
        complaint: IDkgComplaint,
    ) -> BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>> {
        let openers = env
            .nodes
            .receivers(&transcript)
            .filter(|node| *node != complainer);
        let openings: BTreeMap<_, _> = openers
            .take(number_of_openings)
            .map(|opener| {
                let opening =
                    generate_and_verify_opening(opener, complainer, transcript, &complaint);
                (opener.id(), opening)
            })
            .collect();
        assert_eq!(openings.values().len(), number_of_openings);

        let mut complaint_with_openings = BTreeMap::new();
        complaint_with_openings.insert(complaint, openings);
        complaint_with_openings
    }

    fn generate_and_verify_opening(
        opener: &Node,
        complainer: &Node,
        transcript: &IDkgTranscript,
        complaint: &IDkgComplaint,
    ) -> IDkgOpening {
        let opening = opener
            .open_transcript(transcript, complainer.id(), complaint)
            .expect("failed creating opening");
        assert_eq!(
            complainer.verify_opening(transcript, opener.id(), &opening, complaint),
            Ok(())
        );
        opening
    }
}

mod combine_sig_shares {
    use super::*;

    #[test]
    fn should_combine_sig_shares_successfully() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let sig_shares = sig_share_from_each_receiver(&env, &inputs);
        let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        let result = combiner.combine_sig_shares(&inputs, &sig_shares);

        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_fail_combining_sig_shares_with_insufficient_shares() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let insufficient_sig_shares = sig_share_from_each_receiver(&env, &inputs)
            .into_iter()
            .take(inputs.reconstruction_threshold().get() as usize - 1)
            .collect();
        let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        let result = combiner.combine_sig_shares(&inputs, &insufficient_sig_shares);

        assert_matches!(
            result,
            Err(ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold {threshold, share_count})
            if threshold == inputs.reconstruction_threshold().get() && share_count == (threshold as usize - 1)
        );
    }
}

mod verify_combined_sig {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::CorruptBytes;
    use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaVerifyCombinedSignatureError;

    #[test]
    fn should_verify_combined_sig() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let sig_shares = sig_share_from_each_receiver(&env, &inputs);
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);
        let signature = combiner_crypto_component
            .combine_sig_shares(&inputs, &sig_shares)
            .expect("Failed to generate signature");
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        let result = verifier_crypto_component.verify_combined_sig(&inputs, &signature);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_fail_verifying_corrupted_combined_sig() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let sig_shares = sig_share_from_each_receiver(&env, &inputs);
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);
        let corrupted_signature = combiner_crypto_component
            .combine_sig_shares(&inputs, &sig_shares)
            .expect("Failed to generate signature")
            .clone_with_bit_flipped();
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        let result = verifier_crypto_component.verify_combined_sig(&inputs, &corrupted_signature);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature)
        );
    }

    #[test]
    fn should_fail_deserializing_signature_with_invalid_length() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let sig_shares = sig_share_from_each_receiver(&env, &inputs);
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);
        let mut corrupted_signature = combiner_crypto_component
            .combine_sig_shares(&inputs, &sig_shares)
            .expect("Failed to generate signature");
        corrupted_signature.signature.pop();
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        let result = verifier_crypto_component.verify_combined_sig(&inputs, &corrupted_signature);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifyCombinedSignatureError::SerializationError { .. })
        );
    }

    #[test]
    fn should_fail_when_key_internal_transcript_raw_switched() {
        let mut rng = reproducible_rng();
        let (env, inputs, dealers, receivers) = environment_with_sig_inputs(1..10, &mut rng);
        let sig_shares = sig_share_from_each_receiver(&env, &inputs);
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);
        let signature = combiner_crypto_component
            .combine_sig_shares(&inputs, &sig_shares)
            .expect("Failed to generate signature");
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        let inputs_with_other_key_internal_transcript_raw = {
            let another_key_transcript = generate_key_transcript(
                &env,
                &dealers,
                &receivers,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &mut rng,
            );
            assert_ne!(inputs.key_transcript(), &another_key_transcript);
            let key_transcript_with_other_internal_raw = IDkgTranscript {
                internal_transcript_raw: another_key_transcript.internal_transcript_raw,
                ..inputs.key_transcript().clone()
            };
            ThresholdEcdsaSigInputs::new(
                inputs.derivation_path(),
                inputs.hashed_message(),
                *inputs.nonce(),
                inputs.presig_quadruple().clone(),
                key_transcript_with_other_internal_raw,
            )
            .expect("invalid ECDSA inputs")
        };

        let result = verifier_crypto_component
            .verify_combined_sig(&inputs_with_other_key_internal_transcript_raw, &signature);

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature)
        );
    }

    #[test]
    fn should_fail_verifying_combined_sig_for_inputs_with_wrong_hash() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let sig_shares = sig_share_from_each_receiver(&env, &inputs);
        let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);
        let signature = combiner
            .combine_sig_shares(&inputs, &sig_shares)
            .expect("Failed to generate signature");
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        let result = verifier_crypto_component.verify_combined_sig(
            &inputs.into_builder().corrupt_hashed_message().build(),
            &signature,
        );

        assert_matches!(
            result,
            Err(ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature)
        );
    }

    #[test]
    fn should_run_threshold_ecdsa_protocol_with_single_node() {
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..=1, &mut rng);
        let signature = run_tecdsa_protocol(&env, &inputs, &mut rng);
        let verifier = random_crypto_component_not_in_receivers(&env, inputs.receivers(), &mut rng);

        assert_eq!(verifier.verify_combined_sig(&inputs, &signature), Ok(()));
    }

    #[test]
    fn should_verify_combined_signature_with_usual_secp256k1_operation() {
        use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;
        let mut rng = reproducible_rng();
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, &mut rng);
        let combined_sig = run_tecdsa_protocol(&env, &inputs, &mut rng);
        let master_public_key = get_tecdsa_master_public_key(inputs.key_transcript())
            .expect("Master key extraction failed");
        let canister_public_key =
            derive_tecdsa_public_key(&master_public_key, inputs.derivation_path())
                .expect("Public key derivation failed");

        let ecdsa_sig = ecdsa_secp256k1::types::SignatureBytes(
            <[u8; 64]>::try_from(combined_sig.signature).expect("Expected 64 bytes"),
        );
        let ecdsa_pk = ecdsa_secp256k1::types::PublicKeyBytes(canister_public_key.public_key);

        assert_eq!(
            ecdsa_secp256k1::api::verify(&ecdsa_sig, inputs.hashed_message(), &ecdsa_pk),
            Ok(()),
            "ECDSA sig verification failed"
        );
    }
}

mod get_tecdsa_master_public_key {
    use super::*;

    #[test]
    fn should_return_ecdsa_public_key() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let result = get_tecdsa_master_public_key(&key_transcript);
        assert_matches!(result, Ok(_));
        let master_public_key = result.expect("Master key extraction failed");
        assert_eq!(master_public_key.algorithm_id, AlgorithmId::EcdsaSecp256k1);
        assert_eq!(master_public_key.public_key.len(), 33); // 1 byte header + 32 bytes of field element
    }

    #[test]
    fn should_derive_equal_ecdsa_public_keys() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let master_public_key =
            get_tecdsa_master_public_key(&key_transcript).expect("Master key extraction failed");

        let derivation_path_1 = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(42),
            derivation_path: vec![],
        };
        let derivation_path_2 = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(42),
            derivation_path: vec![],
        };

        assert_eq!(derivation_path_1, derivation_path_2);
        let derived_pk_1 = derive_tecdsa_public_key(&master_public_key, &derivation_path_1)
            .expect("Public key derivation failed ");
        let derived_pk_2 = derive_tecdsa_public_key(&master_public_key, &derivation_path_2)
            .expect("Public key derivation failed ");
        assert_eq!(derived_pk_1, derived_pk_2);
    }

    #[test]
    fn should_derive_differing_ecdsa_public_keys() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let master_public_key =
            get_tecdsa_master_public_key(&key_transcript).expect("Master key extraction failed");

        let derivation_paths = [
            ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            },
            ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(2),
                derivation_path: vec![],
            },
            ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(3),
                derivation_path: vec![],
            },
            ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(3),
                derivation_path: vec![vec![1, 2, 3, 4]],
            },
            ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(3),
                derivation_path: vec![vec![1, 2, 3, 5]],
            },
        ];
        let mut derived_keys = std::collections::HashSet::new();
        for derivation_path in &derivation_paths {
            let derived_pk = derive_tecdsa_public_key(&master_public_key, derivation_path)
                .unwrap_or_else(|_| {
                    panic!(
                        "Public key derivation failed for derivation path {:?}",
                        derivation_path
                    )
                });
            assert!(
                derived_keys.insert(derived_pk),
                "Duplicate derived key for derivation path {:?}",
                derivation_path
            );
        }
        assert_eq!(
            derived_keys.len(),
            derivation_paths.len(),
            "# of derived keys does not match # of derivation paths"
        );
    }

    #[test]
    fn should_derive_ecdsa_public_key_for_single_node() {
        let mut rng = reproducible_rng();
        let subnet_size = 1;
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);
        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let master_ecdsa_key = get_tecdsa_master_public_key(&key_transcript);
        assert_matches!(master_ecdsa_key, Ok(_));
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            derivation_path: vec![],
        };

        let derived_public_key =
            derive_tecdsa_public_key(&master_ecdsa_key.unwrap(), &derivation_path);

        assert_matches!(derived_public_key, Ok(_));
    }
}

mod verify_dealing_private {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::IntoBuilder;
    use ic_types::crypto::canister_threshold_sig::error::IDkgVerifyDealingPrivateError;

    #[test]
    fn should_verify_dealing_private() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let signed_dealing = dealer.create_dealing_or_panic(&params);
        let receiver = env.nodes.random_receiver(params.receivers(), &mut rng);

        let result = receiver.verify_dealing_private(&params, &signed_dealing);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_verify_dealing_private_with_wrong_signature() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let signed_dealing_with_corrupted_signature = dealer
            .create_dealing_or_panic(&params)
            .into_builder()
            .corrupt_signature()
            .build();
        let receiver = env.nodes.random_receiver(params.receivers(), &mut rng);

        let (result_verify_public, result_verify_private) = verify_dealing_public_and_private(
            receiver,
            &params,
            &signed_dealing_with_corrupted_signature,
        );

        assert_matches!(
            (result_verify_public, result_verify_private),
            (
                Err(IDkgVerifyDealingPublicError::InvalidSignature { .. }),
                Ok(())
            )
        );
    }

    #[test]
    fn should_verify_when_dealer_is_also_a_receiver() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let dealer_and_receiver = env.nodes.random_node(&mut rng);
        let (dealers_with_at_least_one_common_node, receivers_with_at_least_one_common_node) = {
            let (dealers, receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
            let mut dealers_ids = dealers.get().clone();
            dealers_ids.insert(dealer_and_receiver.id());
            let mut receivers_ids = receivers.get().clone();
            receivers_ids.insert(dealer_and_receiver.id());
            (
                IDkgDealers::new(dealers_ids).expect("valid dealers"),
                IDkgReceivers::new(receivers_ids).expect("valid receivers"),
            )
        };
        let params = env.params_for_random_sharing(
            &dealers_with_at_least_one_common_node,
            &receivers_with_at_least_one_common_node,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let signed_dealing = dealer_and_receiver.create_dealing_or_panic(&params);

        let result = dealer_and_receiver.verify_dealing_private(&params, &signed_dealing);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_fail_on_wrong_transcript_id() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let signed_dealing = dealer.create_dealing_or_panic(&params);
        let receiver = env.nodes.random_receiver(params.receivers(), &mut rng);

        let result = receiver.verify_dealing_private(
            &params,
            &signed_dealing
                .into_builder()
                .corrupt_transcript_id()
                .build_with_signature(&params, dealer, dealer.id()),
        );

        assert_matches!( result, Err(IDkgVerifyDealingPrivateError::InvalidArgument(reason)) if reason.starts_with("mismatching transcript IDs"));
    }

    #[test]
    fn should_fail_on_wrong_internal_dealing_raw() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let signed_dealing = dealer.create_dealing_or_panic(&params);
        let receiver = env.nodes.random_receiver(params.receivers(), &mut rng);

        let result = receiver.verify_dealing_private(
            &params,
            &signed_dealing
                .into_builder()
                .corrupt_internal_dealing_raw_by_flipping_bit()
                .build_with_signature(&params, dealer, dealer.id()),
        );

        assert_matches!( result, Err(IDkgVerifyDealingPrivateError::InvalidArgument(reason)) if reason.starts_with("failed to deserialize internal dealing"));
    }

    /// Call both [IDkgProtocol::verify_dealing_public] and [IDkgProtocol::verify_dealing_private]
    /// on the given dealing.
    /// Productive code should only call [IDkgProtocol::verify_dealing_private] if [IDkgProtocol::verify_dealing_public] was successful.
    /// For testing purposes we want to sometimes document the current behaviour of [IDkgProtocol::verify_dealing_private]
    /// even when [IDkgProtocol::verify_dealing_public] resulted in an error.
    fn verify_dealing_public_and_private<T: IDkgProtocol>(
        receiver: &T,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> (
        Result<(), IDkgVerifyDealingPublicError>,
        Result<(), IDkgVerifyDealingPrivateError>,
    ) {
        (
            receiver.verify_dealing_public(params, signed_dealing),
            receiver.verify_dealing_private(params, signed_dealing),
        )
    }
}

mod verify_dealing_public {
    use super::*;
    use ic_registry_client_helpers::crypto::CryptoRegistry;

    #[test]
    fn should_successfully_verify_random_sharing_dealing_with_valid_input() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);

        let signed_dealing = dealer.create_dealing_or_panic(&params);

        let verifier_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .with_rng(rng)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_fail_verify_dealing_public_with_invalid_signature() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let signed_dealing = dealer
            .create_dealing_or_panic(&params)
            .into_builder()
            .corrupt_signature()
            .build();

        let verifier_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .with_rng(rng)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert_matches!( result,
            Err(IDkgVerifyDealingPublicError::InvalidSignature { error, .. })
            if error.contains("Invalid basic signature on signed iDKG dealing from signer")
        );
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_transcript_id() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let signed_dealing = dealer
            .create_dealing_or_panic(&params)
            .into_builder()
            .corrupt_transcript_id()
            .build_with_signature(&params, dealer, dealer.id());

        let verifier_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .with_rng(rng)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert_matches!(
            result,
            Err(IDkgVerifyDealingPublicError::TranscriptIdMismatch)
        );
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_dealer_id() {
        const MIN_NUM_NODES: usize = 2;
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(MIN_NUM_NODES..10); //need at least 2 nodes to have a dealer and another node
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            &mut rng,
        );
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let other_dealer = env
            .nodes
            .dealers(&params)
            .find(|node| *node != dealer)
            .expect("not enough nodes");
        let signed_dealing = dealer
            .create_dealing_or_panic(&params)
            .into_builder()
            .with_dealer_id(other_dealer.id())
            .build_with_signature(&params, other_dealer, other_dealer.id());

        let verifier_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .with_rng(rng)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert_matches!(
            result,
            Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason == "InvalidProof"
        );
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_dealer_index() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        // We need the signature verification to succeed, so the public key of the valid dealer in
        // the registry needs to be copied to a non-dealer. The subsequent dealer index check will
        // fail (which is what we are testing), since the `NodeId` of the non-dealer is not
        // included in the list of dealers in params.
        let not_a_dealer_node_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        copy_node_signing_key_in_registry_from_one_node_to_another(
            &env,
            dealer.id(),
            not_a_dealer_node_id,
        );
        let signed_dealing = dealer
            .create_dealing_or_panic(&params)
            .into_builder()
            .build_with_signature(&params, dealer, dealer.id())
            .into_builder()
            .with_dealer_id(not_a_dealer_node_id)
            .build();

        let verifier_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .with_rng(rng)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert_matches!(
            result,
            Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason == "No such dealer"
        );
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_internal_dealing_raw() {
        let mut rng = reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let dealer = env.nodes.random_dealer(&params, &mut rng);
        let signed_dealing = dealer
            .create_dealing_or_panic(&params)
            .into_builder()
            .corrupt_internal_dealing_raw_by_flipping_bit()
            .build_with_signature(&params, dealer, dealer.id());

        let verifier_id = random_node_id_excluding(&env.nodes.ids(), &mut rng);
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .with_rng(rng)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert_matches!(
            result,
            Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason.starts_with("ThresholdEcdsaSerializationError")
        );
    }

    fn copy_node_signing_key_in_registry_from_one_node_to_another(
        env: &CanisterThresholdSigTestEnvironment,
        source_node_id: NodeId,
        destination_node_id: NodeId,
    ) {
        let node_signing_public_key = env
            .registry
            .get_crypto_key_for_node(
                source_node_id,
                ic_types::crypto::KeyPurpose::NodeSigning,
                env.newest_registry_version,
            )
            .expect("registry call should succeed");
        env.registry_data
            .add(
                &ic_registry_keys::make_crypto_node_key(
                    destination_node_id,
                    ic_types::crypto::KeyPurpose::NodeSigning,
                ),
                env.newest_registry_version,
                node_signing_public_key,
            )
            .expect("should be able to add node signing public key to registry");
        env.registry.reload();
    }
}

mod verify_initial_dealings {
    use super::*;
    use ic_base_types::RegistryVersion;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        random_transcript_id, IDkgParticipantsRandom,
    };

    #[test]
    fn should_successfully_verify_initial_dealing_from_non_participating_node() {
        let mut rng = reproducible_rng();
        let num_nodes = rng.gen_range(2..10);
        let num_source_subnet = rng.gen_range(1..num_nodes);
        let num_destination_subnet = num_nodes - num_source_subnet;
        assert!(
            num_destination_subnet >= 1,
            "number of nodes in destination subnet is less than 1"
        );
        let env = CanisterThresholdSigTestEnvironment::new(num_nodes, &mut rng);
        let external_verifier = Node::new(
            random_node_id_excluding(&env.nodes.ids(), &mut rng),
            Arc::clone(&env.registry),
            &mut rng,
        );
        let (source_subnet_nodes, destination_subnet_nodes) = env
            .nodes
            .partition(|(index, _node)| *index < num_source_subnet);
        let (initial_dealings, reshare_of_unmasked_params) = generate_initial_dealings(
            env.newest_registry_version,
            source_subnet_nodes,
            destination_subnet_nodes,
            false,
            &mut rng,
        );

        assert_eq!(
            external_verifier
                .verify_initial_dealings(&reshare_of_unmasked_params, &initial_dealings),
            Ok(())
        );
    }

    #[test]
    fn should_fail_on_mismatching_transcript_params() {
        let mut rng = reproducible_rng();
        let num_nodes = rng.gen_range(2..10);
        let num_source_subnet = rng.gen_range(1..num_nodes);
        let num_destination_subnet = num_nodes - num_source_subnet;
        assert!(
            num_destination_subnet >= 1,
            "number of nodes in destination subnet is less than 1"
        );
        let env = CanisterThresholdSigTestEnvironment::new(num_nodes, &mut rng);
        let verifier = Node::new(
            random_node_id_excluding(&env.nodes.ids(), &mut rng),
            Arc::clone(&env.registry),
            &mut rng,
        );
        let (source_subnet_nodes, destination_subnet_nodes) = env
            .nodes
            .partition(|(index, _node)| *index < num_source_subnet);
        let (initial_dealings, reshare_of_unmasked_params) = generate_initial_dealings(
            env.newest_registry_version,
            source_subnet_nodes,
            destination_subnet_nodes,
            false,
            &mut rng,
        );
        let other_params = IDkgTranscriptParams::new(
            random_transcript_id(&mut rng),
            reshare_of_unmasked_params.dealers().get().clone(),
            reshare_of_unmasked_params.receivers().get().clone(),
            env.newest_registry_version,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            IDkgTranscriptOperation::Random,
        )
        .expect("failed to create random IDkgTranscriptParams");

        assert_matches!(
            verifier.verify_initial_dealings(&other_params, &initial_dealings),
            Err(IDkgVerifyInitialDealingsError::MismatchingTranscriptParams)
        );
    }

    #[test]
    fn should_fail_if_public_verification_fails() {
        let mut rng = reproducible_rng();
        let num_nodes = rng.gen_range(2..10);
        let num_source_subnet = rng.gen_range(1..num_nodes);
        let num_destination_subnet = num_nodes - num_source_subnet;
        assert!(
            num_destination_subnet >= 1,
            "number of nodes in destination subnet is less than 1"
        );
        let env = CanisterThresholdSigTestEnvironment::new(num_nodes, &mut rng);
        let verifier = Node::new(
            random_node_id_excluding(&env.nodes.ids(), &mut rng),
            Arc::clone(&env.registry),
            &mut rng,
        );
        let (source_subnet_nodes, destination_subnet_nodes) = env
            .nodes
            .partition(|(index, _node)| *index < num_source_subnet);
        let (initial_dealings_with_first_corrupted, reshare_of_unmasked_params) =
            generate_initial_dealings(
                env.newest_registry_version,
                source_subnet_nodes,
                destination_subnet_nodes,
                true,
                &mut rng,
            );

        let result = verifier.verify_initial_dealings(
            &reshare_of_unmasked_params,
            &initial_dealings_with_first_corrupted,
        );
        assert_matches!(result, Err(IDkgVerifyInitialDealingsError::PublicVerificationFailure { verify_dealing_public_error, ..})
            if matches!(verify_dealing_public_error, IDkgVerifyDealingPublicError::InvalidSignature { .. })
        );
    }

    fn generate_initial_dealings<R: RngCore + CryptoRng>(
        registry_version: RegistryVersion,
        source_subnet_nodes: Nodes,
        target_subnet_nodes: Nodes,
        corrupt_first_dealing: bool,
        rng: &mut R,
    ) -> (InitialIDkgDealings, IDkgTranscriptParams) {
        let (source_dealers, source_receivers) = source_subnet_nodes
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);
        let source_key_transcript = {
            let masked_key_params = IDkgTranscriptParams::new(
                random_transcript_id(rng),
                source_dealers.get().clone(),
                source_receivers.get().clone(),
                registry_version,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                IDkgTranscriptOperation::Random,
            )
            .expect("failed to create random IDkgTranscriptParams");
            let masked_key_transcript = source_subnet_nodes
                .run_idkg_and_create_and_verify_transcript(&masked_key_params, rng);
            let unmasked_params = build_params_from_previous(
                masked_key_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
                rng,
            );
            source_subnet_nodes.run_idkg_and_create_and_verify_transcript(&unmasked_params, rng)
        };

        let reshare_params = IDkgTranscriptParams::new(
            random_transcript_id(rng),
            source_receivers.get().clone(),
            target_subnet_nodes.ids(),
            source_key_transcript.registry_version,
            source_key_transcript.algorithm_id,
            IDkgTranscriptOperation::ReshareOfUnmasked(source_key_transcript),
        )
        .expect("invalid reshare of unmasked parameters");

        let nodes_involved_in_resharing: Nodes = source_subnet_nodes
            .into_receivers(&source_receivers)
            .chain(target_subnet_nodes.into_iter())
            .collect();
        let initial_dealings = {
            let signed_dealings = nodes_involved_in_resharing
                .load_previous_transcripts_and_create_signed_dealings(&reshare_params);
            let mut signed_dealings_vec = signed_dealings.into_values().collect::<Vec<_>>();
            if corrupt_first_dealing {
                if let Some(first_signed_dealing) = signed_dealings_vec.first_mut() {
                    let corrupted_sig = {
                        let mut sig_clone =
                            first_signed_dealing.signature.signature.get_ref().clone();
                        sig_clone.0.push(0xff);
                        BasicSigOf::new(sig_clone)
                    };
                    first_signed_dealing.signature.signature = corrupted_sig;
                }
            }

            InitialIDkgDealings::new(reshare_params.clone(), signed_dealings_vec)
                .expect("should create initial dealings")
        };
        (initial_dealings, reshare_params)
    }
}

mod open_transcript {
    use super::*;

    #[test]
    fn should_open_transcript_successfully() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let result = opener.open_transcript(&transcript, complainer.id(), &complaint);
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn should_fail_open_transcript_with_invalid_share() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener = complainer; // opener's share is invalid
        let result = opener.open_transcript(&transcript, opener.id(), &complaint);
        assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
            if internal_error.contains("InvalidCommitment"));
    }

    #[test]
    fn should_fail_open_transcript_when_missing_a_dealing() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        // Remove the corrupted dealing from the transcript.
        transcript.verified_dealings.remove(
            &transcript
                .index_for_dealer_id(complaint.dealer_id)
                .expect("Missing dealer of corrupted dealing"),
        );

        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);
        let result = opener.open_transcript(&transcript, complainer.id(), &complaint);
        assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
            if internal_error.contains("MissingDealing"));
    }

    #[test]
    fn should_fail_open_transcript_with_an_invalid_complaint() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, mut complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        // Set "wrong" dealer_id in the complaint
        complaint.dealer_id =
            random_dealer_id_excluding(&transcript, complaint.dealer_id, &mut rng);

        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);
        let result = opener.open_transcript(&transcript, complainer.id(), &complaint);
        assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
            if internal_error.contains("InvalidComplaint"));
    }

    #[test]
    fn should_fail_open_transcript_with_a_valid_complaint_but_wrong_transcript() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);

        // Create another environment of the same size, and generate a transcript for it.
        let env_2 = CanisterThresholdSigTestEnvironment::new(env.nodes.len(), &mut rng);
        let (dealers_2, receivers_2) =
            env_2.choose_dealers_and_receivers(&IDkgParticipants::Random, &mut rng);
        let params_2 = env_2.params_for_random_sharing(
            &dealers_2,
            &receivers_2,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let transcript_2 = &env_2
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params_2, &mut rng);

        // Try `open_transcript` but with a wrong transcript.
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);
        let result = opener.open_transcript(transcript_2, complainer.id(), &complaint);
        assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
            if internal_error.contains("InvalidArgumentMismatchingTranscriptIDs"));
    }
}

mod verify_opening {
    use super::*;

    #[test]
    fn should_verify_opening_successfully() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let opening = opener
            .open_transcript(&transcript, complainer.id(), &complaint)
            .expect("Unexpected failure of open_transcript");
        let verifier = env.nodes.random_receiver(&transcript.receivers, &mut rng);
        let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_transcript_id_in_opening() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let mut opening = opener
            .open_transcript(&transcript, complainer.id(), &complaint)
            .expect("Unexpected failure of open_transcript");
        let wrong_transcript_id = dummy_idkg_transcript_id_for_tests(1);
        assert_ne!(
            opening.transcript_id, wrong_transcript_id,
            "Unexpected collision with a random transcript_id"
        );
        opening.transcript_id = wrong_transcript_id;
        let verifier = env.nodes.random_receiver(&transcript.receivers, &mut rng);
        let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
        assert_matches!(result, Err(IDkgVerifyOpeningError::TranscriptIdMismatch));
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_transcript_id_in_complaint() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, mut complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let opening = opener
            .open_transcript(&transcript, complainer.id(), &complaint)
            .expect("Unexpected failure of open_transcript");
        let wrong_transcript_id = dummy_idkg_transcript_id_for_tests(1);
        assert_ne!(
            complaint.transcript_id, wrong_transcript_id,
            "Unexpected collision with a random transcript_id"
        );
        complaint.transcript_id = wrong_transcript_id;
        let verifier = env.nodes.random_receiver(&transcript.receivers, &mut rng);

        let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
        assert_matches!(result, Err(IDkgVerifyOpeningError::TranscriptIdMismatch));
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_dealer_id() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let mut opening = opener
            .open_transcript(&transcript, complainer.id(), &complaint)
            .expect("Unexpected failure of open_transcript");
        opening.dealer_id = random_dealer_id_excluding(&transcript, opening.dealer_id, &mut rng);
        let verifier = env.nodes.random_receiver(&transcript.receivers, &mut rng);

        let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
        assert_matches!(result, Err(IDkgVerifyOpeningError::DealerIdMismatch));
    }

    #[test]
    fn should_fail_verify_opening_when_opener_is_not_a_receiver() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let opening = opener
            .open_transcript(&transcript, complainer.id(), &complaint)
            .expect("Unexpected failure of open_transcript");
        let verifier = env.nodes.random_receiver(&transcript.receivers, &mut rng);
        let wrong_opener_id = node_id(123456789);
        assert!(
            !transcript.receivers.get().contains(&wrong_opener_id),
            "Wrong opener_id unexpectedly in receivers"
        );
        let result = verifier.verify_opening(&transcript, wrong_opener_id, &opening, &complaint);
        assert_matches!(
            result,
            Err(IDkgVerifyOpeningError::MissingOpenerInReceivers { .. })
        );
    }

    #[test]
    fn should_fail_verify_opening_with_corrupted_opening() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let mut opening = opener
            .open_transcript(&transcript, complainer.id(), &complaint)
            .expect("Unexpected failure of open_transcript");
        opening
            .internal_opening_raw
            .truncate(opening.internal_opening_raw.len() - 1);
        let verifier = env.nodes.random_receiver(&transcript.receivers, &mut rng);

        let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
        assert_matches!(result, Err(IDkgVerifyOpeningError::InternalError { .. }));
    }

    #[test]
    fn should_fail_verify_opening_when_dealing_is_missing() {
        let mut rng = reproducible_rng();
        let (env, params, mut transcript) = environment_and_transcript_for_complaint(&mut rng);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, &mut rng);
        let opener =
            env.nodes
                .random_receiver_excluding(complainer, &transcript.receivers, &mut rng);

        let opening = opener
            .open_transcript(&transcript, complainer.id(), &complaint)
            .expect("Unexpected failure of open_transcript");
        let verifier = env.nodes.random_receiver(&transcript.receivers, &mut rng);
        let dealings = transcript.verified_dealings.clone();
        let (dealer_index, _signed_dealing) = dealings
            .iter()
            .find(|(_index, batch_signed_dealing)| {
                batch_signed_dealing.dealer_id() == complaint.dealer_id
            })
            .expect("Inconsistent transcript");
        transcript.verified_dealings.remove(dealer_index);
        let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
        assert_matches!(
            result,
            Err(IDkgVerifyOpeningError::MissingDealingInTranscript { .. })
        );
    }
}

mod reshare_key_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        n_random_node_ids, random_transcript_id, IDkgParticipantsRandom,
    };
    use std::collections::BTreeSet;

    #[test]
    fn should_reshare_initial_dealings_to_another_subnet() {
        let mut rng = reproducible_rng();
        let even_subnet_size = (1..=10)
            .map(|n| n * 2)
            .choose(&mut rng)
            .expect("non-empty iterator");
        let env = CanisterThresholdSigTestEnvironment::new(even_subnet_size, &mut rng);
        let (source_subnet_nodes, target_subnet_nodes) = env
            .nodes
            .partition(|(index, _node)| *index < even_subnet_size / 2);
        assert_eq!(source_subnet_nodes.len(), target_subnet_nodes.len());
        let (source_dealers, source_receivers) = source_subnet_nodes
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let source_key_transcript = {
            let masked_key_params = IDkgTranscriptParams::new(
                random_transcript_id(&mut rng),
                source_dealers.get().clone(),
                source_receivers.get().clone(),
                env.newest_registry_version,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                IDkgTranscriptOperation::Random,
            )
            .expect("failed to create random IDkgTranscriptParams");
            let masked_key_transcript = source_subnet_nodes
                .run_idkg_and_create_and_verify_transcript(&masked_key_params, &mut rng);
            let unmasked_params = build_params_from_previous(
                masked_key_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
                &mut rng,
            );
            source_subnet_nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_params, &mut rng)
        };
        let source_tecdsa_master_public_key =
            get_tecdsa_master_public_key(&source_key_transcript).expect("valid public key");

        let reshare_params = IDkgTranscriptParams::new(
            random_transcript_id(&mut rng),
            source_receivers.get().clone(),
            target_subnet_nodes.ids(),
            source_key_transcript.registry_version,
            source_key_transcript.algorithm_id,
            IDkgTranscriptOperation::ReshareOfUnmasked(source_key_transcript),
        )
        .expect("invalid reshare of unmasked parameters");

        let nodes_involved_in_resharing: Nodes = source_subnet_nodes
            .into_receivers(&source_receivers)
            .chain(target_subnet_nodes.into_iter())
            .collect();
        let initial_dealings = {
            let signed_dealings = nodes_involved_in_resharing
                .load_previous_transcripts_and_create_signed_dealings(&reshare_params);
            let initial_dealings = InitialIDkgDealings::new(
                reshare_params.clone(),
                signed_dealings.into_values().collect::<Vec<_>>(),
            )
            .expect("should create initial dealings");
            assert_eq!(
                nodes_involved_in_resharing
                    .random_receiver(&reshare_params, &mut rng)
                    .verify_initial_dealings(&reshare_params, &initial_dealings),
                Ok(())
            );
            initial_dealings
        };
        let reshared_key_transcript = {
            let dealings = initial_dealings
                .dealings()
                .iter()
                .map(|signed_dealing| {
                    nodes_involved_in_resharing
                        .support_dealing_from_all_receivers(signed_dealing.clone(), &reshare_params)
                })
                .collect();
            nodes_involved_in_resharing
                .random_receiver(&reshare_params, &mut rng)
                .create_transcript_or_panic(&reshare_params, &dealings)
        };
        let target_tecdsa_master_public_key =
            get_tecdsa_master_public_key(&reshared_key_transcript).expect("valid public key");

        assert_eq!(
            source_tecdsa_master_public_key,
            target_tecdsa_master_public_key
        );
    }

    #[test]
    fn should_reshare_key_transcript_to_another_subnet() {
        let mut rng = reproducible_rng();
        let even_subnet_size = (1..=10)
            .map(|n| n * 2)
            .choose(&mut rng)
            .expect("non-empty iterator");
        let env = CanisterThresholdSigTestEnvironment::new(even_subnet_size, &mut rng);
        let (source_subnet_nodes, target_subnet_nodes) = env
            .nodes
            .partition(|(index, _node)| *index < even_subnet_size / 2);
        assert_eq!(source_subnet_nodes.len(), target_subnet_nodes.len());
        let (source_dealers, source_receivers) = source_subnet_nodes
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);

        let source_key_transcript = {
            let masked_key_params = IDkgTranscriptParams::new(
                random_transcript_id(&mut rng),
                source_dealers.get().clone(),
                source_receivers.get().clone(),
                env.newest_registry_version,
                AlgorithmId::ThresholdEcdsaSecp256k1,
                IDkgTranscriptOperation::Random,
            )
            .expect("failed to create random IDkgTranscriptParams");
            let masked_key_transcript = source_subnet_nodes
                .run_idkg_and_create_and_verify_transcript(&masked_key_params, &mut rng);
            let unmasked_params = build_params_from_previous(
                masked_key_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
                &mut rng,
            );
            source_subnet_nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_params, &mut rng)
        };
        let source_tecdsa_master_public_key =
            get_tecdsa_master_public_key(&source_key_transcript).expect("valid public key");

        let reshare_params = IDkgTranscriptParams::new(
            random_transcript_id(&mut rng),
            source_receivers.get().clone(),
            target_subnet_nodes.ids(),
            source_key_transcript.registry_version,
            source_key_transcript.algorithm_id,
            IDkgTranscriptOperation::ReshareOfUnmasked(source_key_transcript),
        )
        .expect("invalid reshare of unmasked parameters");

        let nodes_involved_in_resharing: Nodes = source_subnet_nodes
            .into_receivers(&source_receivers)
            .chain(target_subnet_nodes.into_iter())
            .collect();
        let reshared_key_transcript = nodes_involved_in_resharing
            .run_idkg_and_create_and_verify_transcript(&reshare_params, &mut rng);
        let target_tecdsa_master_public_key =
            get_tecdsa_master_public_key(&reshared_key_transcript).expect("valid public key");

        assert_eq!(
            source_tecdsa_master_public_key,
            target_tecdsa_master_public_key
        );
    }

    #[test]
    fn should_reshare_key_transcript_from_dealers_to_receivers_and_back() {
        let mut rng = ReproducibleRng::new();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);
        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let tecdsa_master_public_key =
            get_tecdsa_master_public_key(&key_transcript).expect("valid public key");

        let new_dealers = receivers.get().clone();
        let new_receivers = dealers.get().clone();
        let reshare_params = IDkgTranscriptParams::new(
            random_transcript_id(&mut rng),
            new_dealers,
            new_receivers,
            key_transcript.registry_version,
            key_transcript.algorithm_id,
            IDkgTranscriptOperation::ReshareOfUnmasked(key_transcript),
        )
        .expect("invalid reshare of unmasked parameters");
        let reshared_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&reshare_params, &mut rng);
        let reshared_tecdsa_master_public_key =
            get_tecdsa_master_public_key(&reshared_key_transcript).expect("valid public key");

        assert_eq!(tecdsa_master_public_key, reshared_tecdsa_master_public_key);
    }

    #[test]
    fn should_reshare_key_transcript_when_new_nodes_added() {
        let mut rng = ReproducibleRng::new();
        let subnet_size = rng.gen_range(1..10);
        let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);
        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let tecdsa_master_public_key =
            get_tecdsa_master_public_key(&key_transcript).expect("valid public key");

        let receivers_with_new_node_ids: BTreeSet<_> = {
            let mut new_receivers = receivers.get().clone();
            let num_new_nodes = rng.gen_range(1..10);
            let new_random_node_ids = n_random_node_ids(num_new_nodes, &mut rng);
            for new_node_id in new_random_node_ids.iter() {
                env.add_node(Node::new(*new_node_id, Arc::clone(&env.registry), &mut rng));
                assert!(new_receivers.insert(*new_node_id));
            }
            env.registry.reload();
            new_receivers
        };

        let reshare_params = IDkgTranscriptParams::new(
            random_transcript_id(&mut rng),
            receivers.get().clone(),
            receivers_with_new_node_ids,
            key_transcript.registry_version,
            key_transcript.algorithm_id,
            IDkgTranscriptOperation::ReshareOfUnmasked(key_transcript),
        )
        .expect("invalid reshare of unmasked parameters");
        let reshared_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&reshare_params, &mut rng);
        let reshared_tecdsa_master_public_key =
            get_tecdsa_master_public_key(&reshared_key_transcript).expect("valid public key");

        assert_eq!(tecdsa_master_public_key, reshared_tecdsa_master_public_key);
    }

    #[test]
    fn should_reshare_key_transcript_when_receivers_removed() {
        let mut rng = ReproducibleRng::new();
        let subnet_size = rng.gen_range(2..10); //at least 2 receivers to be able to remove 1
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, &mut rng);
        let (dealers, receivers) = env
            .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, &mut rng);
        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let tecdsa_master_public_key =
            get_tecdsa_master_public_key(&key_transcript).expect("valid public key");

        let receivers_without_removed_receiver = {
            let num_receivers_to_remove = rng.gen_range(1..=receivers.get().len() - 1);
            let removed_receivers = env
                .nodes
                .receivers(&receivers)
                .choose_multiple(&mut rng, num_receivers_to_remove);
            let mut new_receivers = receivers.get().clone();
            for removed_receiver in removed_receivers.iter() {
                assert!(new_receivers.remove(&removed_receiver.id()));
            }
            new_receivers
        };
        let reshare_params = IDkgTranscriptParams::new(
            random_transcript_id(&mut rng),
            receivers.get().clone(),
            receivers_without_removed_receiver,
            key_transcript.registry_version,
            key_transcript.algorithm_id,
            IDkgTranscriptOperation::ReshareOfUnmasked(key_transcript),
        )
        .expect("invalid reshare of unmasked parameters");
        let reshared_key_transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&reshare_params, &mut rng);
        let reshared_tecdsa_master_public_key =
            get_tecdsa_master_public_key(&reshared_key_transcript).expect("valid public key");

        assert_eq!(tecdsa_master_public_key, reshared_tecdsa_master_public_key);
    }
}

/// Corrupts the dealing by modifying the ciphertext intended for the specified receiver.
fn corrupt_signed_dealing_for_one_receiver(
    dealing_index_to_corrupt: NodeIndex,
    dealings: &mut BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
    receiver_index: NodeIndex,
) {
    let signed_dealing = dealings
        .get_mut(&dealing_index_to_corrupt)
        .unwrap_or_else(|| panic!("Missing dealing at index {:?}", dealing_index_to_corrupt));
    let invalidated_internal_dealing_raw = {
        let mut internal_dealing =
            IDkgDealingInternal::deserialize(&signed_dealing.idkg_dealing().internal_dealing_raw)
                .expect("failed to deserialize internal dealing");
        match internal_dealing.ciphertext {
            MEGaCiphertext::Single(ref mut ctext) => {
                let corrupted_ctext = corrupt_ecc_scalar(&ctext.ctexts[receiver_index as usize]);
                ctext.ctexts[receiver_index as usize] = corrupted_ctext;
            }
            MEGaCiphertext::Pairs(ref mut ctext) => {
                let (ctext_1, ctext_2) = ctext.ctexts[receiver_index as usize].clone();
                let corrupted_ctext_1 = corrupt_ecc_scalar(&ctext_1);
                ctext.ctexts[receiver_index as usize] = (corrupted_ctext_1, ctext_2);
            }
        };
        internal_dealing
            .serialize()
            .expect("failed to serialize internal dealing")
    };
    signed_dealing.content.content.internal_dealing_raw = invalidated_internal_dealing_raw;
}

fn check_dealer_indexes(params: &IDkgTranscriptParams, transcript: &IDkgTranscript) {
    // Transcript should have correct dealer indexes
    for &index in transcript.verified_dealings.keys() {
        let dealer_id = transcript
            .dealer_id_for_index(index)
            .expect("Transcript should return dealer ID for verified dealings");
        assert_eq!(params.dealer_index(dealer_id), Some(index));
        assert_eq!(
            params.dealer_index(dealer_id),
            transcript.index_for_dealer_id(dealer_id)
        )
    }
}

fn corrupt_ecc_scalar(value: &EccScalar) -> EccScalar {
    value
        .add(&EccScalar::one(value.curve_type()))
        .expect("Corruption for testing failed")
}

fn environment_and_transcript_for_complaint<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (
    CanisterThresholdSigTestEnvironment,
    IDkgTranscriptParams,
    IDkgTranscript,
) {
    // need min. 1 non-complaining node, and enough nodes that after
    // removing all but collection threshold # of dealings, at least
    // one dealing remains to corrupt
    const MIN_NUM_NODES: usize = 4;
    // Need at least 1 complainer and 1 non-complaining node
    const MIN_NUM_RECEIVERS: usize = 2;

    let subnet_size = rng.gen_range(MIN_NUM_NODES..10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
    let (dealers, receivers) = env.choose_dealers_and_receivers(
        &IDkgParticipants::RandomWithAtLeast {
            min_num_dealers: MIN_NUM_NODES,
            min_num_receivers: MIN_NUM_RECEIVERS,
        },
        rng,
    );

    let params = env.params_for_random_sharing(
        &dealers,
        &receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        rng,
    );
    let transcript = env
        .nodes
        .run_idkg_and_create_and_verify_transcript(&params, rng);
    (env, params, transcript)
}

fn generate_single_complaint<'a, R: RngCore + CryptoRng>(
    transcript: &mut IDkgTranscript,
    params: &'a IDkgTranscriptParams,
    env: &'a CanisterThresholdSigTestEnvironment,
    rng: &mut R,
) -> (&'a Node, IDkgComplaint) {
    let (complainer, _, mut complaints) = generate_complaints(transcript, 1, params, env, rng);
    (
        complainer,
        complaints.pop().expect("expected one complaint"),
    )
}

fn generate_complaints<'a, R: RngCore + CryptoRng>(
    transcript: &mut IDkgTranscript,
    number_of_complaints: usize,
    params: &'a IDkgTranscriptParams,
    env: &'a CanisterThresholdSigTestEnvironment,
    rng: &mut R,
) -> (&'a Node, Vec<NodeIndex>, Vec<IDkgComplaint>) {
    assert!(
        number_of_complaints > 0,
        "should generate at least one complaint"
    );
    assert!(
        number_of_complaints <= transcript.verified_dealings.len(),
        "cannot generate {} complaints because there are only {} dealings",
        number_of_complaints,
        transcript.verified_dealings.len()
    );

    let dealing_indices_to_corrupt = transcript
        .verified_dealings
        .keys()
        .copied()
        .choose_multiple(rng, number_of_complaints);
    assert_eq!(dealing_indices_to_corrupt.len(), number_of_complaints);

    let complainer = env.nodes.random_receiver(params.receivers(), rng);
    let complainer_index = params
        .receiver_index(complainer.id())
        .unwrap_or_else(|| panic!("Missing receiver {:?}", complainer));
    dealing_indices_to_corrupt
        .iter()
        .for_each(|index_to_corrupt| {
            corrupt_signed_dealing_for_one_receiver(
                *index_to_corrupt,
                &mut transcript.verified_dealings,
                complainer_index,
            )
        });

    let complaints = {
        let complaints = complainer
            .load_transcript(transcript)
            .expect("expected complaints");
        assert_eq!(complaints.len(), number_of_complaints);
        complaints
    };

    (complainer, dealing_indices_to_corrupt, complaints)
}

fn environment_with_sig_inputs<R, S>(
    subnet_size_range: S,
    rng: &mut R,
) -> (
    CanisterThresholdSigTestEnvironment,
    ThresholdEcdsaSigInputs,
    IDkgDealers,
    IDkgReceivers,
)
where
    R: RngCore + CryptoRng,
    S: SampleRange<usize>,
{
    let subnet_size = rng.gen_range(subnet_size_range);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

    let key_transcript = generate_key_transcript(
        &env,
        &dealers,
        &receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        rng,
    );
    let quadruple = generate_presig_quadruple(
        &env,
        &dealers,
        &receivers,
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &key_transcript,
        rng,
    );

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            derivation_path: vec![],
        };

        let hashed_message = rng.gen::<[u8; 32]>();
        let seed = Randomness::from(rng.gen::<[u8; 32]>());

        ThresholdEcdsaSigInputs::new(
            &derivation_path,
            &hashed_message,
            seed,
            quadruple,
            key_transcript,
        )
        .expect("failed to create signature inputs")
    };
    (env, inputs, dealers, receivers)
}
