use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_crypto::CryptoComponentImpl;
use ic_crypto::get_master_public_key_from_transcript;
use ic_crypto_internal_csp::Csp;
use ic_crypto_internal_csp::vault::api::IDkgCreateDealingVaultError;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::test_utils::ComplaintCorrupter;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, IDkgParticipants, IntoBuilder, build_params_from_previous,
    copy_dealing_in_transcript, corrupt_dealings_and_generate_complaints_for_random_complainer,
    corrupt_random_dealing_and_generate_complaint,
    dummy_values::dummy_idkg_transcript_id_for_tests,
    generate_ecdsa_presig_quadruple, generate_initial_dealings, generate_key_transcript,
    generate_tschnorr_protocol_inputs,
    node::{Node, Nodes},
    node_id, random_dealer_id, random_dealer_id_excluding, random_node_id_excluding,
    random_receiver_id, random_receiver_id_excluding, setup_masked_random_params,
    setup_unmasked_random_params, swap_two_dealings_in_transcript,
};
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_interfaces::crypto::IDkgProtocol;
use ic_logger::{new_logger, replica_logger::no_op_logger};
use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaSigInputs;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgOpenTranscriptError,
    IDkgVerifyComplaintError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgDealers, IDkgReceivers, IDkgTranscript, IDkgTranscriptOperation, IDkgTranscriptParams,
    InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::crypto::{AlgorithmId, CryptoError, ExtendedDerivationPath};
use ic_types::{NodeId, Randomness};
use maplit::hashset;
use rand::prelude::*;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;

mod create_dealing {
    use super::*;
    use ic_interfaces::crypto::BasicSigVerifier;

    #[test]
    fn should_create_signed_dealing_with_correct_public_key() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);

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
    }

    #[test]
    fn should_fail_create_dealing_if_registry_missing_mega_pubkey() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..10);
            let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);

            let new_node_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let crypto_not_in_registry = Node::new(new_node_id, Arc::clone(&env.registry), rng);
            env.nodes.insert(crypto_not_in_registry);
            let (dealers, receivers_with_new_node_id) = {
                let (random_dealers, random_receivers) =
                    env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
                let mut receivers_ids = random_receivers.get().clone();
                receivers_ids.insert(new_node_id);
                let receivers_with_new_node_id =
                    IDkgReceivers::new(receivers_ids).expect("valid receivers");
                (random_dealers, receivers_with_new_node_id)
            };
            let params =
                setup_masked_random_params(&env, alg, &dealers, &receivers_with_new_node_id, rng);
            let dealer = env.nodes.random_dealer(&params, rng);

            let result = dealer.create_dealing(&params);
            assert_matches!(result, Err(IDkgCreateDealingError::PublicKeyNotFound { node_id, .. }) if node_id==new_node_id);
        }
    }

    #[test]
    fn should_fail_create_dealing_if_node_isnt_a_dealer() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let bad_dealer_id = random_node_id_excluding(params.dealers().get(), rng);
            let bad_dealer = Node::new(bad_dealer_id, Arc::clone(&env.registry), rng);

            let result = bad_dealer.create_dealing(&params);
            let err = result.unwrap_err();
            assert_matches!(err, IDkgCreateDealingError::NotADealer { node_id } if node_id==bad_dealer_id);
        }
    }

    #[test]
    fn should_fail_create_reshare_dealing_if_transcript_isnt_loaded() {
        let rng = &mut reproducible_rng();
        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);

            let (dealers, receivers) = env
                .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

            let initial_params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let initial_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&initial_params, rng);

            let reshare_params = build_params_from_previous(
                initial_params,
                IDkgTranscriptOperation::ReshareOfMasked(initial_transcript.clone()),
                rng,
            );
            let dealer = env.nodes.random_dealer(&reshare_params, rng);

            // We don't call `load_transcript`...

            let result = dealer.create_dealing(&reshare_params);
            let err = result.unwrap_err();
            assert_matches!(err, IDkgCreateDealingError::SecretSharesNotFound { .. });

            // Now, load the transcript and make sure it succeeds
            dealer.load_transcript_or_panic(&initial_transcript);
            let result = dealer.create_dealing(&reshare_params);
            assert_matches!(result, Ok(_));
        }
    }

    #[test]
    fn should_fail_to_create_dealing_when_kappa_unmasked_not_retained() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) = env
                .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

            let masked_key_params =
                setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let masked_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&masked_key_params, rng);

            let unmasked_key_params = build_params_from_previous(
                masked_key_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
                rng,
            );

            let unmasked_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, rng);

            let unmasked_kappa_params =
                setup_unmasked_random_params(&env, alg, &dealers, &receivers, rng);

            let unmasked_kappa_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_kappa_params, rng);

            let dealer = env.nodes.random_dealer(&unmasked_key_params, rng);

            dealer.load_transcript_or_panic(&masked_key_transcript);
            dealer.load_transcript_or_panic(&unmasked_key_transcript);
            dealer.load_transcript_or_panic(&unmasked_kappa_transcript);

            let reshare_params = build_params_from_previous(
                unmasked_kappa_params,
                IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_kappa_transcript.clone()),
                rng,
            );

            // make sure creating dealings succeeds with all the transcripts
            let result = dealer.create_dealing(&reshare_params);
            assert_matches!(result, Ok(_));

            // Do not include kappa unmasked in retained transcripts
            let active_transcripts = hashset!(masked_key_transcript, unmasked_key_transcript,);
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

    #[test]
    fn should_fail_to_create_dealing_when_reshared_unmasked_key_transcript_not_retained() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) = env
                .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

            let masked_key_params =
                setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let masked_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&masked_key_params, rng);

            let unmasked_key_params = build_params_from_previous(
                masked_key_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
                rng,
            );

            let unmasked_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, rng);

            let reshare_params = build_params_from_previous(
                unmasked_key_params,
                IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_key_transcript.clone()),
                rng,
            );

            let dealer = env.nodes.random_dealer(&reshare_params, rng);
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

    #[test]
    fn should_fail_on_vault_errors() {
        fn setup(
            alg: AlgorithmId,
            err: IDkgCreateDealingVaultError,
            rng: &mut ReproducibleRng,
        ) -> (
            CanisterThresholdSigTestEnvironment,
            IDkgTranscriptParams,
            CryptoComponentImpl<Csp>,
        ) {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (random_dealers, random_receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

            let params =
                setup_masked_random_params(&env, alg, &random_dealers, &random_receivers, rng);

            let vault = Arc::new({
                let mut vault = MockLocalCspVault::new();
                vault
                    .expect_idkg_create_dealing()
                    .times(1)
                    .return_once(move |_, _, _, _, _, _| Err(err));
                vault
            });

            let logger = no_op_logger();
            let metrics = Arc::new(CryptoMetrics::none());

            let csp = Csp::new_from_vault(
                Arc::clone(&vault) as _,
                new_logger!(&logger),
                Arc::clone(&metrics),
            );

            let dealer = CryptoComponentImpl::new_for_test(
                csp,
                vault,
                logger,
                Arc::clone(&env.registry) as _,
                env.nodes.random_dealer(&params, rng).id(),
                Arc::new(CryptoMetrics::none()),
                None,
            );

            (env, params, dealer)
        }

        macro_rules! setup_with_vault_error_and_assert_matches {
            ( $rng:expr_2021, $alg:expr_2021; $vault_error:expr_2021 => $expected_result_pattern:pat if $cond:expr_2021) => {
                let (_env, params, dealer) = setup($alg, $vault_error, $rng);
                assert_matches!(dealer.create_dealing(&params), $expected_result_pattern if $cond);
            };
            ( $rng:expr_2021, $alg:expr_2021; $vault_error:expr_2021 => $expected_result_pattern:pat ) => {
                setup_with_vault_error_and_assert_matches!($rng, $alg; $vault_error => $expected_result_pattern if true);
            };
        }

        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let valid_receiver_index = 0;
            let invalid_receiver_index = 1_000_000;
            let invalid_algorithm_id =
                ic_protobuf::registry::crypto::v1::AlgorithmId::ThresBls12381;

            setup_with_vault_error_and_assert_matches!(
                rng, alg;
                IDkgCreateDealingVaultError::MalformedPublicKey {
                    receiver_index: valid_receiver_index,
                    key_bytes: vec![0, 1, 2, 3],
                } =>
                    Err(IDkgCreateDealingError::MalformedPublicKey {..})
            );

            setup_with_vault_error_and_assert_matches!(
                rng, alg;
                IDkgCreateDealingVaultError::MalformedPublicKey {
                    receiver_index: invalid_receiver_index,
                    key_bytes: vec![0, 1, 2, 3],
                } =>
                    Err(IDkgCreateDealingError::InternalError { internal_error })
                    if internal_error.contains("out of bounds for malformed public key")
            );

            setup_with_vault_error_and_assert_matches!(
                rng, alg;
                IDkgCreateDealingVaultError::UnsupportedAlgorithm(Some(invalid_algorithm_id)) =>
                    Err(IDkgCreateDealingError::UnsupportedAlgorithm { algorithm_id })
                    if algorithm_id == Some(invalid_algorithm_id)
            );

            setup_with_vault_error_and_assert_matches!(
                rng, alg;
                IDkgCreateDealingVaultError::TransientInternalError("oh no!".to_string()) =>
                    Err(IDkgCreateDealingError::TransientInternalError { internal_error })
                    if internal_error == "oh no!"
            );

            setup_with_vault_error_and_assert_matches!(
                rng, alg;
                IDkgCreateDealingVaultError::SerializationError("oh no!".to_string()) =>
                    Err(IDkgCreateDealingError::SerializationError { internal_error })
                    if internal_error == "oh no!"
            );

            setup_with_vault_error_and_assert_matches!(
                rng, alg;
                IDkgCreateDealingVaultError::InternalError("oh no!".to_string()) =>
                    Err(IDkgCreateDealingError::InternalError { internal_error })
                    if internal_error == "oh no!"
            );
        }
    }
}

mod create_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CorruptBytesCollection, setup_masked_random_params,
    };

    #[test]
    fn should_create_transcript() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
            let batch_signed_dealings = env
                .nodes
                .support_dealings_from_all_receivers(signed_dealings, &params);

            let creator = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);
            let result = creator.create_transcript(&params, &batch_signed_dealings);

            assert_matches!(result, Ok(transcript) if transcript.transcript_id == params.transcript_id())
        }
    }

    #[test]
    fn should_fail_create_transcript_without_enough_dealings() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(1..30);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);

            let (dealers, receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let dealings: BTreeMap<NodeId, SignedIDkgDealing> = env
                .nodes
                .filter_by_dealers(&params)
                .take(params.collection_threshold().get() as usize - 1) // NOTE: Not enough!
                .map(|dealer| {
                    let dealing = env.nodes.create_and_verify_signed_dealing(&params, dealer);
                    (dealer.id(), dealing)
                })
                .collect();

            let batch_signed_dealings = env
                .nodes
                .support_dealings_from_all_receivers(dealings.clone(), &params);
            let creator = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            let result = creator.create_transcript(&params, &batch_signed_dealings);

            let err = result.unwrap_err();
            assert_matches!(
                err,
                IDkgCreateTranscriptError::UnsatisfiedCollectionThreshold { threshold, dealing_count }
                if (threshold as usize)==(params.collection_threshold().get() as usize) && dealing_count==dealings.len()
            );
        }
    }

    #[test]
    fn should_fail_create_transcript_with_disallowed_dealer() {
        const MIN_NUM_NODES: usize = 2;
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(MIN_NUM_NODES..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) = env.choose_dealers_and_receivers(
                &IDkgParticipants::RandomWithAtLeast {
                    min_num_dealers: MIN_NUM_NODES,
                    min_num_receivers: 1,
                },
                rng,
            );
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
            let batch_signed_dealings = env
                .nodes
                .support_dealings_from_all_receivers(signed_dealings, &params);

            let params_with_removed_dealer = {
                let mut dealers = params.dealers().get().clone();
                let removed_dealer_id = random_dealer_id(&params, rng);
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
            let creator = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);
            let result =
                creator.create_transcript(&params_with_removed_dealer, &batch_signed_dealings);

            assert_matches!(
                result,
                Err(IDkgCreateTranscriptError::DealerNotAllowed { .. })
            );
        }
    }

    #[test]
    fn should_fail_create_transcript_with_signature_by_disallowed_receiver() {
        const MIN_NUM_NODES: usize = 2; // Need enough to be able to remove one
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(MIN_NUM_NODES..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) = env.choose_dealers_and_receivers(
                &IDkgParticipants::RandomWithAtLeast {
                    min_num_dealers: 1,
                    min_num_receivers: MIN_NUM_NODES,
                },
                rng,
            );

            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
            let batch_signed_dealings = env
                .nodes
                .support_dealings_from_all_receivers(signed_dealings, &params);

            // Remove one of the original receivers from the params
            // so that we have a valid sig on the dealing, but `create_transcript` will not
            // consider them eligible to sign
            let (removed_receiver_id, modified_params) = {
                let mut modified_receivers = params.receivers().get().clone();
                let removed_node_id = random_receiver_id(params.receivers(), rng);
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
                .random_filtered_by_receivers(modified_params.receivers(), rng);
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
    }

    #[test]
    fn should_fail_create_transcript_without_enough_signatures() {
        const MIN_NUM_NODES: usize = 4; // Needs to be enough for >=1 signature
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let subnet_size = rng.random_range(MIN_NUM_NODES..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) = env.choose_dealers_and_receivers(
                &IDkgParticipants::RandomWithAtLeast {
                    min_num_dealers: 1,
                    min_num_receivers: MIN_NUM_NODES,
                },
                rng,
            );

            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let signed_dealings = env.nodes.create_and_verify_signed_dealings(&params);
            let insufficient_supporters: Nodes = env
                .nodes
                .into_filtered_by_receivers(params.receivers())
                .take(params.verification_threshold().get() as usize - 1) // Not enough!
                .collect();

            let insufficient_batch_signed_dealings = insufficient_supporters
                .support_dealings_from_all_receivers(signed_dealings, &params);

            let creator =
                insufficient_supporters.random_filtered_by_receivers(params.receivers(), rng);
            let result = creator.create_transcript(&params, &insufficient_batch_signed_dealings);
            let err = result.unwrap_err();
            assert_matches!(
                err,
                IDkgCreateTranscriptError::UnsatisfiedVerificationThreshold { threshold, signature_count, .. }
                if threshold == params.verification_threshold().get() && signature_count == (threshold as usize - 1)
            );
        }
    }

    #[test]
    fn should_fail_create_transcript_with_all_signatures_bad_in_all_dealings() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let creator = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);
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
    }

    #[test]
    fn should_fail_create_transcript_with_all_signatures_bad_in_one_dealing() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let creator = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);
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
    }

    #[test]
    fn should_fail_create_transcript_with_one_bad_signature_in_one_dealing() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let creator = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);
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

    #[test]
    fn should_fail_create_transcript_on_invalid_encoding_of_transcript_operation() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let masked_params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut masked_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&masked_params, rng);
            let unmasked_params = build_params_from_previous(
                masked_params.clone(),
                IDkgTranscriptOperation::ReshareOfMasked(masked_transcript.clone()),
                rng,
            );
            // invalidate the encoding of transcript
            masked_transcript.internal_transcript_raw = vec![0xFF; 100];
            let invalid_unmasked_params = build_params_from_previous(
                masked_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_transcript.clone()),
                rng,
            );

            let dealings = env
                .nodes
                .load_previous_transcripts_and_create_signed_dealings(&unmasked_params);
            let multisigned_dealings = env
                .nodes
                .support_dealings_from_all_receivers(dealings, &unmasked_params);
            let creator = env
                .nodes
                .filter_by_receivers(&unmasked_params)
                .next()
                .unwrap();

            let result = creator.create_transcript(&invalid_unmasked_params, &multisigned_dealings);

            assert_matches!(
                result,
                Err(IDkgCreateTranscriptError::SerializationError { .. })
            );
        }
    }
}

mod load_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{node::Node, setup_masked_random_params};

    #[test]
    fn should_return_ok_from_load_transcript_if_not_a_receiver() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let not_participating_node_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let not_participating_node =
                Node::new(not_participating_node_id, Arc::clone(&env.registry), rng);

            assert!(
                !transcript
                    .receivers
                    .get()
                    .contains(&not_participating_node_id)
            );
            let result = not_participating_node.load_transcript(&transcript);
            assert_matches!(result, Ok(_));
        }
    }

    #[test]
    fn should_run_load_transcript_successfully_if_already_loaded() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let loader = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            assert_matches!(loader.load_transcript(&transcript), Ok(_));
            assert_matches!(loader.load_transcript(&transcript), Ok(_));
        }
    }

    #[test]
    fn should_load_transcript_without_returning_complaints() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let loader = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            let result = loader.load_transcript(&transcript);

            assert_matches!(result, Ok(complaints) if complaints.is_empty());
        }
    }
}

mod verify_complaint {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        IDkgMode, IDkgModeTestContext, IDkgTestContextForComplaint, setup_masked_random_params,
        to_corrupt_complaint,
    };
    use strum::IntoEnumIterator;

    #[test]
    fn should_verify_complaint() {
        let rng = &mut reproducible_rng();
        for mode in IDkgMode::iter() {
            println!("IDKG mode is {mode:?}");
            let subnet_size = mode.subnet_size_for_complaint(6, rng);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            for alg in all_canister_threshold_algorithms() {
                let context = IDkgModeTestContext::new_for_testing_complaint(mode, &env, rng);
                let IDkgTestContextForComplaint {
                    transcript,
                    complaint,
                    complainer,
                    verifier,
                } = context.setup_outputs_for_complaint(&env, alg, rng);

                let result = verifier.verify_complaint(&transcript, complainer.id(), &complaint);

                assert_eq!(result, Ok(()));
            }
        }
    }

    #[test]
    fn should_return_valid_and_correct_complaints_on_load_transcript_with_invalid_dealings() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let num_of_complaints = rng.random_range(1..=transcript.verified_dealings.len());
            let (complainer, corrupted_dealing_indices, complaints) =
                corrupt_dealings_and_generate_complaints_for_random_complainer(
                    &mut transcript,
                    num_of_complaints,
                    &params,
                    &env,
                    rng,
                );

            for complaint in &complaints {
                assert_eq!(complaint.transcript_id, transcript.transcript_id);
                assert_eq!(
                    env.nodes
                        .random_filtered_by_receivers(params.receivers(), rng)
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
    }

    #[test]
    fn should_fail_to_verify_complaint_against_wrong_complainer_id() {
        const MIN_NUM_NODES: usize = 2; //1 complainer and 1 other receiver
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);

            let wrong_complainer_id =
                random_receiver_id_excluding(params.receivers(), complainer.id(), rng);

            assert_matches!(
                env.nodes
                    .random_filtered_by_receivers(params.receivers(), rng)
                    .verify_complaint(&transcript, wrong_complainer_id, &complaint,),
                Err(IDkgVerifyComplaintError::InvalidComplaint)
            );
        }
    }

    #[test]
    fn should_fail_to_verify_complaint_with_wrong_transcript_id() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(2..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);

            let other_transcript_id =
                setup_masked_random_params(&env, alg, &dealers, &receivers, rng).transcript_id();
            assert_ne!(other_transcript_id, params.transcript_id());
            let complaint = complaint
                .into_builder()
                .with_transcript_id(other_transcript_id)
                .build();

            let result = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng)
                .verify_complaint(&transcript, complainer.id(), &complaint);

            assert_matches!(
                result,
                Err(IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs)
            );
        }
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
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            assert!(params.collection_threshold().get() >= 2);
            let num_of_dealings_to_corrupt = 2;

            let (complainer, _, complaints) =
                corrupt_dealings_and_generate_complaints_for_random_complainer(
                    &mut transcript,
                    num_of_dealings_to_corrupt,
                    &params,
                    &env,
                    rng,
                );
            let complainer_id = complainer.id();

            let mut complaint_1 = complaints.first().unwrap().clone();
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
        let rng = &mut reproducible_rng();
        let num_of_dealings_to_corrupt = 2;
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            assert!(params.collection_threshold().get() as usize >= num_of_dealings_to_corrupt);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let (complainer, _, complaints) =
                corrupt_dealings_and_generate_complaints_for_random_complainer(
                    &mut transcript,
                    num_of_dealings_to_corrupt,
                    &params,
                    &env,
                    rng,
                );
            let complainer_id = complainer.id();

            let mut complaint_1 = complaints.first().unwrap().clone();
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

    #[test]
    fn should_fail_to_verify_corrupt_complaint() {
        use strum::IntoEnumIterator;
        const MIN_NUM_NODES: usize = 2; //1 complainer and 1 other receiver
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            for complaint_corrupter in ComplaintCorrupter::iter() {
                let corrupt_complaint = to_corrupt_complaint(&complaint, &complaint_corrupter);
                assert_matches!(
                    env.nodes
                        .random_filtered_by_receivers(params.receivers(), rng)
                        .verify_complaint(&transcript, complainer.id(), &corrupt_complaint),
                    Err(IDkgVerifyComplaintError::InvalidComplaint),
                    "failed for {complaint_corrupter:?}"
                );
            }
        }
    }
}

mod verify_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CorruptBytes, IntoBuilder, setup_masked_random_params,
    };

    #[test]
    fn should_run_idkg_successfully_for_random_dealing() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);

        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            // Transcript should have correct dealer indexes
            check_dealer_indexes(&params, &transcript);
        }
    }

    #[test]
    fn should_run_idkg_successfully_for_reshare_of_random_dealing() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let initial_params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let initial_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&initial_params, rng);

            // Initial transcript should have correct dealer indexes
            check_dealer_indexes(&initial_params, &initial_transcript);

            let reshare_params = build_params_from_previous(
                initial_params,
                IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
                rng,
            );
            let reshare_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);

            // Reshare transcript should have correct dealer indexes
            check_dealer_indexes(&reshare_params, &reshare_transcript);
        }
    }

    #[test]
    fn should_run_idkg_successfully_for_reshare_of_unmasked_dealing() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let initial_params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let initial_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&initial_params, rng);

            // Initial transcript should have correct dealer indexes
            check_dealer_indexes(&initial_params, &initial_transcript);

            let unmasked_params = build_params_from_previous(
                initial_params,
                IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
                rng,
            );
            let unmasked_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_params, rng);

            let reshare_params = build_params_from_previous(
                unmasked_params,
                IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
                rng,
            );
            let reshare_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);

            check_dealer_indexes(&reshare_params, &reshare_transcript);
        }
    }

    #[test]
    fn should_run_idkg_successfully_for_multiplication_of_dealings() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let masked_params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let masked_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&masked_params, rng);

            // Masked transcript should have correct dealer indexes
            check_dealer_indexes(&masked_params, &masked_transcript);

            let unmasked_transcript = {
                let masked_random_params =
                    setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
                let masked_random_transcript = env
                    .nodes
                    .run_idkg_and_create_and_verify_transcript(&masked_random_params, rng);

                let unmasked_params = build_params_from_previous(
                    masked_random_params,
                    IDkgTranscriptOperation::ReshareOfMasked(masked_random_transcript),
                    rng,
                );
                let unmasked_transcript = env
                    .nodes
                    .run_idkg_and_create_and_verify_transcript(&unmasked_params, rng);

                // Unmasked transcript should have correct dealer indexes
                check_dealer_indexes(&unmasked_params, &unmasked_transcript);

                unmasked_transcript
            };

            let multiplication_params = build_params_from_previous(
                masked_params,
                IDkgTranscriptOperation::UnmaskedTimesMasked(
                    unmasked_transcript,
                    masked_transcript,
                ),
                rng,
            );
            let multiplication_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&multiplication_params, rng);

            // Multiplication transcript should have correct dealer indexes
            check_dealer_indexes(&multiplication_params, &multiplication_transcript);
        }
    }

    #[test]
    fn should_include_the_expected_number_of_dealings_in_a_transcript() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let random_params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let random_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&random_params, rng);

            assert_eq!(
                random_transcript.verified_dealings.len(),
                random_params.collection_threshold().get() as usize
            );

            let unmasked_params = build_params_from_previous(
                random_params.clone(),
                IDkgTranscriptOperation::ReshareOfMasked(random_transcript.clone()),
                rng,
            );
            let unmasked_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_params, rng);

            assert_eq!(
                unmasked_transcript.verified_dealings.len(),
                unmasked_params.collection_threshold().get() as usize
            );

            let reshare_params = build_params_from_previous(
                unmasked_params,
                IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript.clone()),
                rng,
            );
            let reshare_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);

            assert_eq!(
                reshare_transcript.verified_dealings.len(),
                reshare_params.collection_threshold().get() as usize
            );

            let multiplication_params = build_params_from_previous(
                random_params,
                IDkgTranscriptOperation::UnmaskedTimesMasked(
                    unmasked_transcript,
                    random_transcript,
                ),
                rng,
            );
            let multiplication_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&multiplication_params, rng);

            assert_eq!(
                multiplication_transcript.verified_dealings.len(),
                multiplication_params.collection_threshold().get() as usize
            );
        }
    }

    #[test]
    fn should_create_quadruple_successfully_with_new_key() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            generate_ecdsa_presig_quadruple(&env, &dealers, &receivers, alg, &key_transcript, rng);
        }
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
        let rng = &mut reproducible_rng();

        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let dealers = env
                .nodes
                .filter_by_dealers(&params)
                .take(params.collection_threshold().get() as usize)
                .choose_multiple(rng, 2);

            let transcript =
                swap_two_dealings_in_transcript(&params, transcript, &env, dealers[0], dealers[1]);

            let r = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r, Ok(()));
        }
    }

    #[test]
    fn should_verify_transcript_reject_reshared_transcript_with_a_duplicated_dealing() {
        const MIN_NUM_NODES: usize = 4;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let masked_key_params =
                setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let masked_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&masked_key_params, rng);

            let params = build_params_from_previous(
                masked_key_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
                rng,
            );

            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let dealers = env
                .nodes
                .filter_by_dealers(&params)
                .take(params.collection_threshold().get() as usize)
                .choose_multiple(rng, 2);

            let transcript =
                copy_dealing_in_transcript(&params, transcript, &env, dealers[0], dealers[1]);

            let r = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r, Err(IDkgVerifyTranscriptError::InvalidTranscript));
        }
    }

    #[test]
    fn should_verify_transcript_reject_random_transcript_with_dealing_replaced() {
        const MIN_NUM_NODES: usize = 4;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let dealers = env
                .nodes
                .filter_by_dealers(&params)
                .take(params.collection_threshold().get() as usize)
                .choose_multiple(rng, 2);
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

            let verified_dealings = Arc::get_mut(&mut transcript.verified_dealings)
                .expect("No other refs to verified_dealings");

            assert!(verified_dealings.insert(dealer1_idx, dealing).is_some());

            let r = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r, Err(IDkgVerifyTranscriptError::InvalidTranscript));
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_insufficient_dealings() {
        const MIN_NUM_NODES: usize = 4;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let dealings_to_remove = 1
                + (transcript.verified_dealings.len()
                    - params.collection_threshold().get() as usize);

            let transcript = transcript
                .into_builder()
                .remove_some_dealings(dealings_to_remove)
                .build();

            assert!(
                transcript.verified_dealings.len() < params.collection_threshold().get() as usize
            );

            let r = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r, Err(IDkgVerifyTranscriptError::InvalidArgument(msg))
                            if msg.starts_with("failed to verify transcript against params: insufficient number of dealings"));
        }
    }

    #[test]
    fn should_fail_on_invalid_encoding_of_transcript_operation() {
        const MIN_NUM_NODES: usize = 4;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let masked_key_params =
                setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

            let mut masked_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&masked_key_params, rng);

            let params = build_params_from_previous(
                masked_key_params.clone(),
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
                rng,
            );

            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            // invalidate the internal transcript
            masked_key_transcript.internal_transcript_raw = vec![0xF; 100];

            let invalid_params = IDkgTranscriptParams::new(
                params.transcript_id(),
                masked_key_params.dealers().get().clone(),
                masked_key_params.receivers().get().clone(),
                masked_key_params.registry_version(),
                masked_key_params.algorithm_id(),
                IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
            )
            .expect("failed to create resharing/multiplication IDkgTranscriptParams");

            let result = env
                .nodes
                .random_filtered_by_receivers(invalid_params.receivers(), rng)
                .verify_transcript(&invalid_params, &transcript);

            assert_matches!(
                result, Err(IDkgVerifyTranscriptError::InvalidArgument(internal_error))
                if internal_error.starts_with("failed to convert transcript operation to internal counterpart")
            );
        }
    }

    fn setup_for_verify_transcript_with_min_num_receivers(
        alg: AlgorithmId,
        rng: &mut ReproducibleRng,
        subnet_size: usize,
        min_num_receivers: usize,
    ) -> (
        CanisterThresholdSigTestEnvironment,
        IDkgTranscriptParams,
        IDkgTranscript,
    ) {
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers,
            },
            rng,
        );

        let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);

        let transcript = env
            .nodes
            .run_idkg_and_create_and_verify_transcript(&params, rng);

        (env, params, transcript)
    }

    fn setup_for_verify_transcript(
        alg: AlgorithmId,
        rng: &mut ReproducibleRng,
        subnet_size: usize,
    ) -> (
        CanisterThresholdSigTestEnvironment,
        IDkgTranscriptParams,
        IDkgTranscript,
    ) {
        setup_for_verify_transcript_with_min_num_receivers(alg, rng, subnet_size, 1)
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_corrupted_internal_data() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(4..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let transcript = transcript
                .into_builder()
                .corrupt_internal_transcript_raw(rng)
                .build();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            // Since the corruption is randomized, we might corrupt the CBOR or the commitments
            // and thus different errors may result
            match r {
                Err(IDkgVerifyTranscriptError::InvalidTranscript) => {}

                Err(IDkgVerifyTranscriptError::SerializationError(msg)) => {
                    assert!(msg.starts_with("failed to deserialize internal transcript"))
                }
                Err(e) => panic!("Unexpected error {e:?}"),
                Ok(()) => panic!("Unexpected success"),
            }
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_wrong_transcript_id() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(4..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let transcript = transcript.into_builder().corrupt_transcript_id().build();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r,
                            Err(IDkgVerifyTranscriptError::InvalidArgument(e))
                            if e.contains("mismatching transcript IDs in transcript"));
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_insufficient_dealing_signatures() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(4..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let verification_threshold = params.verification_threshold().get() as usize;
            let verified_dealings = Arc::get_mut(&mut transcript.verified_dealings)
                .expect("No other refs to verified_dealings");
            let random_batchsigneddealing_signature_batch = &mut verified_dealings
                .values_mut()
                .choose(rng)
                .expect("empty verified dealings")
                .signature
                .signatures_map;

            *random_batchsigneddealing_signature_batch = random_batchsigneddealing_signature_batch
                .clone()
                .into_iter()
                .choose_multiple(rng, verification_threshold - 1)
                .into_iter()
                .collect();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r,
                Err(IDkgVerifyTranscriptError::InvalidArgument(e))
                if e.contains(&format!("insufficient number of signers ({}<{verification_threshold})", verification_threshold - 1))
            );
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_corrupted_dealing_signature() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let verified_dealings = Arc::get_mut(&mut transcript.verified_dealings)
                .expect("No other refs to verified_dealings");
            let some_sig_in_some_dealing = verified_dealings
                .values_mut()
                .choose(rng)
                .expect("empty verified dealings")
                .signature
                .signatures_map
                .values_mut()
                .choose(rng)
                .expect("empty signatures_map");

            *some_sig_in_some_dealing = some_sig_in_some_dealing.clone_with_bit_flipped();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(
                r,
                Err(IDkgVerifyTranscriptError::InvalidDealingSignatureBatch { error, .. })
                if error.contains("Invalid basic signature batch")
            );
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_wrong_registry_version() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(4..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let transcript = transcript.into_builder().corrupt_registry_version().build();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r,
                            Err(IDkgVerifyTranscriptError::InvalidArgument(e))
                            if e.contains("mismatching registry versions in transcript"));
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_wrong_algorithm_id() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(4..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let transcript = transcript.into_builder().corrupt_algorithm_id().build();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r,
                            Err(IDkgVerifyTranscriptError::InvalidArgument(e))
                            if e.contains("mismatching algorithm IDs in transcript"));
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_an_extra_receiver() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(4..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let transcript = transcript.into_builder().add_a_new_receiver().build();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r,
                            Err(IDkgVerifyTranscriptError::InvalidArgument(e))
                            if e.contains("mismatching receivers in transcript"));
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_a_missing_receiver() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(6..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, transcript) =
                setup_for_verify_transcript_with_min_num_receivers(alg, rng, subnet_size, 2);

            let transcript = transcript.into_builder().remove_a_receiver().build();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r,
                            Err(IDkgVerifyTranscriptError::InvalidArgument(e))
                            if e.contains("mismatching receivers in transcript"));
        }
    }

    #[test]
    fn should_verify_transcript_reject_transcript_with_wrong_transcript_type() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(4..10);

        for alg in all_canister_threshold_algorithms() {
            let (env, params, transcript) = setup_for_verify_transcript(alg, rng, subnet_size);

            let transcript = transcript.into_builder().corrupt_transcript_type().build();

            let r = env
                .nodes
                .random_node(rng)
                .verify_transcript(&params, &transcript);

            assert_matches!(r,
                            Err(IDkgVerifyTranscriptError::InvalidArgument(e))
                            if e.contains("failed to verify transcript against params: transcript's type"));
        }
    }
}

mod retain_active_transcripts {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn should_be_nop_when_transcripts_empty() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let retainer = env.nodes.random_node(rng);
        let public_keys_before_retaining = retainer.current_node_public_keys().unwrap();
        assert!(
            public_keys_before_retaining
                .idkg_dealing_encryption_public_key
                .is_some()
        );

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
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);

            let retainer = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            let active_transcripts = hashset!(transcript);
            assert_eq!(
                retainer.retain_active_transcripts(&active_transcripts),
                Ok(())
            );
        }
    }
}

mod load_transcript_with_openings {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::generate_and_verify_openings_for_complaint;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;

    #[test]
    fn should_load_transcript_without_openings_when_none_required() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let loader = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);
            let openings = BTreeMap::new();

            let result = loader.load_transcript_with_openings(&transcript, &openings);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_return_ok_immediately_if_receiver_id_is_not_in_receivers() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            // the loader with the id that is not in the receivers
            let node_id_not_in_receivers = loop {
                let node_id = NodeId::from(PrincipalId::new_node_test_id(rng.r#gen()));
                if !params.receivers().contains(node_id) {
                    break node_id;
                }
            };
            let vault = Arc::new(MockLocalCspVault::new());
            let logger = no_op_logger();
            let metrics = Arc::new(CryptoMetrics::none());
            let csp = Csp::new_from_vault(
                Arc::clone(&vault) as _,
                new_logger!(&logger),
                Arc::clone(&metrics),
            );
            let loader = CryptoComponentImpl::new_for_test(
                csp,
                vault,
                logger,
                Arc::clone(&env.registry) as _,
                node_id_not_in_receivers,
                metrics,
                None,
            );

            env.nodes
                .random_filtered_by_receivers(params.receivers(), rng);
            let openings = BTreeMap::new();

            let result = loader.load_transcript_with_openings(&transcript, &openings);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_load_with_enough_openings() {
        const MIN_NUM_NODES: usize = 2;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            rng,
        );
        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let reconstruction_threshold =
                usize::try_from(transcript.reconstruction_threshold().get())
                    .expect("invalid number");
            let number_of_openings = reconstruction_threshold;

            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
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
    }

    // In a scenario with a cheating dealer but when other parties have enough
    // valid dealings, all honest parties must be able to reconstruct their
    // dealings from the openings and successfully `sign_share` with threshold ECDSA.
    #[test]
    fn should_ecdsa_sign_share_when_loaded_with_openings() {
        use ic_interfaces::crypto::{ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
        const MIN_NUM_NODES: usize = 2;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let random_sharing_params =
                setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let random_sharing_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&random_sharing_params, rng);
            let unmasked_key_params = build_params_from_previous(
                random_sharing_params,
                IDkgTranscriptOperation::ReshareOfMasked(random_sharing_transcript),
                rng,
            );
            let mut key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, rng);
            let reconstruction_threshold =
                usize::try_from(key_transcript.reconstruction_threshold().get())
                    .expect("invalid number");
            let number_of_openings = reconstruction_threshold;

            let (complainer, complaint) = corrupt_random_dealing_and_generate_complaint(
                &mut key_transcript,
                &unmasked_key_params,
                &env,
                rng,
            );
            let complaint_with_openings = generate_and_verify_openings_for_complaint(
                number_of_openings,
                &key_transcript,
                &env,
                complainer,
                complaint,
            );
            complainer
                .load_transcript_with_openings(&key_transcript, &complaint_with_openings)
                .expect("failed to load transcript with openings");
            let quadruple = generate_ecdsa_presig_quadruple(
                &env,
                &dealers,
                &receivers,
                alg,
                &key_transcript,
                rng,
            );
            let caller = PrincipalId::new_user_test_id(1);
            let derivation_path = vec![];

            let hashed_message = rng.r#gen::<[u8; 32]>();
            let seed = rng.r#gen::<[u8; 32]>();

            let inputs = ThresholdEcdsaSigInputs::new(
                &caller,
                &derivation_path,
                &hashed_message,
                &seed,
                &quadruple,
                &key_transcript,
            )
            .expect("failed to create signature inputs");

            complainer.load_transcript_or_panic(inputs.presig_quadruple().kappa_unmasked());
            complainer.load_transcript_or_panic(inputs.presig_quadruple().lambda_masked());
            complainer.load_transcript_or_panic(inputs.presig_quadruple().kappa_times_lambda());
            complainer.load_transcript_or_panic(inputs.presig_quadruple().key_times_lambda());

            let sig_result = complainer
                .create_sig_share(&inputs)
                .expect("signing failed");
            let verifier = env
                .nodes
                .random_filtered_by_receivers_excluding(complainer, &receivers, rng);

            verifier
                .verify_sig_share(complainer.id(), &inputs, &sig_result)
                .expect("verification failed");
        }
    }

    // In a scenario with a cheating dealer but when other parties have enough
    // valid dealings, all honest parties must be able to reconstruct their
    // dealings from the openings and successfully `create_sig_share` with
    // threshold Schnorr.
    #[test]
    fn should_schnorr_create_sig_share_when_loaded_with_openings() {
        use ic_interfaces::crypto::{ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner};

        const MIN_NUM_NODES: usize = 2;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);
        for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
            let random_sharing_params =
                setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let random_sharing_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&random_sharing_params, rng);
            let unmasked_key_params = build_params_from_previous(
                random_sharing_params,
                IDkgTranscriptOperation::ReshareOfMasked(random_sharing_transcript),
                rng,
            );
            let mut key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, rng);
            let reconstruction_threshold =
                usize::try_from(key_transcript.reconstruction_threshold().get())
                    .expect("invalid number");
            let number_of_openings = reconstruction_threshold;

            let (complainer, complaint) = corrupt_random_dealing_and_generate_complaint(
                &mut key_transcript,
                &unmasked_key_params,
                &env,
                rng,
            );
            let complaint_with_openings = generate_and_verify_openings_for_complaint(
                number_of_openings,
                &key_transcript,
                &env,
                complainer,
                complaint,
            );
            complainer
                .load_transcript_with_openings(&key_transcript, &complaint_with_openings)
                .expect("failed to load transcript with openings");

            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };
            let message = rng.r#gen::<[u8; 32]>();
            let seed = Randomness::from(rng.r#gen::<[u8; 32]>());

            let taproot_tree_root = {
                if alg == AlgorithmId::ThresholdSchnorrBip340 {
                    let choose = rng.r#gen::<u8>();
                    if choose <= 128 {
                        None
                    } else if choose <= 192 {
                        Some(vec![])
                    } else {
                        Some(rng.r#gen::<[u8; 32]>().to_vec())
                    }
                } else {
                    None
                }
            };

            let inputs = generate_tschnorr_protocol_inputs(
                &env,
                &dealers,
                &receivers,
                &key_transcript,
                &message,
                seed,
                taproot_tree_root.as_deref(),
                &derivation_path,
                alg,
                rng,
            );
            complainer.load_transcript_or_panic(inputs.presig_transcript().blinder_unmasked());

            let sig_result = complainer
                .create_sig_share(&inputs.as_ref())
                .expect("signing failed");
            let verifier = env
                .nodes
                .random_filtered_by_receivers_excluding(complainer, &receivers, rng);

            verifier
                .verify_sig_share(complainer.id(), &inputs.as_ref(), &sig_result)
                .expect("verification failed");
        }
    }

    #[test]
    fn should_fail_because_not_enough_openings() {
        const MIN_NUM_NODES: usize = 2;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            rng,
        );
        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let reconstruction_threshold =
                usize::try_from(transcript.reconstruction_threshold().get())
                    .expect("invalid number");
            let number_of_openings = reconstruction_threshold - 1;

            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
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
    }

    #[test]
    fn should_fail_if_opener_id_not_in_receivers() {
        const MIN_NUM_NODES: usize = 4;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            rng,
        );
        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let reconstruction_threshold =
                usize::try_from(transcript.reconstruction_threshold().get())
                    .expect("invalid number");
            let number_of_openings = reconstruction_threshold;

            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let mut complaint_with_openings = generate_and_verify_openings_for_complaint(
                number_of_openings,
                &transcript,
                &env,
                complainer,
                complaint,
            );

            let (_complaint, openings) = complaint_with_openings
                .iter_mut()
                .next()
                .expect("empty openings");

            let (key_to_replace, opening) = openings
                .first_key_value()
                .map(|(k, o)| (*k, o.clone()))
                .expect("empty openings");
            openings.remove(&key_to_replace);
            openings.insert(NodeId::from(PrincipalId::new_anonymous()), opening);

            let result =
                complainer.load_transcript_with_openings(&transcript, &complaint_with_openings);

            assert_matches!(
                result,
                Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
                if internal_error.contains("invalid opener")
            );
        }
    }

    #[test]
    fn should_fail_if_opening_cannot_be_deserialized() {
        const MIN_NUM_NODES: usize = 4;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            rng,
        );
        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let reconstruction_threshold =
                usize::try_from(transcript.reconstruction_threshold().get())
                    .expect("invalid number");
            let number_of_openings = reconstruction_threshold;

            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let mut complaint_with_openings = generate_and_verify_openings_for_complaint(
                number_of_openings,
                &transcript,
                &env,
                complainer,
                complaint,
            );

            let openings = complaint_with_openings
                .values_mut()
                .next()
                .expect("empty openings");
            let (_opener_id, opening) = openings.iter_mut().next().expect("empty openings");
            // invalidate the opening encoding
            opening.internal_opening_raw = vec![0xFF; 100];

            let result =
                complainer.load_transcript_with_openings(&transcript, &complaint_with_openings);

            assert_matches!(
                result,
                Err(IDkgLoadTranscriptError::SerializationError { internal_error })
                if internal_error.contains("failed to deserialize opening")
            );
        }
    }

    #[test]
    fn should_fail_if_dealer_id_in_complaint_is_not_among_dealers_in_transcript() {
        const MIN_NUM_NODES: usize = 4;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: 1,
                min_num_receivers: MIN_NUM_NODES,
            },
            rng,
        );
        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let mut transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params, rng);
            let reconstruction_threshold =
                usize::try_from(transcript.reconstruction_threshold().get())
                    .expect("invalid number");
            let number_of_openings = reconstruction_threshold;

            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let mut complaint_with_openings = generate_and_verify_openings_for_complaint(
                number_of_openings,
                &transcript,
                &env,
                complainer,
                complaint,
            );

            let (mut complaint, mut openings) = complaint_with_openings
                .first_key_value()
                .map(|(c, o)| (c.clone(), o.clone()))
                .expect("empty openings");
            complaint_with_openings.remove(&complaint);
            complaint.dealer_id = NodeId::from(PrincipalId::new_anonymous());
            for (_opener_id, opening) in openings.iter_mut() {
                opening.dealer_id = NodeId::from(PrincipalId::new_anonymous());
            }
            complaint_with_openings.insert(complaint, openings);

            let result =
                complainer.load_transcript_with_openings(&transcript, &complaint_with_openings);

            assert_matches!(
                result,
                Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
                if internal_error.contains("invalid complaint") && internal_error.contains("not a dealer")
            );
        }
    }
}

mod verify_dealing_private {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{IntoBuilder, setup_masked_random_params};
    use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_metrics::MetricsRegistry;
    use ic_registry_keys::make_crypto_node_key;
    use ic_types::crypto::KeyPurpose::IDkgMEGaEncryption;
    use ic_types::crypto::canister_threshold_sig::error::IDkgVerifyDealingPrivateError;
    use ic_types::registry::RegistryClientError;
    use prost::Message;

    #[test]
    fn should_verify_dealing_private() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer.create_dealing_or_panic(&params);
            let receiver = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            let result = receiver.verify_dealing_private(&params, &signed_dealing);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_verify_dealing_private_with_wrong_signature() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing_with_corrupted_signature = dealer
                .create_dealing_or_panic(&params)
                .into_builder()
                .corrupt_signature()
                .build();
            let receiver = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

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
    }

    #[test]
    fn should_verify_when_dealer_is_also_a_receiver() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let dealer_and_receiver = env.nodes.random_node(rng);
        let (dealers_with_at_least_one_common_node, receivers_with_at_least_one_common_node) = {
            let (dealers, receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
            let mut dealers_ids = dealers.get().clone();
            dealers_ids.insert(dealer_and_receiver.id());
            let mut receivers_ids = receivers.get().clone();
            receivers_ids.insert(dealer_and_receiver.id());
            (
                IDkgDealers::new(dealers_ids).expect("valid dealers"),
                IDkgReceivers::new(receivers_ids).expect("valid receivers"),
            )
        };

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(
                &env,
                alg,
                &dealers_with_at_least_one_common_node,
                &receivers_with_at_least_one_common_node,
                rng,
            );
            let signed_dealing = dealer_and_receiver.create_dealing_or_panic(&params);

            let result = dealer_and_receiver.verify_dealing_private(&params, &signed_dealing);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_fail_on_wrong_transcript_id() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer.create_dealing_or_panic(&params);
            let receiver = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            let result = receiver.verify_dealing_private(
                &params,
                &signed_dealing
                    .into_builder()
                    .corrupt_transcript_id()
                    .build_with_signature(&params, dealer, dealer.id()),
            );

            assert_matches!( result, Err(IDkgVerifyDealingPrivateError::InvalidArgument(reason)) if reason.starts_with("mismatching transcript IDs"));
        }
    }

    #[test]
    fn should_fail_on_wrong_internal_dealing_raw() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer.create_dealing_or_panic(&params);
            let receiver = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            let result = receiver.verify_dealing_private(
                &params,
                &signed_dealing
                    .into_builder()
                    .corrupt_internal_dealing_raw_by_flipping_bit()
                    .build_with_signature(&params, dealer, dealer.id()),
            );

            assert_matches!( result, Err(IDkgVerifyDealingPrivateError::InvalidArgument(reason)) if reason.starts_with("failed to deserialize internal dealing"));
        }
    }

    #[test]
    fn should_fail_if_dealing_signer_id_is_not_a_dealer_id() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer.create_dealing_or_panic(&params);
            let receiver = env
                .nodes
                .random_filtered_by_receivers(params.receivers(), rng);

            let invalid_dealer_id = NodeId::from(PrincipalId::new_anonymous());

            let result = receiver.verify_dealing_private(
                &params,
                &signed_dealing
                    .into_builder()
                    .with_dealer_id(invalid_dealer_id)
                    .build(),
            );

            assert_matches!(
                result,
                Err(IDkgVerifyDealingPrivateError::InvalidArgument(reason))
                if reason.starts_with("failed to determine dealer index: node") &&
                reason.contains("is not a dealer"));
        }
    }

    #[test]
    fn should_fail_on_public_key_registry_error() {
        let rng = &mut reproducible_rng();
        let registry_client_error = RegistryClientError::PollLockFailed {
            error: "oh no!".to_string(),
        };

        for alg in all_canister_threshold_algorithms() {
            let setup =
                Setup::new_with_registry_result(alg, Err(registry_client_error.clone()), rng);

            assert_matches!(
                setup.crypto.verify_dealing_private(&setup.params, &setup.signed_dealing),
                Err(IDkgVerifyDealingPrivateError::RegistryError(error))
                    if error == registry_client_error
            );
        }
    }

    #[test]
    fn should_fail_on_missing_key_in_the_registry() {
        let rng = &mut reproducible_rng();

        let key_not_found = Ok(None);

        for alg in all_canister_threshold_algorithms() {
            let setup = Setup::new_with_registry_result(alg, key_not_found.clone(), rng);

            assert_matches!(
                setup
                    .crypto
                    .verify_dealing_private(&setup.params, &setup.signed_dealing),
                Err(IDkgVerifyDealingPrivateError::PublicKeyNotInRegistry { .. })
            );
        }
    }

    #[test]
    fn should_fail_on_vault_errors() {
        let vault_errors = vec![
            // if mega_keyset_from_sks fails on deserialization of private or public key
            IDkgVerifyDealingPrivateError::InternalError("deserialization error".to_string()),
            // if mega_keyset_from_sks fails because the private key cannot be found
            IDkgVerifyDealingPrivateError::PrivateKeyNotFound,
            // if privately_verify_dealing fails because the algorithm in the params is not supported
            IDkgVerifyDealingPrivateError::InvalidArgument("algorithm not supported".to_string()),
            // if privately_verify returns a CanisterThresholdError (only one as a smoke test here)
            IDkgVerifyDealingPrivateError::InvalidDealing("invalid proof".to_string()),
        ];
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            for vault_error in &vault_errors {
                let setup = Setup::new_with_vault_error(alg, vault_error.clone(), rng);

                assert_matches!(
                    setup.crypto.verify_dealing_private(&setup.params, &setup.signed_dealing),
                    Err(error)
                        if error == *vault_error
                );
            }
        }
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

    struct Setup {
        crypto: CryptoComponentImpl<MockAllCryptoServiceProvider>,
        params: IDkgTranscriptParams,
        signed_dealing: SignedIDkgDealing,
    }

    impl Setup {
        fn new_with_registry_result(
            alg: AlgorithmId,
            registry_result: Result<Option<Vec<u8>>, RegistryClientError>,
            rng: &mut ReproducibleRng,
        ) -> Setup {
            Self::new_with_vault_and_optional_registry_client_result(
                alg,
                MockLocalCspVault::new(),
                Some(registry_result),
                rng,
            )
        }

        fn new_with_vault_error(
            alg: AlgorithmId,
            vault_error: IDkgVerifyDealingPrivateError,
            rng: &mut ReproducibleRng,
        ) -> Setup {
            let mut mock_vault = MockLocalCspVault::new();
            mock_vault
                .expect_idkg_verify_dealing_private()
                .times(1)
                .returning(move |_, _, _, _, _, _| Err(vault_error.clone()));

            Self::new_with_vault_and_optional_registry_client_result(alg, mock_vault, None, rng)
        }

        fn new_with_vault_and_optional_registry_client_result(
            alg: AlgorithmId,
            mock_vault: MockLocalCspVault,
            registry_client_result: Option<Result<Option<Vec<u8>>, RegistryClientError>>,
            rng: &mut ReproducibleRng,
        ) -> Setup {
            let subnet_size = rng.random_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) =
                env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer.create_dealing_or_panic(&params);
            let node_id = *receivers
                .get()
                .first()
                .expect("should contain at least one receiver");

            let mut mock_registry = MockRegistryClient::new();
            match registry_client_result {
                None => {
                    let registry_key = make_crypto_node_key(node_id, IDkgMEGaEncryption);
                    let registry_version = params.registry_version();
                    let idkg_dealing_encryption_public_key_proto =
                        valid_idkg_dealing_encryption_public_key();
                    let mut idkg_dealing_encryption_public_key_bytes = Vec::new();
                    idkg_dealing_encryption_public_key_proto
                        .encode(&mut idkg_dealing_encryption_public_key_bytes)
                        .expect("the public key should encode successfully");
                    mock_registry
                        .expect_get_value()
                        .withf(move |key, version| {
                            key == registry_key.as_str() && version == &registry_version
                        })
                        .return_const(Ok(Some(idkg_dealing_encryption_public_key_bytes)));
                }
                Some(result) => {
                    mock_registry
                        .expect_get_value()
                        .times(1)
                        .return_once(move |_, _| result);
                }
            }
            let registry_client = Arc::new(mock_registry);

            let logger = no_op_logger();
            let metrics = MetricsRegistry::new();
            let crypto_metrics = Arc::new(CryptoMetrics::new(Some(&metrics)));
            let time_source = None;
            let crypto = CryptoComponentImpl::new_for_test(
                MockAllCryptoServiceProvider::new(),
                Arc::new(mock_vault),
                logger,
                registry_client,
                node_id,
                crypto_metrics,
                time_source,
            );

            Setup {
                crypto,
                params,
                signed_dealing,
            }
        }
    }
}

mod verify_dealing_public {
    use super::*;
    use ic_registry_client_helpers::crypto::CryptoRegistry;

    #[test]
    fn should_successfully_verify_random_sharing_dealing_with_valid_input() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);

            let signed_dealing = dealer.create_dealing_or_panic(&params);

            let verifier_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let verifier = TempCryptoComponent::builder()
                .with_registry(Arc::clone(&env.registry) as Arc<_>)
                .with_node_id(verifier_id)
                .with_rng(rng.fork())
                .build();

            let result = verifier.verify_dealing_public(&params, &signed_dealing);
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_fail_verify_dealing_public_with_invalid_signature() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer
                .create_dealing_or_panic(&params)
                .into_builder()
                .corrupt_signature()
                .build();

            let verifier_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let verifier = TempCryptoComponent::builder()
                .with_registry(Arc::clone(&env.registry) as Arc<_>)
                .with_node_id(verifier_id)
                .with_rng(rng.fork())
                .build();

            let result = verifier.verify_dealing_public(&params, &signed_dealing);

            assert_matches!(result,
                            Err(IDkgVerifyDealingPublicError::InvalidSignature { error, .. })
                            if error.contains("Invalid basic signature on signed iDKG dealing from signer")
            );
        }
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_transcript_id() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer
                .create_dealing_or_panic(&params)
                .into_builder()
                .corrupt_transcript_id()
                .build_with_signature(&params, dealer, dealer.id());

            let verifier_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let verifier = TempCryptoComponent::builder()
                .with_registry(Arc::clone(&env.registry) as Arc<_>)
                .with_node_id(verifier_id)
                .with_rng(rng.fork())
                .build();

            let result = verifier.verify_dealing_public(&params, &signed_dealing);

            assert_matches!(
                result,
                Err(IDkgVerifyDealingPublicError::TranscriptIdMismatch)
            );
        }
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_dealer_id() {
        const MIN_NUM_NODES: usize = 2;
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(MIN_NUM_NODES..10); //need at least 2 nodes to have a dealer and another node
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::RandomWithAtLeast {
                min_num_dealers: MIN_NUM_NODES,
                min_num_receivers: 1,
            },
            rng,
        );

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let other_dealer = env
                .nodes
                .filter_by_dealers(&params)
                .find(|node| *node != dealer)
                .expect("not enough nodes");
            let signed_dealing = dealer
                .create_dealing_or_panic(&params)
                .into_builder()
                .with_dealer_id(other_dealer.id())
                .build_with_signature(&params, other_dealer, other_dealer.id());

            let verifier_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let verifier = TempCryptoComponent::builder()
                .with_registry(Arc::clone(&env.registry) as Arc<_>)
                .with_node_id(verifier_id)
                .with_rng(rng.fork())
                .build();

            let result = verifier.verify_dealing_public(&params, &signed_dealing);

            assert_matches!(
                result,
                Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason == "InvalidProof"
            );
        }
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_dealer_index() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);

        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            // We need the signature verification to succeed, so the public key of the valid dealer in
            // the registry needs to be copied to a non-dealer. The subsequent dealer index check will
            // fail (which is what we are testing), since the `NodeId` of the non-dealer is not
            // included in the list of dealers in params.
            let not_a_dealer_node_id = random_node_id_excluding(&env.nodes.ids(), rng);
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

            let verifier_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let verifier = TempCryptoComponent::builder()
                .with_registry(Arc::clone(&env.registry) as Arc<_>)
                .with_node_id(verifier_id)
                .with_rng(rng.fork())
                .build();

            let result = verifier.verify_dealing_public(&params, &signed_dealing);

            assert_matches!(
                result,
                Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason == "No such dealer"
            );
        }
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_internal_dealing_raw() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) = env.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
        for alg in all_canister_threshold_algorithms() {
            let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
            let dealer = env.nodes.random_dealer(&params, rng);
            let signed_dealing = dealer
                .create_dealing_or_panic(&params)
                .into_builder()
                .corrupt_internal_dealing_raw_by_flipping_bit()
                .build_with_signature(&params, dealer, dealer.id());

            let verifier_id = random_node_id_excluding(&env.nodes.ids(), rng);
            let verifier = TempCryptoComponent::builder()
                .with_registry(Arc::clone(&env.registry) as Arc<_>)
                .with_node_id(verifier_id)
                .with_rng(rng.fork())
                .build();

            let result = verifier.verify_dealing_public(&params, &signed_dealing);

            assert_matches!(
                result,
                Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason.starts_with("CanisterThresholdSerializationError")
            );
        }
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
    use ic_crypto_test_utils_canister_threshold_sigs::random_transcript_id;

    #[test]
    fn should_successfully_verify_initial_dealing_from_non_participating_node() {
        let rng = &mut reproducible_rng();
        let num_nodes = rng.random_range(2..10);
        let num_source_subnet = rng.random_range(1..num_nodes);
        let num_destination_subnet = num_nodes - num_source_subnet;
        assert!(
            num_destination_subnet >= 1,
            "number of nodes in destination subnet is less than 1"
        );
        for alg in all_canister_threshold_algorithms() {
            let env = CanisterThresholdSigTestEnvironment::new(num_nodes, rng);
            let external_verifier = Node::new(
                random_node_id_excluding(&env.nodes.ids(), rng),
                Arc::clone(&env.registry),
                rng,
            );
            let (source_subnet_nodes, destination_subnet_nodes) = env
                .nodes
                .partition(|(index, _node)| *index < num_source_subnet);

            let (initial_dealings, reshare_of_unmasked_params) = generate_initial_dealings(
                alg,
                env.newest_registry_version,
                source_subnet_nodes,
                destination_subnet_nodes,
                false,
                rng,
            );

            assert_eq!(
                external_verifier
                    .verify_initial_dealings(&reshare_of_unmasked_params, &initial_dealings),
                Ok(())
            );
        }
    }

    #[test]
    fn should_fail_on_mismatching_transcript_params() {
        let rng = &mut reproducible_rng();
        let num_nodes = rng.random_range(2..10);
        let num_source_subnet = rng.random_range(1..num_nodes);
        let num_destination_subnet = num_nodes - num_source_subnet;
        assert!(
            num_destination_subnet >= 1,
            "number of nodes in destination subnet is less than 1"
        );

        for alg in all_canister_threshold_algorithms() {
            let env = CanisterThresholdSigTestEnvironment::new(num_nodes, rng);
            let verifier = Node::new(
                random_node_id_excluding(&env.nodes.ids(), rng),
                Arc::clone(&env.registry),
                rng,
            );
            let (source_subnet_nodes, destination_subnet_nodes) = env
                .nodes
                .partition(|(index, _node)| *index < num_source_subnet);
            let (initial_dealings, reshare_of_unmasked_params) = generate_initial_dealings(
                alg,
                env.newest_registry_version,
                source_subnet_nodes,
                destination_subnet_nodes,
                false,
                rng,
            );

            let other_params = IDkgTranscriptParams::new(
                random_transcript_id(rng),
                reshare_of_unmasked_params.dealers().get().clone(),
                reshare_of_unmasked_params.receivers().get().clone(),
                env.newest_registry_version,
                alg,
                IDkgTranscriptOperation::Random,
            )
            .expect("failed to create random IDkgTranscriptParams");

            assert_matches!(
                verifier.verify_initial_dealings(&other_params, &initial_dealings),
                Err(IDkgVerifyInitialDealingsError::MismatchingTranscriptParams)
            );
        }
    }

    #[test]
    fn should_fail_if_public_verification_fails() {
        let rng = &mut reproducible_rng();
        let num_nodes = rng.random_range(2..10);
        let num_source_subnet = rng.random_range(1..num_nodes);
        let num_destination_subnet = num_nodes - num_source_subnet;
        assert!(
            num_destination_subnet >= 1,
            "number of nodes in destination subnet is less than 1"
        );

        for alg in all_canister_threshold_algorithms() {
            let env = CanisterThresholdSigTestEnvironment::new(num_nodes, rng);
            let verifier = Node::new(
                random_node_id_excluding(&env.nodes.ids(), rng),
                Arc::clone(&env.registry),
                rng,
            );
            let (source_subnet_nodes, destination_subnet_nodes) = env
                .nodes
                .partition(|(index, _node)| *index < num_source_subnet);
            let (initial_dealings_with_first_corrupted, reshare_of_unmasked_params) =
                generate_initial_dealings(
                    alg,
                    env.newest_registry_version,
                    source_subnet_nodes,
                    destination_subnet_nodes,
                    true,
                    rng,
                );

            let result = verifier.verify_initial_dealings(
                &reshare_of_unmasked_params,
                &initial_dealings_with_first_corrupted,
            );
            assert_matches!(result, Err(IDkgVerifyInitialDealingsError::PublicVerificationFailure { verify_dealing_public_error, ..})
                            if matches!(verify_dealing_public_error, IDkgVerifyDealingPublicError::InvalidSignature { .. })
            );
        }
    }
}

mod open_transcript {
    use super::*;

    #[test]
    fn should_open_transcript_successfully() {
        let rng = &mut reproducible_rng();
        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let result = opener.open_transcript(&transcript, complainer.id(), &complaint);
            assert_matches!(result, Ok(_));
        }
    }

    #[test]
    fn should_fail_open_transcript_with_invalid_share() {
        let rng = &mut reproducible_rng();
        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = complainer; // opener's share is invalid
            let result = opener.open_transcript(&transcript, opener.id(), &complaint);
            assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
                            if internal_error.contains("InvalidCommitment"));
        }
    }

    #[test]
    fn should_fail_open_transcript_when_missing_a_dealing() {
        let rng = &mut reproducible_rng();
        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            // Remove the corrupted dealing from the transcript.
            let corrupted_dealer_index = transcript
                .index_for_dealer_id(complaint.dealer_id)
                .expect("Missing dealer of corrupted dealing");
            let verified_dealings = Arc::get_mut(&mut transcript.verified_dealings)
                .expect("No other refs to verified_dealings");
            verified_dealings.remove(&corrupted_dealer_index);

            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );
            let result = opener.open_transcript(&transcript, complainer.id(), &complaint);
            assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
                            if internal_error.contains("MissingDealing"));
        }
    }

    #[test]
    fn should_fail_open_transcript_with_an_invalid_complaint() {
        let rng = &mut reproducible_rng();
        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, mut complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            // Set "wrong" dealer_id in the complaint
            complaint.dealer_id = random_dealer_id_excluding(&transcript, complaint.dealer_id, rng);

            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );
            let result = opener.open_transcript(&transcript, complainer.id(), &complaint);
            assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
                            if internal_error.contains("InvalidComplaint"));
        }
    }

    #[test]
    fn should_fail_open_transcript_with_a_valid_complaint_but_wrong_transcript() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);

            // Create another environment of the same size, and generate a transcript for it.
            let env_2 = CanisterThresholdSigTestEnvironment::new(env.nodes.len(), rng);
            let (dealers_2, receivers_2) =
                env_2.choose_dealers_and_receivers(&IDkgParticipants::Random, rng);
            let params_2 = setup_masked_random_params(&env_2, alg, &dealers_2, &receivers_2, rng);
            let transcript_2 = &env_2
                .nodes
                .run_idkg_and_create_and_verify_transcript(&params_2, rng);

            // Try `open_transcript` but with a wrong transcript.
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );
            let result = opener.open_transcript(transcript_2, complainer.id(), &complaint);
            assert_matches!(result, Err(IDkgOpenTranscriptError::InternalError { internal_error })
                            if internal_error.contains("InvalidArgumentMismatchingTranscriptIDs"));
        }
    }
}

mod verify_opening {
    use super::*;

    #[test]
    fn should_verify_opening_successfully() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let opening = opener
                .open_transcript(&transcript, complainer.id(), &complaint)
                .expect("Unexpected failure of open_transcript");
            let verifier = env
                .nodes
                .random_filtered_by_receivers(&transcript.receivers, rng);
            let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_transcript_id_in_opening() {
        let rng = &mut reproducible_rng();
        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let mut opening = opener
                .open_transcript(&transcript, complainer.id(), &complaint)
                .expect("Unexpected failure of open_transcript");
            let wrong_transcript_id = dummy_idkg_transcript_id_for_tests(1);
            assert_ne!(
                opening.transcript_id, wrong_transcript_id,
                "Unexpected collision with a random transcript_id"
            );
            opening.transcript_id = wrong_transcript_id;
            let verifier = env
                .nodes
                .random_filtered_by_receivers(&transcript.receivers, rng);
            let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
            assert_matches!(result, Err(IDkgVerifyOpeningError::TranscriptIdMismatch));
        }
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_transcript_id_in_complaint() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, mut complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let opening = opener
                .open_transcript(&transcript, complainer.id(), &complaint)
                .expect("Unexpected failure of open_transcript");
            let wrong_transcript_id = dummy_idkg_transcript_id_for_tests(1);
            assert_ne!(
                complaint.transcript_id, wrong_transcript_id,
                "Unexpected collision with a random transcript_id"
            );
            complaint.transcript_id = wrong_transcript_id;
            let verifier = env
                .nodes
                .random_filtered_by_receivers(&transcript.receivers, rng);

            let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
            assert_matches!(result, Err(IDkgVerifyOpeningError::TranscriptIdMismatch));
        }
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_dealer_id() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let mut opening = opener
                .open_transcript(&transcript, complainer.id(), &complaint)
                .expect("Unexpected failure of open_transcript");
            opening.dealer_id = random_dealer_id_excluding(&transcript, opening.dealer_id, rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(&transcript.receivers, rng);

            let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
            assert_matches!(result, Err(IDkgVerifyOpeningError::DealerIdMismatch));
        }
    }

    #[test]
    fn should_fail_verify_opening_when_opener_is_not_a_receiver() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let opening = opener
                .open_transcript(&transcript, complainer.id(), &complaint)
                .expect("Unexpected failure of open_transcript");
            let verifier = env
                .nodes
                .random_filtered_by_receivers(&transcript.receivers, rng);
            let wrong_opener_id = node_id(123456789);
            assert!(
                !transcript.receivers.contains(wrong_opener_id),
                "Wrong opener_id unexpectedly in receivers"
            );
            let result =
                verifier.verify_opening(&transcript, wrong_opener_id, &opening, &complaint);
            assert_matches!(
                result,
                Err(IDkgVerifyOpeningError::MissingOpenerInReceivers { .. })
            );
        }
    }

    #[test]
    fn should_fail_verify_opening_with_corrupted_opening() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let mut opening = opener
                .open_transcript(&transcript, complainer.id(), &complaint)
                .expect("Unexpected failure of open_transcript");
            opening
                .internal_opening_raw
                .truncate(opening.internal_opening_raw.len() - 1);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(&transcript.receivers, rng);

            let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
            assert_matches!(result, Err(IDkgVerifyOpeningError::InternalError { .. }));
        }
    }

    #[test]
    fn should_fail_verify_opening_when_dealing_is_missing() {
        let rng = &mut reproducible_rng();

        for alg in all_canister_threshold_algorithms() {
            let (env, params, mut transcript) = environment_and_transcript_for_complaint(alg, rng);
            let (complainer, complaint) =
                corrupt_random_dealing_and_generate_complaint(&mut transcript, &params, &env, rng);
            let opener = env.nodes.random_filtered_by_receivers_excluding(
                complainer,
                &transcript.receivers,
                rng,
            );

            let opening = opener
                .open_transcript(&transcript, complainer.id(), &complaint)
                .expect("Unexpected failure of open_transcript");
            let verifier = env
                .nodes
                .random_filtered_by_receivers(&transcript.receivers, rng);

            let dealer_index = transcript
                .verified_dealings
                .iter()
                .find_map(|(index, batch_signed_dealing)| {
                    (batch_signed_dealing.dealer_id() == complaint.dealer_id).then_some(*index)
                })
                .expect("Inconsistent transcript");
            let verified_dealings = Arc::get_mut(&mut transcript.verified_dealings)
                .expect("No other refs to verified_dealings");
            verified_dealings.remove(&dealer_index);
            let result = verifier.verify_opening(&transcript, opener.id(), &opening, &complaint);
            assert_matches!(
                result,
                Err(IDkgVerifyOpeningError::MissingDealingInTranscript { .. })
            );
        }
    }
}

mod reshare_key_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        IDkgParticipantsRandom, n_random_node_ids, random_transcript_id,
    };
    use std::collections::BTreeSet;

    #[test]
    fn should_reshare_initial_dealings_to_another_subnet() {
        let rng = &mut reproducible_rng();
        let total_num_nodes = rng.random_range(2..=20);
        let partition_index = rng.random_range(1..total_num_nodes);

        for alg in all_canister_threshold_algorithms() {
            let env = CanisterThresholdSigTestEnvironment::new(total_num_nodes, rng);
            let (source_subnet_nodes, target_subnet_nodes) = env
                .nodes
                .partition(|(index, _node)| *index < partition_index);
            let (source_dealers, source_receivers) = source_subnet_nodes
                .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);
            let source_key_transcript = {
                let unmasked_key_params = IDkgTranscriptParams::new(
                    random_transcript_id(rng),
                    source_dealers.get().clone(),
                    source_receivers.get().clone(),
                    env.newest_registry_version,
                    alg,
                    IDkgTranscriptOperation::RandomUnmasked,
                )
                .expect("failed to create random IDkgTranscriptParams");
                source_subnet_nodes
                    .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, rng)
            };
            let source_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&source_key_transcript)
                    .expect("valid public key");

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
                .into_filtered_by_receivers(&source_receivers)
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
                        .random_filtered_by_receivers(&reshare_params, rng)
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
                        nodes_involved_in_resharing.support_dealing_from_all_receivers(
                            signed_dealing.clone(),
                            &reshare_params,
                        )
                    })
                    .collect();
                nodes_involved_in_resharing
                    .random_filtered_by_receivers(&reshare_params, rng)
                    .create_transcript_or_panic(&reshare_params, &dealings)
            };
            let target_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&reshared_key_transcript)
                    .expect("valid public key");

            assert_eq!(
                source_tecdsa_master_public_key,
                target_tecdsa_master_public_key
            );
        }
    }

    #[test]
    fn should_reshare_key_transcript_to_another_subnet() {
        let rng = &mut reproducible_rng();
        let total_num_nodes = rng.random_range(2..=20);
        let partition_index = rng.random_range(1..total_num_nodes);

        for alg in all_canister_threshold_algorithms() {
            let env = CanisterThresholdSigTestEnvironment::new(total_num_nodes, rng);
            let (source_subnet_nodes, target_subnet_nodes) = env
                .nodes
                .partition(|(index, _node)| *index < partition_index);
            let (source_dealers, source_receivers) = source_subnet_nodes
                .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);
            let source_key_transcript = {
                let unmasked_key_params = IDkgTranscriptParams::new(
                    random_transcript_id(rng),
                    source_dealers.get().clone(),
                    source_receivers.get().clone(),
                    env.newest_registry_version,
                    alg,
                    IDkgTranscriptOperation::RandomUnmasked,
                )
                .expect("failed to create random IDkgTranscriptParams");
                source_subnet_nodes
                    .run_idkg_and_create_and_verify_transcript(&unmasked_key_params, rng)
            };
            let source_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&source_key_transcript)
                    .expect("valid public key");

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
                .into_filtered_by_receivers(&source_receivers)
                .chain(target_subnet_nodes.into_iter())
                .collect();
            let reshared_key_transcript = nodes_involved_in_resharing
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);
            let target_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&reshared_key_transcript)
                    .expect("valid public key");

            assert_eq!(
                source_tecdsa_master_public_key,
                target_tecdsa_master_public_key
            );
        }
    }

    #[test]
    fn should_reshare_random_unmasked_transcript_to_new_receivers() {
        let rng = &mut reproducible_rng();
        let total_num_nodes = rng.random_range(2..=20);
        let partition_index = rng.random_range(1..total_num_nodes);

        for alg in all_canister_threshold_algorithms() {
            let env = CanisterThresholdSigTestEnvironment::new(total_num_nodes, rng);
            let (source_subnet_nodes, target_subnet_nodes) = env
                .nodes
                .partition(|(index, _node)| *index < partition_index);
            let (source_dealers, source_receivers) = source_subnet_nodes
                .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);
            let source_key_transcript = {
                let key_params = IDkgTranscriptParams::new(
                    random_transcript_id(rng),
                    source_dealers.get().clone(),
                    source_receivers.get().clone(),
                    env.newest_registry_version,
                    alg,
                    IDkgTranscriptOperation::RandomUnmasked,
                )
                .expect("failed to create random IDkgTranscriptParams");
                source_subnet_nodes.run_idkg_and_create_and_verify_transcript(&key_params, rng)
            };
            let source_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&source_key_transcript)
                    .expect("valid public key");

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
                .into_filtered_by_receivers(&source_receivers)
                .chain(target_subnet_nodes.into_iter())
                .collect();
            let reshared_key_transcript = nodes_involved_in_resharing
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);
            let target_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&reshared_key_transcript)
                    .expect("valid public key");

            assert_eq!(
                source_tecdsa_master_public_key,
                target_tecdsa_master_public_key
            );
        }
    }

    #[test]
    fn should_reshare_key_transcript_from_dealers_to_receivers_and_back() {
        let rng = &mut ReproducibleRng::new();
        let subnet_size = rng.random_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let tecdsa_master_public_key =
                get_master_public_key_from_transcript(&key_transcript).expect("valid public key");

            let new_dealers = receivers.get().clone();
            let new_receivers = dealers.get().clone();
            let reshare_params = IDkgTranscriptParams::new(
                random_transcript_id(rng),
                new_dealers,
                new_receivers,
                key_transcript.registry_version,
                key_transcript.algorithm_id,
                IDkgTranscriptOperation::ReshareOfUnmasked(key_transcript),
            )
            .expect("invalid reshare of unmasked parameters");
            let reshared_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);
            let reshared_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&reshared_key_transcript)
                    .expect("valid public key");

            assert_eq!(tecdsa_master_public_key, reshared_tecdsa_master_public_key);
        }
    }

    #[test]
    fn should_reshare_key_transcript_when_new_nodes_added() {
        let rng = &mut ReproducibleRng::new();
        let subnet_size = rng.random_range(1..10);
        let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let tecdsa_master_public_key =
                get_master_public_key_from_transcript(&key_transcript).expect("valid public key");

            let receivers_with_new_node_ids: BTreeSet<_> = {
                let mut new_receivers = receivers.get().clone();
                let num_new_nodes = rng.random_range(1..10);
                let new_random_node_ids = n_random_node_ids(num_new_nodes, rng);
                for new_node_id in new_random_node_ids.iter() {
                    env.add_node(Node::new(*new_node_id, Arc::clone(&env.registry), rng));
                    assert!(new_receivers.insert(*new_node_id));
                }
                env.registry.reload();
                new_receivers
            };

            let reshare_params = IDkgTranscriptParams::new(
                random_transcript_id(rng),
                receivers.get().clone(),
                receivers_with_new_node_ids,
                key_transcript.registry_version,
                key_transcript.algorithm_id,
                IDkgTranscriptOperation::ReshareOfUnmasked(key_transcript),
            )
            .expect("invalid reshare of unmasked parameters");
            let reshared_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);
            let reshared_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&reshared_key_transcript)
                    .expect("valid public key");

            assert_eq!(tecdsa_master_public_key, reshared_tecdsa_master_public_key);
        }
    }

    #[test]
    fn should_reshare_key_transcript_when_receivers_removed() {
        let rng = &mut ReproducibleRng::new();
        let subnet_size = rng.random_range(2..10); //at least 2 receivers to be able to remove 1
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in all_canister_threshold_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let tecdsa_master_public_key =
                get_master_public_key_from_transcript(&key_transcript).expect("valid public key");

            let receivers_without_removed_receiver = {
                let num_receivers_to_remove = rng.random_range(1..=receivers.get().len() - 1);
                let removed_receivers = env
                    .nodes
                    .filter_by_receivers(&receivers)
                    .choose_multiple(rng, num_receivers_to_remove);
                let mut new_receivers = receivers.get().clone();
                for removed_receiver in removed_receivers.iter() {
                    assert!(new_receivers.remove(&removed_receiver.id()));
                }
                new_receivers
            };
            let reshare_params = IDkgTranscriptParams::new(
                random_transcript_id(rng),
                receivers.get().clone(),
                receivers_without_removed_receiver,
                key_transcript.registry_version,
                key_transcript.algorithm_id,
                IDkgTranscriptOperation::ReshareOfUnmasked(key_transcript),
            )
            .expect("invalid reshare of unmasked parameters");
            let reshared_key_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&reshare_params, rng);
            let reshared_tecdsa_master_public_key =
                get_master_public_key_from_transcript(&reshared_key_transcript)
                    .expect("valid public key");

            assert_eq!(tecdsa_master_public_key, reshared_tecdsa_master_public_key);
        }
    }
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

fn environment_and_transcript_for_complaint<R: RngCore + CryptoRng>(
    alg: AlgorithmId,
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

    let subnet_size = rng.random_range(MIN_NUM_NODES..10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
    let (dealers, receivers) = env.choose_dealers_and_receivers(
        &IDkgParticipants::RandomWithAtLeast {
            min_num_dealers: MIN_NUM_NODES,
            min_num_receivers: MIN_NUM_RECEIVERS,
        },
        rng,
    );

    let params = setup_masked_random_params(&env, alg, &dealers, &receivers, rng);
    let transcript = env
        .nodes
        .run_idkg_and_create_and_verify_transcript(&params, rng);
    (env, params, transcript)
}

fn all_canister_threshold_algorithms() -> Vec<AlgorithmId> {
    AlgorithmId::all_threshold_ecdsa_algorithms()
        .into_iter()
        .chain(AlgorithmId::all_threshold_schnorr_algorithms())
        .collect()
}
