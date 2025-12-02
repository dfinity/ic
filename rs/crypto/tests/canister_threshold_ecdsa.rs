use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_crypto::get_master_public_key_from_transcript;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, IDkgParticipants, IntoBuilder,
    ecdsa::environment_with_sig_inputs, ecdsa_sig_share_from_each_receiver,
    generate_ecdsa_presig_quadruple, generate_key_transcript,
    random_crypto_component_not_in_receivers, random_node_id_excluding, random_receiver_id,
    random_receiver_id_excluding, run_tecdsa_protocol,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_utils_canister_threshold_sig::derive_threshold_public_key;
use ic_interfaces::crypto::{IDkgProtocol, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
use ic_types::NodeId;
use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaSigInputs;
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaCreateSigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use ic_types::crypto::{AlgorithmId, ExtendedDerivationPath};
use maplit::hashset;
use rand::prelude::*;
use std::convert::TryFrom;
use std::sync::Arc;

mod sign_share {
    use super::*;
    use proptest::array::uniform5;
    use proptest::prelude::{Strategy, any};
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashSet;

    #[test]
    fn should_create_signature_share_successfully_with_new_key() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
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

            let receiver = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);
            receiver.load_tecdsa_sig_transcripts(&inputs);
            let result = receiver.create_sig_share(&inputs);
            assert_matches!(result, Ok(_));
        }
    }

    #[test]
    fn should_fail_create_signature_if_not_receiver() {
        let rng = &mut reproducible_rng();

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let subnet_size = rng.gen_range(1..10);
            let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
            let (dealers, receivers) = env
                .choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
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

            let bad_signer_id = random_node_id_excluding(inputs.receivers().get(), rng);
            let bad_crypto_component = TempCryptoComponent::builder()
                .with_registry(Arc::clone(&env.registry) as Arc<_>)
                .with_node_id(bad_signer_id)
                .with_rng(rng.fork())
                .build();

            let result = bad_crypto_component.create_sig_share(&inputs);
            let err = result.unwrap_err();
            assert_matches!(err, ThresholdEcdsaCreateSigShareError::NotAReceiver);
        }
    }

    #[test]
    fn should_fail_to_sign_when_input_transcripts_not_retained() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
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

            let receiver = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);
            receiver.load_tecdsa_sig_transcripts(&inputs);
            assert_matches!(receiver.create_sig_share(&inputs), Ok(_));
            let another_key_transcript =
                generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let active_transcripts = hashset!(another_key_transcript);
            assert_eq!(
                receiver.retain_active_transcripts(&active_transcripts),
                Ok(())
            );

            let result = receiver.create_sig_share(&inputs);
            assert_matches!(
                result,
                Err(ThresholdEcdsaCreateSigShareError::SecretSharesNotFound { .. })
            );
        }
    }

    #[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
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
        let rng = &mut reproducible_rng();
        let subnet_size = 4;
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        let caller = PrincipalId::new_user_test_id(1);
        let derivation_path = vec![];

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let hashed_message = rng.r#gen::<[u8; 32]>();
            let seed = rng.r#gen::<[u8; 32]>();

            const CHACHA_SEED_LEN: usize = 32;
            let mut runner = TestRunner::new_with_rng(
                Config::with_cases(10),
                TestRng::from_seed(RngAlgorithm::ChaCha, &rng.r#gen::<[u8; CHACHA_SEED_LEN]>()),
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
                    let key_transcript =
                        generate_key_transcript(&env, &dealers, &receivers, alg, &mut inner_rng);
                    let quadruple = generate_ecdsa_presig_quadruple(
                        &env,
                        &dealers,
                        &receivers,
                        alg,
                        &key_transcript,
                        &mut inner_rng,
                    );

                    let inputs = ThresholdEcdsaSigInputs::new(
                        &caller,
                        &derivation_path,
                        &hashed_message,
                        &seed,
                        &quadruple,
                        &key_transcript,
                    )
                    .expect("failed to create signature inputs");

                    let receiver = env
                        .nodes
                        .random_filtered_by_receivers(inputs.receivers(), &mut inner_rng);
                    receiver.load_tecdsa_sig_transcripts(&inputs);
                    assert_matches!(
                        receiver.create_sig_share(&inputs),
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

                    let result = receiver.create_sig_share(&inputs);

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
                            Err(ThresholdEcdsaCreateSigShareError::SecretSharesNotFound { .. }),
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
}

mod verify_sig_share {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::CorruptBytes;
    use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaSigShare;
    use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaVerifySigShareError;

    #[test]
    fn should_verify_sig_share_successfully() {
        let rng = &mut reproducible_rng();

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let result = verifier.verify_sig_share(signer_id, &inputs.as_ref(), &sig_share);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_fail_verifying_inputs_with_wrong_hashed_message() {
        let rng = &mut reproducible_rng();

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let inputs_with_wrong_hash = inputs
                .clone()
                .into_builder()
                .corrupt_hashed_message()
                .build();
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let result =
                verifier.verify_sig_share(signer_id, &inputs_with_wrong_hash.as_ref(), &sig_share);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
            );
        }
    }

    #[test]
    fn should_fail_verifying_inputs_with_wrong_nonce() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let inputs_with_wrong_nonce = inputs.clone().into_builder().corrupt_nonce().build();
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let result =
                verifier.verify_sig_share(signer_id, &inputs_with_wrong_nonce.as_ref(), &sig_share);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
            );
        }
    }

    #[test]
    fn should_fail_verifying_corrupted_sig_share() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let (signer_id, corrupted_sig_share) = {
                let (signer_id, sig_share) =
                    signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
                (signer_id, sig_share.clone_with_bit_flipped())
            };
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let result =
                verifier.verify_sig_share(signer_id, &inputs.as_ref(), &corrupted_sig_share);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
            );
        }
    }

    #[test]
    fn should_verify_sig_share_from_another_signer_when_threshold_1() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(2..=3, alg, rng);
            assert_eq!(inputs.key_transcript().reconstruction_threshold().get(), 1);
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            let other_signer_id = random_receiver_id_excluding(inputs.receivers(), signer_id, rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let result = verifier.verify_sig_share(other_signer_id, &inputs.as_ref(), &sig_share);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_fail_verifying_sig_share_from_another_signer() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(4..10, alg, rng);
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            let other_signer_id = random_receiver_id_excluding(inputs.receivers(), signer_id, rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let result = verifier.verify_sig_share(other_signer_id, &inputs.as_ref(), &sig_share);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifySigShareError::InvalidSignatureShare)
            );
        }
    }

    #[test]
    fn should_fail_verifying_sig_share_for_unknown_signer() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            let unknown_signer_id = NodeId::from(PrincipalId::new_node_test_id(1));
            assert_ne!(signer_id, unknown_signer_id);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let result = verifier.verify_sig_share(unknown_signer_id, &inputs.as_ref(), &sig_share);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifySigShareError::InvalidArgumentMissingSignerInTranscript {signer_id})
                    if signer_id == unknown_signer_id
            );
        }
    }

    #[test]
    fn should_fail_deserializing_invalid_sig_share() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);
            let signer_id = random_receiver_id(inputs.receivers(), rng);
            let invalid_sig_share = ThresholdEcdsaSigShare {
                sig_share_raw: Vec::new(),
            };

            let result = verifier.verify_sig_share(signer_id, &inputs.as_ref(), &invalid_sig_share);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifySigShareError::SerializationError { .. })
            )
        }
    }

    #[test]
    fn should_fail_when_key_internal_transcript_raw_switched() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, dealers, receivers) = environment_with_sig_inputs(1..10, alg, rng);
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            let verifier = env
                .nodes
                .random_filtered_by_receivers(inputs.receivers(), rng);

            let another_key_transcript =
                generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            assert_ne!(inputs.key_transcript(), &another_key_transcript);
            let key_transcript_with_other_internal_raw = IDkgTranscript {
                internal_transcript_raw: another_key_transcript.internal_transcript_raw,
                ..inputs.key_transcript().clone()
            };
            let inputs_with_other_key_internal_transcript_raw = ThresholdEcdsaSigInputs::new(
                &inputs.caller,
                &inputs.derivation_path,
                &inputs.hashed_message,
                &inputs.nonce,
                &inputs.presig_quadruple,
                &key_transcript_with_other_internal_raw,
            )
            .expect("invalid ECDSA inputs");

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
    }

    fn signature_share_from_random_receiver<R: RngCore + CryptoRng>(
        env: &CanisterThresholdSigTestEnvironment,
        inputs: &ThresholdEcdsaSigInputs,
        rng: &mut R,
    ) -> (NodeId, ThresholdEcdsaSigShare) {
        let signer = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);
        signer.load_tecdsa_sig_transcripts(inputs);
        let sig_share = signer
            .create_sig_share(inputs)
            .expect("failed to generate sig share");
        (signer.id(), sig_share)
    }
}

mod combine_sig_shares {
    use super::*;

    #[test]
    fn should_combine_sig_shares_successfully() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs.as_ref());
            let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            let result = combiner.combine_sig_shares(&inputs.as_ref(), &sig_shares);

            assert_matches!(result, Ok(_));
        }
    }

    #[test]
    fn should_fail_combining_sig_shares_with_insufficient_shares() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let insufficient_sig_shares =
                ecdsa_sig_share_from_each_receiver(&env, &inputs.as_ref())
                    .into_iter()
                    .take(inputs.reconstruction_threshold().get() as usize - 1)
                    .collect();
            let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            let result = combiner.combine_sig_shares(&inputs.as_ref(), &insufficient_sig_shares);

            assert_matches!(
                result,
                Err(ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold {threshold, share_count})
                    if threshold == inputs.reconstruction_threshold().get() && share_count == (threshold as usize - 1)
            );
        }
    }
}

mod verify_combined_sig {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::CorruptBytes;
    use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaVerifyCombinedSignatureError;

    #[test]
    fn should_verify_combined_sig() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs.as_ref());
            let combiner_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
            let signature = combiner_crypto_component
                .combine_sig_shares(&inputs.as_ref(), &sig_shares)
                .expect("Failed to generate signature");
            let verifier_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            let result =
                verifier_crypto_component.verify_combined_sig(&inputs.as_ref(), &signature);

            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn should_fail_verifying_corrupted_combined_sig() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs.as_ref());
            let combiner_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
            let corrupted_signature = combiner_crypto_component
                .combine_sig_shares(&inputs.as_ref(), &sig_shares)
                .expect("Failed to generate signature")
                .clone_with_bit_flipped();
            let verifier_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            let result = verifier_crypto_component
                .verify_combined_sig(&inputs.as_ref(), &corrupted_signature);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature)
            );
        }
    }

    #[test]
    fn should_fail_deserializing_signature_with_invalid_length() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs.as_ref());
            let combiner_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
            let mut corrupted_signature = combiner_crypto_component
                .combine_sig_shares(&inputs.as_ref(), &sig_shares)
                .expect("Failed to generate signature");
            corrupted_signature.signature.pop();
            let verifier_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            let result = verifier_crypto_component
                .verify_combined_sig(&inputs.as_ref(), &corrupted_signature);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifyCombinedSignatureError::SerializationError { .. })
            );
        }
    }

    #[test]
    fn should_fail_when_key_internal_transcript_raw_switched() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, dealers, receivers) = environment_with_sig_inputs(1..10, alg, rng);
            let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs.as_ref());
            let combiner_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
            let signature = combiner_crypto_component
                .combine_sig_shares(&inputs.as_ref(), &sig_shares)
                .expect("Failed to generate signature");
            let verifier_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            let another_key_transcript =
                generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            assert_ne!(inputs.key_transcript(), &another_key_transcript);
            let key_transcript_with_other_internal_raw = IDkgTranscript {
                internal_transcript_raw: another_key_transcript.internal_transcript_raw,
                ..inputs.key_transcript().clone()
            };
            let inputs_with_other_key_internal_transcript_raw = ThresholdEcdsaSigInputs::new(
                &inputs.caller,
                &inputs.derivation_path,
                &inputs.hashed_message,
                &inputs.nonce,
                &inputs.presig_quadruple,
                &key_transcript_with_other_internal_raw,
            )
            .expect("invalid ECDSA inputs");

            let result = verifier_crypto_component
                .verify_combined_sig(&inputs_with_other_key_internal_transcript_raw, &signature);

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature)
            );
        }
    }

    #[test]
    fn should_fail_verifying_combined_sig_for_inputs_with_wrong_hash() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let sig_shares = ecdsa_sig_share_from_each_receiver(&env, &inputs.as_ref());
            let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
            let signature = combiner
                .combine_sig_shares(&inputs.as_ref(), &sig_shares)
                .expect("Failed to generate signature");
            let verifier_crypto_component =
                random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            let result = verifier_crypto_component.verify_combined_sig(
                &inputs
                    .into_builder()
                    .corrupt_hashed_message()
                    .build()
                    .as_ref(),
                &signature,
            );

            assert_matches!(
                result,
                Err(ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature)
            );
        }
    }

    #[test]
    fn should_run_threshold_ecdsa_protocol_with_single_node() {
        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..=1, alg, rng);
            let signature = run_tecdsa_protocol(&env, &inputs.as_ref(), rng);
            let verifier = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

            assert_eq!(
                verifier.verify_combined_sig(&inputs.as_ref(), &signature),
                Ok(())
            );
        }
    }

    #[test]
    fn should_verify_combined_signature_with_usual_basic_sig_verification() {
        use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;
        use ic_crypto_internal_basic_sig_ecdsa_secp256r1 as ecdsa_secp256r1;

        let rng = &mut reproducible_rng();
        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
            let combined_sig = run_tecdsa_protocol(&env, &inputs.as_ref(), rng);
            let master_public_key = get_master_public_key_from_transcript(inputs.key_transcript())
                .expect("Master key extraction failed");
            let canister_public_key = derive_threshold_public_key(
                &master_public_key,
                &ExtendedDerivationPath {
                    caller: inputs.caller,
                    derivation_path: inputs.derivation_path,
                },
            )
            .expect("Public key derivation failed");

            match alg {
                AlgorithmId::ThresholdEcdsaSecp256k1 => {
                    let ecdsa_sig = ecdsa_secp256k1::types::SignatureBytes(
                        <[u8; 64]>::try_from(combined_sig.signature).expect("Expected 64 bytes"),
                    );
                    let ecdsa_pk =
                        ecdsa_secp256k1::types::PublicKeyBytes(canister_public_key.public_key);

                    assert_eq!(
                        ecdsa_secp256k1::api::verify(&ecdsa_sig, &inputs.hashed_message, &ecdsa_pk),
                        Ok(()),
                        "ECDSA sig verification failed"
                    );
                }
                AlgorithmId::ThresholdEcdsaSecp256r1 => {
                    let ecdsa_sig = ecdsa_secp256r1::types::SignatureBytes(
                        <[u8; 64]>::try_from(combined_sig.signature).expect("Expected 64 bytes"),
                    );
                    let ecdsa_pk =
                        ecdsa_secp256r1::types::PublicKeyBytes(canister_public_key.public_key);

                    assert_eq!(
                        ecdsa_secp256r1::verify(&ecdsa_sig, &inputs.hashed_message, &ecdsa_pk),
                        Ok(()),
                        "ECDSA sig verification failed"
                    );
                }
                unexpected => {
                    panic!("Unhandled ECDSA algorithm {unexpected}")
                }
            }
        }
    }
}

mod get_tecdsa_master_public_key {
    use super::*;

    #[test]
    fn should_return_ecdsa_public_key() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let result = get_master_public_key_from_transcript(&key_transcript);
            assert_matches!(result, Ok(_));
            let master_public_key = result.expect("Master key extraction failed");

            // 1 byte header + 32 bytes of field element
            let (expected_length, expected_alg) = match alg {
                AlgorithmId::ThresholdEcdsaSecp256r1 => (1 + 32, AlgorithmId::EcdsaP256),
                AlgorithmId::ThresholdEcdsaSecp256k1 => (1 + 32, AlgorithmId::EcdsaSecp256k1),
                unexpected => {
                    panic!("Unexpected ECDSA algorithm {unexpected}");
                }
            };

            assert_eq!(master_public_key.algorithm_id, expected_alg);
            assert_eq!(master_public_key.public_key.len(), expected_length);
        }
    }

    #[test]
    fn should_derive_equal_ecdsa_public_keys() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let master_public_key = get_master_public_key_from_transcript(&key_transcript)
                .expect("Master key extraction failed");

            let derivation_path_1 = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(42),
                derivation_path: vec![],
            };
            let derivation_path_2 = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(42),
                derivation_path: vec![],
            };

            assert_eq!(derivation_path_1, derivation_path_2);
            let derived_pk_1 = derive_threshold_public_key(&master_public_key, &derivation_path_1)
                .expect("Public key derivation failed ");
            let derived_pk_2 = derive_threshold_public_key(&master_public_key, &derivation_path_2)
                .expect("Public key derivation failed ");
            assert_eq!(derived_pk_1, derived_pk_2);
        }
    }

    #[test]
    fn should_derive_differing_ecdsa_public_keys() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let master_public_key = get_master_public_key_from_transcript(&key_transcript)
                .expect("Master key extraction failed");

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
                let derived_pk = derive_threshold_public_key(&master_public_key, derivation_path)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Public key derivation failed for derivation path {derivation_path:?}"
                        )
                    });
                assert!(
                    derived_keys.insert(derived_pk),
                    "Duplicate derived key for derivation path {derivation_path:?}"
                );
            }
            assert_eq!(
                derived_keys.len(),
                derivation_paths.len(),
                "# of derived keys does not match # of derivation paths"
            );
        }
    }

    #[test]
    fn should_derive_ecdsa_public_key_for_single_node() {
        let rng = &mut reproducible_rng();
        let subnet_size = 1;
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::RandomForThresholdSignature, rng);

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let master_ecdsa_key = get_master_public_key_from_transcript(&key_transcript);
            assert_matches!(master_ecdsa_key, Ok(_));
            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };

            let derived_public_key =
                derive_threshold_public_key(&master_ecdsa_key.unwrap(), &derivation_path);

            assert_matches!(derived_public_key, Ok(_));
        }
    }
}
