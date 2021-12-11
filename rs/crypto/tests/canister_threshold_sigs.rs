use ic_base_types::PrincipalId;
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_test_utils_canister_threshold_sigs::{
    build_params_from_previous, create_dealing, create_dealings, generate_key_transcript,
    generate_presig_quadruple, load_input_transcripts, load_transcript, multisign_dealings,
    random_dealer_id, random_node_id_excluding, random_receiver_for_inputs, random_receiver_id,
    run_idkg_and_create_transcript, CanisterThresholdSigTestEnvironment,
};
use ic_interfaces::crypto::{
    IDkgProtocol, MultiSigVerifier, MultiSigner, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
};
use ic_test_utilities::crypto::{
    crypto_for, dummy_idkg_transcript_id_for_tests, temp_crypto_components_for,
};
use ic_test_utilities::types::ids::NODE_1;
use ic_types::consensus::ecdsa::EcdsaDealing;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, ThresholdEcdsaCombineSigSharesError,
    ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealers, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgMultiSignedDealing,
    IDkgOpening, IDkgReceivers, IDkgTranscript, IDkgTranscriptOperation, IDkgTranscriptParams,
    IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
};
use ic_types::crypto::canister_threshold_sig::{
    ExtendedDerivationPath, PreSignatureQuadruple, ThresholdEcdsaSigInputs,
};
use ic_types::crypto::{AlgorithmId, CombinedMultiSig, CombinedMultiSigOf, CryptoError};
use ic_types::{Height, NodeId, Randomness, RegistryVersion};
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[test]
fn should_fail_create_dealing_if_registry_missing_mega_pubkey() {
    let subnet_size = thread_rng().gen_range(1, 10) + 1;
    let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size - 1);

    let new_node_id = random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
    let crypto_not_in_registry =
        TempCryptoComponent::new(Arc::clone(&env.registry) as Arc<_>, new_node_id);
    env.crypto_components
        .insert(new_node_id, crypto_not_in_registry);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let dealer_id = random_dealer_id(&params);

    let result = crypto_for(dealer_id, &env.crypto_components).create_dealing(&params);
    let err = result.unwrap_err();
    assert!(
        matches!(err, IDkgCreateDealingError::PublicKeyNotFound { node_id, .. } if node_id==new_node_id)
    );
}

#[test]
fn should_fail_create_dealing_if_node_isnt_a_dealer() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    let bad_dealer_id = random_node_id_excluding(params.dealers().get());
    let crypto_not_in_registry =
        TempCryptoComponent::new(Arc::clone(&env.registry) as Arc<_>, bad_dealer_id);
    env.crypto_components
        .insert(bad_dealer_id, crypto_not_in_registry);

    let result = crypto_for(bad_dealer_id, &env.crypto_components).create_dealing(&params);
    let err = result.unwrap_err();
    assert!(
        matches!(err, IDkgCreateDealingError::NotADealer { node_id } if node_id==bad_dealer_id)
    );
}

#[test]
fn should_fail_create_reshare_dealing_if_transcript_isnt_loaded() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let initial_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let initial_transcript =
        run_idkg_and_create_transcript(&initial_params, &env.crypto_components);

    let reshare_params = build_params_from_previous(
        initial_params,
        IDkgTranscriptOperation::ReshareOfMasked(initial_transcript.clone()),
    );
    let dealer_id = random_dealer_id(&reshare_params);

    // We don't call `load_transcript`...

    let result = crypto_for(dealer_id, &env.crypto_components).create_dealing(&reshare_params);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        IDkgCreateDealingError::SecretSharesNotFound { .. }
    ));

    // Now, load the transcript and make sure it succeeds
    load_transcript(&initial_transcript, &env.crypto_components, dealer_id);
    let result = crypto_for(dealer_id, &env.crypto_components).create_dealing(&reshare_params);
    assert!(result.is_ok());
}

#[test]
fn should_fail_create_transcript_without_enough_dealings() {
    let subnet_size = thread_rng().gen_range(1, 30);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    let dealings = params
        .dealers()
        .get()
        .iter()
        .take(params.collection_threshold().get() as usize - 1) // NOTE: Not enough!
        .map(|node| {
            let dealing = create_dealing(&params, &env.crypto_components, *node);
            (*node, dealing)
        })
        .collect();

    let multisigned_dealings = multisign_dealings(&params, &env.crypto_components, &dealings);
    let creator_id = random_receiver_id(&params);
    let result = crypto_for(creator_id, &env.crypto_components)
        .create_transcript(&params, &multisigned_dealings);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        IDkgCreateTranscriptError::UnsatisfiedCollectionThreshold { threshold, dealing_count }
        if (threshold as usize)==(params.collection_threshold().get() as usize) && (dealing_count as usize)==dealings.len()
    ));
}

#[test]
fn should_fail_create_transcript_with_mislabeled_dealers() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    let dealings = params
        .dealers()
        .get()
        .iter()
        .map(|node| {
            let dealing = create_dealing(&params, &env.crypto_components, *node);
            // NOTE: Wrong Id!
            let non_dealer_node = random_node_id_excluding(params.dealers().get());
            (non_dealer_node, dealing)
        })
        .collect();

    let multisigned_dealings = multisign_dealings(&params, &env.crypto_components, &dealings);
    let creator_id = random_receiver_id(&params);
    let result = crypto_for(creator_id, &env.crypto_components)
        .create_transcript(&params, &multisigned_dealings);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        IDkgCreateTranscriptError::DealerNotAllowed { .. }
    ));
}

#[test]
fn should_fail_create_transcript_with_signature_by_disallowed_receiver() {
    let subnet_size = thread_rng().gen_range(2, 10); // Need enough to be able to remove one
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    let dealings = create_dealings(&params, &env.crypto_components);
    let multisigned_dealings = multisign_dealings(&params, &env.crypto_components, &dealings);

    // Remove one of the original receivers from the params
    // so that we have a valid sig on the dealing, but `create_transcript` will not
    // consider them eligible to sign
    let mut modified_receivers = params.receivers().get().clone();
    let removed_node_id = random_receiver_id(&params);
    modified_receivers.remove(&removed_node_id);
    let modified_params = IDkgTranscriptParams::new(
        params.transcript_id(),
        params.dealers().clone(),
        IDkgReceivers::new(modified_receivers).expect("failed to create new receivers"),
        params.registry_version(),
        params.algorithm_id(),
        params.operation_type().clone(),
    )
    .expect("failed to create new params");

    let creator_id = random_receiver_id(&modified_params);
    let result = crypto_for(creator_id, &env.crypto_components)
        .create_transcript(&modified_params, &multisigned_dealings);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        IDkgCreateTranscriptError::SignerNotAllowed {
            node_id
        }
        if node_id==removed_node_id
    ));
}
#[test]
fn should_fail_create_transcript_without_enough_signatures() {
    let subnet_size = thread_rng().gen_range(4, 10); // Needs to be enough for >=1 signature
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    let dealings = create_dealings(&params, &env.crypto_components);
    let insufficient_multisigned_dealings = dealings
        .iter()
        .map(|(dealer_id, dealing)| {
            let multisigned_dealing = {
                let ecdsa_dealing = EcdsaDealing {
                    requested_height: Height::from(1),
                    dealer_id: *dealer_id,
                    transcript_id: params.transcript_id(),
                    dealing: dealing.clone(),
                };

                let signers: BTreeSet<_> = params
                    .receivers()
                    .get()
                    .iter()
                    .take(params.verification_threshold().get() as usize - 1) // Not enough!
                    .cloned()
                    .collect();

                let signature = {
                    let signatures: BTreeMap<_, _> = signers
                        .iter()
                        .map(|signer_id| {
                            let signature = crypto_for(*signer_id, &env.crypto_components)
                                .sign_multi(&ecdsa_dealing, *signer_id, params.registry_version())
                                .expect("failed to generate multi-signature share");

                            (*signer_id, signature)
                        })
                        .collect();

                    let combiner_id = **params
                        .receivers()
                        .get()
                        .iter()
                        .choose_multiple(&mut thread_rng(), 1)
                        .get(0)
                        .expect("receivers is empty");
                    crypto_for(combiner_id, &env.crypto_components)
                        .combine_multi_sig_individuals(signatures, params.registry_version())
                        .expect("failed to combine individual signatures")
                };

                IDkgMultiSignedDealing {
                    signature,
                    signers,
                    dealing: ecdsa_dealing,
                }
            };

            (*dealer_id, multisigned_dealing)
        })
        .collect();

    let creator_id = random_receiver_id(&params);
    let result = crypto_for(creator_id, &env.crypto_components)
        .create_transcript(&params, &insufficient_multisigned_dealings);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        IDkgCreateTranscriptError::UnsatisfiedVerificationThreshold { threshold, signature_count, .. }
        if threshold == params.verification_threshold().get() && signature_count == (threshold as usize - 1)
    ));
}

#[test]
fn should_fail_create_transcript_with_bad_signature() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

    let dealings = params
        .dealers()
        .get()
        .iter()
        .map(|node| {
            let dealing = create_dealing(&params, &env.crypto_components, *node);
            (*node, dealing)
        })
        .collect();

    let mut multisigned_dealings = multisign_dealings(&params, &env.crypto_components, &dealings);
    // Erase the multisig on each dealing
    for (_, dealing) in multisigned_dealings.iter_mut() {
        dealing.signature = CombinedMultiSigOf::new(CombinedMultiSig(vec![0; 48]));
    }

    let creator_id = random_receiver_id(&params);
    let result = crypto_for(creator_id, &env.crypto_components)
        .create_transcript(&params, &multisigned_dealings);
    let err = result.unwrap_err();
    println!("{:?}", err);
    assert!(matches!(
        err,
        IDkgCreateTranscriptError::InvalidMultisignature {
            crypto_error: CryptoError::MalformedSignature { .. }
        }
    ));
}

#[test]
fn should_return_ok_from_load_transcript_if_not_a_receiver() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let transcript = run_idkg_and_create_transcript(&params, &env.crypto_components);

    let loader_id_not_receiver =
        random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
    let crypto_not_in_registry =
        TempCryptoComponent::new(Arc::clone(&env.registry) as Arc<_>, loader_id_not_receiver);
    env.crypto_components
        .insert(loader_id_not_receiver, crypto_not_in_registry);

    assert!(!transcript.receivers.get().contains(&loader_id_not_receiver));
    let result =
        crypto_for(loader_id_not_receiver, &env.crypto_components).load_transcript(&transcript);
    assert!(result.is_ok());
}

#[test]
fn should_run_load_transcript_successfully_if_already_loaded() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let transcript = run_idkg_and_create_transcript(&params, &env.crypto_components);

    let loader_id = random_receiver_id(&params);

    assert!(crypto_for(loader_id, &env.crypto_components)
        .load_transcript(&transcript)
        .is_ok());

    let result = crypto_for(loader_id, &env.crypto_components).load_transcript(&transcript);
    assert!(result.is_ok());
}

#[test]
fn should_run_idkg_successfully_for_random_dealing() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    run_idkg_and_create_transcript(&params, &env.crypto_components);
}

#[test]
fn should_run_idkg_successfully_for_reshare_of_random_dealing() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let initial_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let initial_transcript =
        run_idkg_and_create_transcript(&initial_params, &env.crypto_components);

    let reshare_params = build_params_from_previous(
        initial_params,
        IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
    );
    run_idkg_and_create_transcript(&reshare_params, &env.crypto_components);
}

#[test]
fn should_run_idkg_successfully_for_reshare_of_unmasked_dealing() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let initial_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let initial_transcript =
        run_idkg_and_create_transcript(&initial_params, &env.crypto_components);

    let unmasked_params = build_params_from_previous(
        initial_params,
        IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
    );
    let unmasked_transcript =
        run_idkg_and_create_transcript(&unmasked_params, &env.crypto_components);

    let reshare_params = build_params_from_previous(
        unmasked_params,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
    );
    run_idkg_and_create_transcript(&reshare_params, &env.crypto_components);
}

#[test]
fn should_run_idkg_successfully_for_multiplication_of_dealings() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let masked_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let masked_transcript = run_idkg_and_create_transcript(&masked_params, &env.crypto_components);

    let unmasked_transcript = {
        let masked_random_params =
            env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let masked_random_transcript =
            run_idkg_and_create_transcript(&masked_random_params, &env.crypto_components);
        let unmasked_params = build_params_from_previous(
            masked_random_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_random_transcript),
        );

        run_idkg_and_create_transcript(&unmasked_params, &env.crypto_components)
    };

    let multiplication_params = build_params_from_previous(
        masked_params,
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
    );

    run_idkg_and_create_transcript(&multiplication_params, &env.crypto_components);
}

#[test]
fn should_create_quadruple_successfully_with_new_key() {
    let subnet_size = thread_rng().gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);
}

#[test]
fn should_create_signature_share_successfully_with_new_key() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let signer_id = random_receiver_for_inputs(&inputs);

    load_input_transcripts(&env.crypto_components, signer_id, &inputs);

    let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
    assert!(result.is_ok());
}

#[test]
fn should_fail_create_signature_if_not_receiver() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let bad_signer_id = random_node_id_excluding(inputs.receivers().get());
    let bad_crypto_component =
        TempCryptoComponent::new(Arc::clone(&env.registry) as Arc<_>, bad_signer_id);

    let result = bad_crypto_component.sign_share(&inputs);
    let err = result.unwrap_err();
    assert!(matches!(err, ThresholdEcdsaSignShareError::NotAReceiver));
}

#[test]
fn should_fail_create_signature_share_without_any_transcripts_loaded() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    // This allows the `inputs` to be accepted by `sign_share`,
    // but the transcripts weren't loaded.
    let inputs = fake_sig_inputs(&env.receivers());

    let signer_id = random_receiver_for_inputs(&inputs);

    let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }
    ));
}

#[test]
fn should_fail_create_signature_share_without_kappa_times_lambda_loaded() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let signer_id = random_receiver_for_inputs(&inputs);

    {
        load_transcript(
            inputs.presig_quadruple().kappa_unmasked(),
            &env.crypto_components,
            signer_id,
        );
        load_transcript(
            inputs.presig_quadruple().lambda_masked(),
            &env.crypto_components,
            signer_id,
        );
        // Not loading kappa_times_lambda
        load_transcript(
            inputs.presig_quadruple().key_times_lambda(),
            &env.crypto_components,
            signer_id,
        );
        load_transcript(inputs.key_transcript(), &env.crypto_components, signer_id);
    }

    let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }
    ));
}

#[test]
fn should_fail_create_signature_share_without_key_times_lambda_loaded() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let signer_id = random_receiver_for_inputs(&inputs);

    {
        load_transcript(
            inputs.presig_quadruple().kappa_unmasked(),
            &env.crypto_components,
            signer_id,
        );
        load_transcript(
            inputs.presig_quadruple().lambda_masked(),
            &env.crypto_components,
            signer_id,
        );
        load_transcript(
            inputs.presig_quadruple().kappa_times_lambda(),
            &env.crypto_components,
            signer_id,
        );
        // Not loading key_times_lambda
        load_transcript(inputs.key_transcript(), &env.crypto_components, signer_id);
    }

    let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }
    ));
}

#[test]
fn should_verify_sig_share_successfully() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let signer_id = random_receiver_for_inputs(&inputs);
    load_input_transcripts(&env.crypto_components, signer_id, &inputs);
    let sig_share = crypto_for(signer_id, &env.crypto_components)
        .sign_share(&inputs)
        .expect("failed to generate sig share");

    let verifier_id = random_receiver_for_inputs(&inputs);
    let result = crypto_for(verifier_id, &env.crypto_components)
        .verify_sig_share(signer_id, &inputs, &sig_share);
    assert!(result.is_ok());
}

#[test]
fn should_combine_sig_shares_successfully() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let sig_shares = inputs
        .receivers()
        .get()
        .iter()
        .map(|&signer_id| {
            load_input_transcripts(&env.crypto_components, signer_id, &inputs);

            let sig_share = crypto_for(signer_id, &env.crypto_components)
                .sign_share(&inputs)
                .expect("failed to create sig share");
            (signer_id, sig_share)
        })
        .collect();

    // Combiner can be someone not involved in the IDkg
    let combiner_id = random_node_id_excluding(inputs.receivers().get());
    let combiner_crypto_component =
        TempCryptoComponent::new(Arc::clone(&env.registry) as Arc<_>, combiner_id);
    let result = combiner_crypto_component.combine_sig_shares(&inputs, &sig_shares);
    assert!(result.is_ok());
}

#[test]
fn should_fail_combine_sig_shares_with_insufficient_shares() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let sig_shares = inputs
        .receivers()
        .get()
        .iter()
        .take(inputs.reconstruction_threshold().get() as usize - 1) // Not enough!
        .map(|&signer_id| {
            load_input_transcripts(&env.crypto_components, signer_id, &inputs);

            let sig_share = crypto_for(signer_id, &env.crypto_components)
                .sign_share(&inputs)
                .expect("failed to create sig share");
            (signer_id, sig_share)
        })
        .collect();

    let combiner_id = random_receiver_for_inputs(&inputs);
    let result =
        crypto_for(combiner_id, &env.crypto_components).combine_sig_shares(&inputs, &sig_shares);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold {threshold, share_count}
        if threshold == inputs.reconstruction_threshold().get() && share_count == (threshold as usize - 1)
    ));
}

#[test]
fn should_verify_combined_sig_successfully() {
    let mut rng = thread_rng();

    let subnet_size = rng.gen_range(1, 10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
    let quadruple =
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

    let inputs = {
        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            bip32_derivation_path: vec![],
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

    let sig_shares = inputs
        .receivers()
        .get()
        .iter()
        .map(|&signer_id| {
            load_input_transcripts(&env.crypto_components, signer_id, &inputs);

            let sig_share = crypto_for(signer_id, &env.crypto_components)
                .sign_share(&inputs)
                .expect("failed to create sig share");
            (signer_id, sig_share)
        })
        .collect();

    let combiner_id = random_receiver_for_inputs(&inputs);
    let combined_sig = crypto_for(combiner_id, &env.crypto_components)
        .combine_sig_shares(&inputs, &sig_shares)
        .expect("failed to combine sig shares");

    let verifier_id = random_receiver_for_inputs(&inputs);
    let result =
        crypto_for(verifier_id, &env.crypto_components).verify_combined_sig(&inputs, &combined_sig);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_dealing_public() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params_for(NODE_1);
    let dealing = IDkgDealing {
        transcript_id: dummy_idkg_transcript_id_for_tests(1),
        dealer_id: NodeId::from(PrincipalId::new_node_test_id(0)),
        internal_dealing_raw: vec![],
    };
    let result = crypto_for(NODE_1, &crypto_components).verify_dealing_public(&params, &dealing);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_dealing_private() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params_for(NODE_1);
    let dealing = IDkgDealing {
        transcript_id: dummy_idkg_transcript_id_for_tests(1),
        dealer_id: NodeId::from(PrincipalId::new_node_test_id(0)),
        internal_dealing_raw: vec![],
    };
    let result = crypto_for(NODE_1, &crypto_components).verify_dealing_private(&params, &dealing);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_transcript() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params_for(NODE_1);
    let transcript = fake_transcript();
    let result = crypto_for(NODE_1, &crypto_components).verify_transcript(&params, &transcript);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_complaint() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let complaint = fake_complaint();
    let transcript = fake_transcript();
    let result =
        crypto_for(NODE_1, &crypto_components).verify_complaint(&transcript, NODE_1, &complaint);
    assert!(result.is_ok());
}

#[test]
fn should_run_open_transcript() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let complaint = fake_complaint();
    let transcript = fake_transcript();
    let result = crypto_for(NODE_1, &crypto_components).open_transcript(&transcript, &complaint);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_opening() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let transcript = fake_transcript();
    let opening = fake_opening();
    let complaint = fake_complaint();
    let result = crypto_for(NODE_1, &crypto_components).verify_opening(
        &transcript,
        NODE_1,
        &opening,
        &complaint,
    );
    assert!(result.is_ok());
}

#[test]
fn should_run_load_transcript_with_openings() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let transcript = fake_transcript();
    let mut openings = BTreeMap::new();
    let complaint = fake_complaint();
    openings.insert(complaint, BTreeMap::new());
    let result =
        crypto_for(NODE_1, &crypto_components).load_transcript_with_openings(transcript, openings);
    assert!(result.is_ok());
}

#[test]
fn should_run_retain_active_transcripts() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    crypto_for(NODE_1, &crypto_components).retain_active_transcripts(&[]);
}

#[test]
fn should_run_get_public_key() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let key_transcript = fake_transcript();
    let result = crypto_for(NODE_1, &crypto_components)
        .get_public_key(PrincipalId::new_user_test_id(1), key_transcript);
    assert!(result.is_ok());
}

fn fake_params_for(node_id: NodeId) -> IDkgTranscriptParams {
    let mut nodes = BTreeSet::new();
    nodes.insert(node_id);

    IDkgTranscriptParams::new(
        dummy_idkg_transcript_id_for_tests(1),
        IDkgDealers::new(nodes.clone()).unwrap(),
        IDkgReceivers::new(nodes).unwrap(),
        RegistryVersion::from(1),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        IDkgTranscriptOperation::Random,
    )
    .expect("failed to generate fake parameters")
}

fn fake_transcript() -> IDkgTranscript {
    let mut nodes = BTreeSet::new();
    nodes.insert(NODE_1);

    IDkgTranscript {
        transcript_id: dummy_idkg_transcript_id_for_tests(1),
        receivers: IDkgReceivers::new(nodes).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}

fn fake_complaint() -> IDkgComplaint {
    IDkgComplaint {
        transcript_id: dummy_idkg_transcript_id_for_tests(1),
        dealer_id: NODE_1,
        internal_complaint_raw: vec![],
    }
}

fn fake_opening() -> IDkgOpening {
    IDkgOpening {
        transcript_id: dummy_idkg_transcript_id_for_tests(1),
        dealer_id: NODE_1,
        internal_opening_raw: vec![],
    }
}

fn fake_key_and_presig_quadruple(
    nodes: &BTreeSet<NodeId>,
) -> (IDkgTranscript, PreSignatureQuadruple) {
    let internal_transcript_raw = {
        // Just generate a transcript and use its "raw" field,
        // so the others will at least be correctly parsable
        let env = CanisterThresholdSigTestEnvironment::new(1);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript = run_idkg_and_create_transcript(&params, &env.crypto_components);
        transcript.internal_transcript_raw
    };

    let original_kappa_id = dummy_idkg_transcript_id_for_tests(1);
    let kappa_id = dummy_idkg_transcript_id_for_tests(2);
    let lambda_id = dummy_idkg_transcript_id_for_tests(3);
    let key_id = dummy_idkg_transcript_id_for_tests(4);

    let fake_kappa = IDkgTranscript {
        transcript_id: kappa_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            original_kappa_id,
        )),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: internal_transcript_raw.clone(),
    };

    let fake_lambda = IDkgTranscript {
        transcript_id: lambda_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: internal_transcript_raw.clone(),
    };

    let fake_kappa_times_lambda = IDkgTranscript {
        transcript_id: dummy_idkg_transcript_id_for_tests(40),
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(
            IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(kappa_id, lambda_id),
        ),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: internal_transcript_raw.clone(),
    };

    let fake_key = IDkgTranscript {
        transcript_id: key_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            dummy_idkg_transcript_id_for_tests(50),
        )),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: internal_transcript_raw.clone(),
    };

    let fake_key_times_lambda = IDkgTranscript {
        transcript_id: dummy_idkg_transcript_id_for_tests(50),
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(
            IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(key_id, lambda_id),
        ),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw,
    };

    let presig_quadruple = PreSignatureQuadruple::new(
        fake_kappa,
        fake_lambda,
        fake_kappa_times_lambda,
        fake_key_times_lambda,
    )
    .unwrap();

    (fake_key, presig_quadruple)
}

fn fake_sig_inputs(nodes: &BTreeSet<NodeId>) -> ThresholdEcdsaSigInputs {
    let (fake_key, fake_presig_quadruple) = fake_key_and_presig_quadruple(nodes);

    let derivation_path = ExtendedDerivationPath {
        caller: PrincipalId::new_user_test_id(1),
        bip32_derivation_path: vec![],
    };

    ThresholdEcdsaSigInputs::new(
        &derivation_path,
        &[],
        Randomness::from([0_u8; 32]),
        fake_presig_quadruple,
        fake_key,
    )
    .expect("failed to create signature inputs")
}
