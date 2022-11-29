use ic_base_types::PrincipalId;
use ic_crypto::get_tecdsa_master_public_key;
use ic_crypto_internal_threshold_sig_ecdsa::{EccScalar, IDkgDealingInternal, MEGaCiphertext};
use ic_crypto_tecdsa::derive_tecdsa_public_key;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils::{crypto_for, dkg::dummy_idkg_transcript_id_for_tests};
use ic_crypto_test_utils_canister_threshold_sigs::load_previous_transcripts_and_create_signed_dealings;
use ic_crypto_test_utils_canister_threshold_sigs::IntoBuilder;
use ic_crypto_test_utils_canister_threshold_sigs::{
    batch_sign_signed_dealings, batch_signature_from_signers, build_params_from_previous,
    create_and_verify_signed_dealing, create_and_verify_signed_dealings, create_signed_dealing,
    generate_key_transcript, generate_presig_quadruple, generate_tecdsa_protocol_inputs,
    load_input_transcripts, load_transcript, node_id, random_dealer_id, random_dealer_id_excluding,
    random_node_id_excluding, random_receiver_for_inputs, random_receiver_id,
    random_receiver_id_excluding, run_idkg_and_create_and_verify_transcript, run_tecdsa_protocol,
    CanisterThresholdSigTestEnvironment,
};
use ic_interfaces::crypto::{IDkgProtocol, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
use ic_types::crypto::canister_threshold_sig::error::IDkgVerifyInitialDealingsError;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgOpenTranscriptError,
    IDkgVerifyComplaintError, IDkgVerifyDealingPublicError, IDkgVerifyOpeningError,
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::InitialIDkgDealings;
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgComplaint, IDkgMaskedTranscriptOrigin, IDkgReceivers,
    IDkgTranscript, IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{
    ExtendedDerivationPath, PreSignatureQuadruple, ThresholdEcdsaCombinedSignature,
    ThresholdEcdsaSigInputs,
};
use ic_types::crypto::{AlgorithmId, BasicSigOf, CryptoError};
use ic_types::{NodeId, NodeIndex, Randomness, RegistryVersion};
use maplit::hashset;
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::sync::Arc;

mod create_dealing {
    use super::*;
    use ic_interfaces::crypto::BasicSigVerifier;

    #[test]
    fn should_create_signed_dealing_with_correct_public_key() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let dealer = crypto_for(dealer_id, &env.crypto_components);

        let dealing = dealer
            .create_dealing(&params)
            .expect("could not create dealing");
        assert_eq!(dealing.dealer_id(), dealer_id);

        let verification_result = dealer.verify_basic_sig(
            &dealing.signature.signature,
            &dealing.content,
            dealer_id,
            params.registry_version(),
        );
        assert!(verification_result.is_ok());
    }

    #[test]
    fn should_fail_create_dealing_if_registry_missing_mega_pubkey() {
        let subnet_size = thread_rng().gen_range(1..10);
        let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let new_node_id =
            random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
        let crypto_not_in_registry = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(new_node_id)
            .build();
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
        let subnet_size = thread_rng().gen_range(1..10);
        let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let bad_dealer_id = random_node_id_excluding(params.dealers().get());
        let crypto_not_in_registry = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(bad_dealer_id)
            .build();
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
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let initial_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let initial_transcript =
            run_idkg_and_create_and_verify_transcript(&initial_params, &env.crypto_components);

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
}

mod create_transcript {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::CorruptBytesCollection;

    #[test]
    fn should_fail_create_transcript_without_enough_dealings() {
        let subnet_size = thread_rng().gen_range(1..30);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let dealings: BTreeMap<NodeId, SignedIDkgDealing> = params
            .dealers()
            .get()
            .iter()
            .take(params.collection_threshold().get() as usize - 1) // NOTE: Not enough!
            .map(|node| {
                let dealing =
                    create_and_verify_signed_dealing(&params, &env.crypto_components, *node);
                (*node, dealing)
            })
            .collect();

        let batch_signed_dealings =
            batch_sign_signed_dealings(&params, &env.crypto_components, dealings.clone());
        let creator_id = random_receiver_id(&params);
        let result = crypto_for(creator_id, &env.crypto_components)
            .create_transcript(&params, &batch_signed_dealings);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            IDkgCreateTranscriptError::UnsatisfiedCollectionThreshold { threshold, dealing_count }
            if (threshold as usize)==(params.collection_threshold().get() as usize) && (dealing_count as usize)==dealings.len()
        ));
    }

    #[test]
    fn should_fail_create_transcript_with_mislabeled_dealers() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let dealings = params
            .dealers()
            .get()
            .iter()
            .map(|node| {
                let dealing =
                    create_and_verify_signed_dealing(&params, &env.crypto_components, *node);
                // NOTE: Wrong Id!
                let non_dealer_node = random_node_id_excluding(params.dealers().get());
                (non_dealer_node, dealing)
            })
            .collect();

        let batch_signed_dealings =
            batch_sign_signed_dealings(&params, &env.crypto_components, dealings);
        let creator_id = random_receiver_id(&params);
        let result = crypto_for(creator_id, &env.crypto_components)
            .create_transcript(&params, &batch_signed_dealings);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            IDkgCreateTranscriptError::DealerNotAllowed { .. }
        ));
    }

    #[test]
    fn should_fail_create_transcript_with_signature_by_disallowed_receiver() {
        let subnet_size = thread_rng().gen_range(2..10); // Need enough to be able to remove one
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let signed_dealings = create_and_verify_signed_dealings(&params, &env.crypto_components);
        let batch_signed_dealings =
            batch_sign_signed_dealings(&params, &env.crypto_components, signed_dealings);

        // Remove one of the original receivers from the params
        // so that we have a valid sig on the dealing, but `create_transcript` will not
        // consider them eligible to sign
        let mut modified_receivers = params.receivers().get().clone();
        let removed_node_id = random_receiver_id(&params);
        modified_receivers.remove(&removed_node_id);
        let modified_params = IDkgTranscriptParams::new(
            params.transcript_id(),
            params.dealers().get().clone(),
            modified_receivers,
            params.registry_version(),
            params.algorithm_id(),
            params.operation_type().clone(),
        )
        .expect("failed to create new params");

        let creator_id = random_receiver_id(&modified_params);
        let result = crypto_for(creator_id, &env.crypto_components)
            .create_transcript(&modified_params, &batch_signed_dealings);
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
        let subnet_size = thread_rng().gen_range(4..10); // Needs to be enough for >=1 signature
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let signed_dealings = create_and_verify_signed_dealings(&params, &env.crypto_components);
        let insufficient_batch_signed_dealings = signed_dealings
            .into_iter()
            .map(|(dealer_id, signed_dealing)| {
                let signature_batch = {
                    let signers: BTreeSet<_> = params
                        .receivers()
                        .get()
                        .iter()
                        .take(params.verification_threshold().get() as usize - 1) // Not enough!
                        .cloned()
                        .collect();

                    batch_signature_from_signers(
                        params.registry_version(),
                        &env.crypto_components,
                        signed_dealing,
                        &signers,
                    )
                };

                (dealer_id, signature_batch)
            })
            .collect();

        let creator_id = random_receiver_id(&params);
        let result = crypto_for(creator_id, &env.crypto_components)
            .create_transcript(&params, &insufficient_batch_signed_dealings);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            IDkgCreateTranscriptError::UnsatisfiedVerificationThreshold { threshold, signature_count, .. }
            if threshold == params.verification_threshold().get() && signature_count == (threshold as usize - 1)
        ));
    }

    #[test]
    fn should_fail_create_transcript_with_all_signatures_bad_in_all_dealings() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let creator_id = random_receiver_id(&params);
        let mut batch_signed_dealings = create_batch_signed_dealings(&env, &params);
        batch_signed_dealings
            .values_mut()
            .for_each(|dealing| dealing.flip_a_bit_in_all());

        let result = crypto_for(creator_id, &env.crypto_components)
            .create_transcript(&params, &batch_signed_dealings);

        assert!(matches!(
            result,
            Err(IDkgCreateTranscriptError::InvalidSignatureBatch {
                crypto_error: CryptoError::SignatureVerification { .. }
            })
        ));
    }

    #[test]
    fn should_fail_create_transcript_with_all_signatures_bad_in_one_dealing() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let creator_id = random_receiver_id(&params);
        let mut batch_signed_dealings = create_batch_signed_dealings(&env, &params);
        batch_signed_dealings
            .values_mut()
            .next()
            .expect("empty map")
            .flip_a_bit_in_all();

        let result = crypto_for(creator_id, &env.crypto_components)
            .create_transcript(&params, &batch_signed_dealings);

        assert!(matches!(
            result,
            Err(IDkgCreateTranscriptError::InvalidSignatureBatch {
                crypto_error: CryptoError::SignatureVerification { .. }
            })
        ));
    }

    #[test]
    fn should_fail_create_transcript_with_one_bad_signature_in_one_dealing() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let creator_id = random_receiver_id(&params);
        let mut batch_signed_dealings = create_batch_signed_dealings(&env, &params);
        batch_signed_dealings
            .values_mut()
            .next()
            .expect("empty map")
            .flip_a_bit_in_one();

        let result = crypto_for(creator_id, &env.crypto_components)
            .create_transcript(&params, &batch_signed_dealings);

        assert!(matches!(
            result,
            Err(IDkgCreateTranscriptError::InvalidSignatureBatch {
                crypto_error: CryptoError::SignatureVerification { .. }
            })
        ));
    }

    fn create_batch_signed_dealings(
        env: &CanisterThresholdSigTestEnvironment,
        params: &IDkgTranscriptParams,
    ) -> BTreeMap<NodeId, BatchSignedIDkgDealing> {
        let signed_dealings = create_and_verify_signed_dealings(params, &env.crypto_components);
        batch_sign_signed_dealings(params, &env.crypto_components, signed_dealings)
    }
}

mod load_transcript {
    use super::*;

    #[test]
    fn should_return_ok_from_load_transcript_if_not_a_receiver() {
        let subnet_size = thread_rng().gen_range(1..10);
        let mut env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);

        let loader_id_not_receiver =
            random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
        let crypto_not_in_registry = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(loader_id_not_receiver)
            .build();
        env.crypto_components
            .insert(loader_id_not_receiver, crypto_not_in_registry);

        assert!(!transcript.receivers.get().contains(&loader_id_not_receiver));
        let result =
            crypto_for(loader_id_not_receiver, &env.crypto_components).load_transcript(&transcript);
        assert!(result.is_ok());
    }

    #[test]
    fn should_run_load_transcript_successfully_if_already_loaded() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);

        let loader_id = random_receiver_id(&params);

        assert!(crypto_for(loader_id, &env.crypto_components)
            .load_transcript(&transcript)
            .is_ok());

        let result = crypto_for(loader_id, &env.crypto_components).load_transcript(&transcript);
        assert!(result.is_ok());
    }

    #[test]
    fn should_load_transcript_without_returning_complaints() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        let loader_id = random_receiver_id(&params);

        let result = crypto_for(loader_id, &env.crypto_components).load_transcript(&transcript);

        assert!(matches!(result, Ok(complaints) if complaints.is_empty()));
    }
}

mod verify_complaint {
    use super::*;

    #[test]
    fn should_verify_complaint() {
        let rng = &mut thread_rng();
        let subnet_size = rng.gen_range(2..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, rng);

        let result = crypto_for(random_receiver_id(&params), &env.crypto_components)
            .verify_complaint(&transcript, complainer.get_node_id(), &complaint);

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_valid_and_correct_complaints_on_load_transcript_with_invalid_dealings() {
        let rng = &mut thread_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);

        let num_of_complaints = rng.gen_range(1..=transcript.verified_dealings.len());
        let (complainer, corrupted_dealing_indices, complaints) =
            generate_complaints(&mut transcript, num_of_complaints, &params, &env, rng);

        for complaint in &complaints {
            assert_eq!(complaint.transcript_id, transcript.transcript_id);
            assert!(
                crypto_for(random_receiver_id(&params), &env.crypto_components)
                    .verify_complaint(&transcript, complainer.get_node_id(), complaint)
                    .is_ok()
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
        let rng = &mut thread_rng();
        let subnet_size = rng.gen_range(2..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, rng);

        let wrong_complainer_id =
            random_receiver_id_excluding(params.receivers(), complainer.get_node_id());

        assert!(matches!(
            crypto_for(random_receiver_id(&params), &env.crypto_components).verify_complaint(
                &transcript,
                wrong_complainer_id,
                &complaint,
            ),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        ));
    }

    #[test]
    fn should_fail_to_verify_complaint_with_wrong_transcript_id() {
        let rng = &mut thread_rng();
        let subnet_size = rng.gen_range(2..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, rng);

        let other_transcript_id = env
            .params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1)
            .transcript_id();
        assert_ne!(other_transcript_id, params.transcript_id());
        let complaint = complaint
            .into_builder()
            .with_transcript_id(other_transcript_id)
            .build();

        let result = crypto_for(random_receiver_id(&params), &env.crypto_components)
            .verify_complaint(&transcript, complainer.get_node_id(), &complaint);

        assert!(matches!(
            result,
            Err(IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs)
        ));
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
        let rng = &mut thread_rng();
        let subnet_size = rng.gen_range(4..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        assert!(params.collection_threshold().get() >= 2);
        let num_of_dealings_to_corrupt = 2;

        let (complainer, _, complaints) = generate_complaints(
            &mut transcript,
            num_of_dealings_to_corrupt,
            &params,
            &env,
            rng,
        );
        let complainer_id = complainer.get_node_id();

        let mut complaint_1 = complaints.get(0).unwrap().clone();
        let mut complaint_2 = complaints.get(1).unwrap().clone();
        std::mem::swap(&mut complaint_1.dealer_id, &mut complaint_2.dealer_id);

        assert!(matches!(
            crypto_for(complainer_id, &env.crypto_components).verify_complaint(
                &transcript,
                complainer_id,
                &complaint_1,
            ),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        ));
        assert!(matches!(
            crypto_for(complainer_id, &env.crypto_components).verify_complaint(
                &transcript,
                complainer_id,
                &complaint_2,
            ),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        ));
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
        let rng = &mut thread_rng();
        let num_of_dealings_to_corrupt = 2;
        let subnet_size = rng.gen_range(4..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        assert!(params.collection_threshold().get() as usize >= num_of_dealings_to_corrupt);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);

        let (complainer, _, complaints) = generate_complaints(
            &mut transcript,
            num_of_dealings_to_corrupt,
            &params,
            &env,
            rng,
        );
        let complainer_id = complainer.get_node_id();

        let mut complaint_1 = complaints.get(0).unwrap().clone();
        let mut complaint_2 = complaints.get(1).unwrap().clone();
        std::mem::swap(
            &mut complaint_1.internal_complaint_raw,
            &mut complaint_2.internal_complaint_raw,
        );

        assert!(matches!(
            crypto_for(complainer_id, &env.crypto_components).verify_complaint(
                &transcript,
                complainer_id,
                &complaint_1,
            ),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        ));
        assert!(matches!(
            crypto_for(complainer_id, &env.crypto_components).verify_complaint(
                &transcript,
                complainer_id,
                &complaint_2,
            ),
            Err(IDkgVerifyComplaintError::InvalidComplaint)
        ));
    }
}

mod verify_transcript {
    use super::*;

    #[test]
    fn should_run_idkg_successfully_for_random_dealing() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);

        // Transcript should have correct dealer indexes
        check_dealer_indexes(&params, &transcript);
    }

    #[test]
    fn should_run_idkg_successfully_for_reshare_of_random_dealing() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let initial_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let initial_transcript =
            run_idkg_and_create_and_verify_transcript(&initial_params, &env.crypto_components);

        // Initial transcript should have correct dealer indexes
        check_dealer_indexes(&initial_params, &initial_transcript);

        let reshare_params = build_params_from_previous(
            initial_params,
            IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
        );
        let reshare_transcript =
            run_idkg_and_create_and_verify_transcript(&reshare_params, &env.crypto_components);

        // Reshare transcript should have correct dealer indexes
        check_dealer_indexes(&reshare_params, &reshare_transcript);
    }

    #[test]
    fn should_run_idkg_successfully_for_reshare_of_unmasked_dealing() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let initial_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let initial_transcript =
            run_idkg_and_create_and_verify_transcript(&initial_params, &env.crypto_components);

        // Initial transcript should have correct dealer indexes
        check_dealer_indexes(&initial_params, &initial_transcript);

        let unmasked_params = build_params_from_previous(
            initial_params,
            IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
        );
        let unmasked_transcript =
            run_idkg_and_create_and_verify_transcript(&unmasked_params, &env.crypto_components);

        let reshare_params = build_params_from_previous(
            unmasked_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        );
        let reshare_transcript =
            run_idkg_and_create_and_verify_transcript(&reshare_params, &env.crypto_components);

        check_dealer_indexes(&reshare_params, &reshare_transcript);
    }

    #[test]
    fn should_run_idkg_successfully_for_multiplication_of_dealings() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let masked_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let masked_transcript =
            run_idkg_and_create_and_verify_transcript(&masked_params, &env.crypto_components);

        // Masked transcript should have correct dealer indexes
        check_dealer_indexes(&masked_params, &masked_transcript);

        let unmasked_transcript = {
            let masked_random_params =
                env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
            let masked_random_transcript = run_idkg_and_create_and_verify_transcript(
                &masked_random_params,
                &env.crypto_components,
            );

            let unmasked_params = build_params_from_previous(
                masked_random_params,
                IDkgTranscriptOperation::ReshareOfMasked(masked_random_transcript),
            );
            let unmasked_transcript =
                run_idkg_and_create_and_verify_transcript(&unmasked_params, &env.crypto_components);

            // Unmasked transcript should have correct dealer indexes
            check_dealer_indexes(&unmasked_params, &unmasked_transcript);

            unmasked_transcript
        };

        let multiplication_params = build_params_from_previous(
            masked_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
        );
        let multiplication_transcript = run_idkg_and_create_and_verify_transcript(
            &multiplication_params,
            &env.crypto_components,
        );

        // Multiplication transcript should have correct dealer indexes
        check_dealer_indexes(&multiplication_params, &multiplication_transcript);
    }

    #[test]
    fn should_include_the_expected_number_of_dealings_in_a_transcript() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let random_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let random_transcript =
            run_idkg_and_create_and_verify_transcript(&random_params, &env.crypto_components);

        assert_eq!(
            random_transcript.verified_dealings.len(),
            random_params.collection_threshold().get() as usize
        );

        let unmasked_params = build_params_from_previous(
            random_params.clone(),
            IDkgTranscriptOperation::ReshareOfMasked(random_transcript.clone()),
        );
        let unmasked_transcript =
            run_idkg_and_create_and_verify_transcript(&unmasked_params, &env.crypto_components);

        assert_eq!(
            unmasked_transcript.verified_dealings.len(),
            unmasked_params.collection_threshold().get() as usize
        );

        let reshare_params = build_params_from_previous(
            unmasked_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript.clone()),
        );
        let reshare_transcript =
            run_idkg_and_create_and_verify_transcript(&reshare_params, &env.crypto_components);

        assert_eq!(
            reshare_transcript.verified_dealings.len(),
            reshare_params.collection_threshold().get() as usize
        );

        let multiplication_params = build_params_from_previous(
            random_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, random_transcript),
        );
        let multiplication_transcript = run_idkg_and_create_and_verify_transcript(
            &multiplication_params,
            &env.crypto_components,
        );

        assert_eq!(
            multiplication_transcript.verified_dealings.len(),
            multiplication_params.collection_threshold().get() as usize
        );
    }

    #[test]
    fn should_create_quadruple_successfully_with_new_key() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);
    }
}

mod sign_share {
    use super::*;

    #[test]
    fn should_create_signature_share_successfully_with_new_key() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let signer_id = random_receiver_for_inputs(&inputs);

        load_input_transcripts(&env.crypto_components, signer_id, &inputs);

        let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_create_signature_if_not_receiver() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let bad_signer_id = random_node_id_excluding(inputs.receivers().get());
        let bad_crypto_component = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(bad_signer_id)
            .build();

        let result = bad_crypto_component.sign_share(&inputs);
        let err = result.unwrap_err();
        assert!(matches!(err, ThresholdEcdsaSignShareError::NotAReceiver));
    }

    #[test]
    fn should_fail_create_signature_share_without_any_transcripts_loaded() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
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

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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
}

mod verify_sig_share {
    use super::*;

    #[test]
    fn should_verify_sig_share_successfully() {
        let mut rng = thread_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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
}

mod retain_active_transcripts {
    use super::*;
    use ic_interfaces::crypto::KeyManager;
    use std::collections::HashSet;

    #[test]
    fn should_be_nop_when_transcripts_empty() {
        let mut rng = thread_rng();
        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let retainer = crypto_for(random_receiver_id(&params), &env.crypto_components);
        let public_keys_before_retaining = retainer.current_node_public_keys();
        assert!(public_keys_before_retaining
            .idkg_dealing_encryption_public_key
            .is_some());

        let empty_transcripts = HashSet::new();

        assert!(retainer
            .retain_active_transcripts(&empty_transcripts)
            .is_ok());
        assert_eq!(
            public_keys_before_retaining,
            retainer.current_node_public_keys()
        );
    }

    #[test]
    fn should_retain_active_transcripts_successfully() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);

        let retainer_id = random_receiver_id(&params);

        let active_transcripts = hashset!(transcript);
        assert!(crypto_for(retainer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());
    }

    #[test]
    fn should_fail_to_sign_when_input_transcripts_not_retained() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let signer_id = random_receiver_for_inputs(&inputs);
        load_input_transcripts(&env.crypto_components, signer_id, &inputs);
        assert!(crypto_for(signer_id, &env.crypto_components)
            .sign_share(&inputs)
            .is_ok());

        let another_key_transcript =
            generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let active_transcripts = hashset!(another_key_transcript);
        assert!(crypto_for(signer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }
        ));
    }

    #[test]
    fn should_fail_to_sign_when_lambda_masked_not_retained_in_signer() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let signer_id = random_receiver_for_inputs(&inputs);
        load_input_transcripts(&env.crypto_components, signer_id, &inputs);
        assert!(crypto_for(signer_id, &env.crypto_components)
            .sign_share(&inputs)
            .is_ok());

        let active_transcripts = hashset!(
            inputs.key_transcript().clone(),
            inputs.presig_quadruple().kappa_unmasked().clone(),
            inputs.presig_quadruple().kappa_times_lambda().clone(),
            inputs.presig_quadruple().key_times_lambda().clone()
        );
        assert!(crypto_for(signer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }
        ));
    }

    #[test]
    fn should_fail_to_sign_when_kappa_times_lambda_not_retained_in_signer() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let signer_id = random_receiver_for_inputs(&inputs);
        load_input_transcripts(&env.crypto_components, signer_id, &inputs);
        assert!(crypto_for(signer_id, &env.crypto_components)
            .sign_share(&inputs)
            .is_ok());

        let active_transcripts = hashset!(
            inputs.key_transcript().clone(),
            inputs.presig_quadruple().kappa_unmasked().clone(),
            inputs.presig_quadruple().lambda_masked().clone(),
            inputs.presig_quadruple().key_times_lambda().clone()
        );
        assert!(crypto_for(signer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }
        ));
    }

    #[test]
    fn should_fail_to_sign_when_key_times_lambda_not_retained_in_signer() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let signer_id = random_receiver_for_inputs(&inputs);
        load_input_transcripts(&env.crypto_components, signer_id, &inputs);
        assert!(crypto_for(signer_id, &env.crypto_components)
            .sign_share(&inputs)
            .is_ok());

        let active_transcripts = hashset!(
            inputs.key_transcript().clone(),
            inputs.presig_quadruple().kappa_unmasked().clone(),
            inputs.presig_quadruple().lambda_masked().clone(),
            inputs.presig_quadruple().kappa_times_lambda().clone(),
        );
        assert!(crypto_for(signer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ThresholdEcdsaSignShareError::SecretSharesNotFound { .. }
        ));
    }

    #[test]
    fn should_successfully_sign_when_kappa_unmasked_not_retained_in_signer() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let signer_id = random_receiver_for_inputs(&inputs);
        load_input_transcripts(&env.crypto_components, signer_id, &inputs);
        assert!(crypto_for(signer_id, &env.crypto_components)
            .sign_share(&inputs)
            .is_ok());

        let active_transcripts = hashset!(
            inputs.key_transcript().clone(),
            inputs.presig_quadruple().lambda_masked().clone(),
            inputs.presig_quadruple().kappa_times_lambda().clone(),
            inputs.presig_quadruple().key_times_lambda().clone()
        );
        assert!(crypto_for(signer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn should_successfully_sign_when_key_transcript_not_retained_in_signer_but_quadruple_retained()
    {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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

        let signer_id = random_receiver_for_inputs(&inputs);
        load_input_transcripts(&env.crypto_components, signer_id, &inputs);
        assert!(crypto_for(signer_id, &env.crypto_components)
            .sign_share(&inputs)
            .is_ok());

        let active_transcripts = hashset!(
            inputs.presig_quadruple().kappa_unmasked().clone(),
            inputs.presig_quadruple().lambda_masked().clone(),
            inputs.presig_quadruple().kappa_times_lambda().clone(),
            inputs.presig_quadruple().key_times_lambda().clone()
        );
        assert!(crypto_for(signer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        let result = crypto_for(signer_id, &env.crypto_components).sign_share(&inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_to_create_dealing_when_kappa_unmasked_not_retained() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let masked_key_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let masked_key_transcript =
            run_idkg_and_create_and_verify_transcript(&masked_key_params, &env.crypto_components);

        let unmasked_key_params = build_params_from_previous(
            masked_key_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
        );

        let unmasked_key_transcript =
            run_idkg_and_create_and_verify_transcript(&unmasked_key_params, &env.crypto_components);
        let quadruple = generate_presig_quadruple(
            &env,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &unmasked_key_transcript,
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
        );
        let dealer_id = random_dealer_id(&reshare_params);
        load_input_transcripts(&env.crypto_components, dealer_id, &inputs);

        // make sure creating dealings succeeds with all the transcripts
        let result = crypto_for(dealer_id, &env.crypto_components).create_dealing(&reshare_params);
        assert!(result.is_ok());

        // Do not include kappa unmasked in retained transcripts
        let active_transcripts = hashset!(
            masked_key_transcript,
            unmasked_key_transcript,
            inputs.presig_quadruple().lambda_masked().clone(),
            inputs.presig_quadruple().kappa_times_lambda().clone(),
            inputs.presig_quadruple().key_times_lambda().clone(),
        );
        assert!(crypto_for(dealer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        // Create dealing should now fail
        let result = crypto_for(dealer_id, &env.crypto_components).create_dealing(&reshare_params);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            IDkgCreateDealingError::SecretSharesNotFound { .. }
        ));
    }

    #[test]
    fn should_fail_to_create_dealing_when_reshared_unmasked_key_transcript_not_retained() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let masked_key_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let masked_key_transcript =
            run_idkg_and_create_and_verify_transcript(&masked_key_params, &env.crypto_components);

        let unmasked_key_params = build_params_from_previous(
            masked_key_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript.clone()),
        );

        let unmasked_key_transcript =
            run_idkg_and_create_and_verify_transcript(&unmasked_key_params, &env.crypto_components);

        let reshare_params = build_params_from_previous(
            unmasked_key_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_key_transcript.clone()),
        );

        let dealer_id = random_dealer_id(&reshare_params);
        load_transcript(&masked_key_transcript, &env.crypto_components, dealer_id);
        load_transcript(&unmasked_key_transcript, &env.crypto_components, dealer_id);

        // make sure creating dealings succeeds with all the transcripts
        let result = crypto_for(dealer_id, &env.crypto_components).create_dealing(&reshare_params);
        assert!(result.is_ok());

        // Do not include shared unmasked key transcript in retained transcripts
        let active_transcripts = hashset!(masked_key_transcript,);
        assert!(crypto_for(dealer_id, &env.crypto_components)
            .retain_active_transcripts(&active_transcripts)
            .is_ok());

        // Create dealing should now fail
        let result = crypto_for(dealer_id, &env.crypto_components).create_dealing(&reshare_params);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            IDkgCreateDealingError::SecretSharesNotFound { .. }
        ));
    }
}

mod load_transcript_with_openings {
    use super::*;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgOpening;

    #[test]
    fn should_load_transcript_without_openings_when_none_required() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        let loader_id = random_receiver_id(&params);
        let loader = crypto_for(loader_id, &env.crypto_components);
        let openings = BTreeMap::new();

        let result = loader.load_transcript_with_openings(&transcript, &openings);

        assert!(result.is_ok());
    }

    #[test]
    fn should_load_with_enough_openings() {
        let rng = &mut thread_rng();
        let subnet_size = rng.gen_range(4..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        let reconstruction_threshold =
            usize::try_from(transcript.reconstruction_threshold().get()).expect("invalid number");
        let number_of_openings = reconstruction_threshold;

        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, rng);
        let complaint_with_openings = generate_and_verify_openings_for_complaint(
            number_of_openings,
            &transcript,
            &env,
            complainer,
            complaint,
        );

        let result =
            complainer.load_transcript_with_openings(&transcript, &complaint_with_openings);

        assert!(result.is_ok());
    }
    #[test]
    fn should_fail_because_not_enough_openings() {
        let rng = &mut thread_rng();
        let subnet_size = rng.gen_range(4..6);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let mut transcript =
            run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
        let reconstruction_threshold =
            usize::try_from(transcript.reconstruction_threshold().get()).expect("invalid number");
        let number_of_openings = reconstruction_threshold - 1;

        let (complainer, complaint) =
            generate_single_complaint(&mut transcript, &params, &env, rng);
        let complaint_with_openings = generate_and_verify_openings_for_complaint(
            number_of_openings,
            &transcript,
            &env,
            complainer,
            complaint,
        );

        let result =
            complainer.load_transcript_with_openings(&transcript, &complaint_with_openings);

        assert!(matches!(
            result,
            Err(IDkgLoadTranscriptError::InsufficientOpenings { .. })
        ));
    }

    fn generate_and_verify_openings_for_complaint(
        number_of_openings: usize,
        transcript: &IDkgTranscript,
        env: &CanisterThresholdSigTestEnvironment,
        complainer: &TempCryptoComponent,
        complaint: IDkgComplaint,
    ) -> BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>> {
        let opener_ids = receivers_excluding(&transcript.receivers, &complainer.get_node_id());
        let openings: BTreeMap<_, _> = opener_ids
            .iter()
            .take(number_of_openings)
            .map(|opener_id| {
                let opener = crypto_for(*opener_id, &env.crypto_components);
                let opening =
                    generate_and_verify_opening(opener, complainer, transcript, &complaint);
                (*opener_id, opening)
            })
            .collect();
        assert_eq!(openings.values().len(), number_of_openings);

        let mut complaint_with_openings = BTreeMap::new();
        complaint_with_openings.insert(complaint, openings);
        complaint_with_openings
    }

    fn receivers_excluding(receivers: &IDkgReceivers, excluded_id: &NodeId) -> Vec<NodeId> {
        receivers
            .get()
            .iter()
            .copied()
            .filter(|node_id| *node_id != *excluded_id)
            .collect()
    }

    fn generate_and_verify_opening(
        opener: &TempCryptoComponent,
        complainer: &TempCryptoComponent,
        transcript: &IDkgTranscript,
        complaint: &IDkgComplaint,
    ) -> IDkgOpening {
        let opening = opener
            .open_transcript(transcript, complainer.get_node_id(), complaint)
            .expect("failed creating opening");
        assert!(complainer
            .verify_opening(transcript, opener.get_node_id(), &opening, complaint)
            .is_ok());
        opening
    }
}

mod combine_sig_shares {
    use super::*;

    #[test]
    fn should_combine_sig_shares_successfully() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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
        let combiner_crypto_component = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(combiner_id)
            .build();
        let result = combiner_crypto_component.combine_sig_shares(&inputs, &sig_shares);
        assert!(result.is_ok());
    }
}

mod verify_combined_sig {
    use super::*;

    #[test]
    fn should_verify_sig_shares_and_combined_sig_successfully() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            derivation_path: vec![],
        };

        let seed = Randomness::from(rng.gen::<[u8; 32]>());

        let inputs = ThresholdEcdsaSigInputs::new(
            &derivation_path,
            &rng.gen::<[u8; 32]>(),
            seed,
            quadruple.clone(),
            key_transcript.clone(),
        )
        .expect("failed to create signature inputs");

        let inputs_with_wrong_hash = ThresholdEcdsaSigInputs::new(
            &derivation_path,
            &rng.gen::<[u8; 32]>(),
            seed,
            quadruple,
            key_transcript,
        )
        .expect("failed to create signature inputs");

        let sig_shares: BTreeMap<_, _> = inputs
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

        let verifier_id = random_node_id_excluding(inputs.receivers().get());
        let verifier_crypto_component = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .build();

        // Verify that each signature share can be verified
        for (signer_id, sig_share) in sig_shares.iter() {
            assert!(verifier_crypto_component
                .verify_sig_share(*signer_id, &inputs, sig_share)
                .is_ok());

            // With wrong hash, share does not verify
            assert!(verifier_crypto_component
                .verify_sig_share(*signer_id, &inputs_with_wrong_hash, sig_share)
                .is_err());
        }

        // Combiner can be someone not involved in the IDkg
        let combiner_id = random_node_id_excluding(inputs.receivers().get());
        let combiner_crypto_component = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(combiner_id)
            .build();
        let signature = combiner_crypto_component
            .combine_sig_shares(&inputs, &sig_shares)
            .expect("Failed to generate signature");

        assert!(verifier_crypto_component
            .verify_combined_sig(&inputs, &signature)
            .is_ok());

        assert!(verifier_crypto_component
            .verify_combined_sig(&inputs_with_wrong_hash, &signature)
            .is_err());

        let modified_signature = ThresholdEcdsaCombinedSignature {
            signature: {
                let mut s = signature.signature;
                s[5] ^= 1;
                s
            },
        };

        assert!(verifier_crypto_component
            .verify_combined_sig(&inputs, &modified_signature)
            .is_err());
    }

    #[test]
    fn should_run_threshold_ecdsa_protocol_with_single_node() {
        let subnet_size = 1;

        // Test environment for ECDSA
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        // Generate the key transcript containing the master key
        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);

        // Extract the master key from the key transcript
        let master_ecdsa_key = get_tecdsa_master_public_key(&key_transcript);

        assert!(master_ecdsa_key.is_ok());

        let derivation_path = ExtendedDerivationPath {
            caller: PrincipalId::new_user_test_id(1),
            derivation_path: vec![],
        };

        // Derive the key for principal
        let derived_public_key =
            derive_tecdsa_public_key(&master_ecdsa_key.unwrap(), &derivation_path);

        assert!(derived_public_key.is_ok());

        let mut rng = thread_rng();
        let nonce = Randomness::from(rng.gen::<[u8; 32]>());
        let message_hash = &rng.gen::<[u8; 32]>();

        let sig_inputs = generate_tecdsa_protocol_inputs(
            &env,
            &key_transcript,
            message_hash,
            nonce,
            derivation_path,
            AlgorithmId::ThresholdEcdsaSecp256k1,
        );

        // Compute the threshold ECDSA signature
        let signature = run_tecdsa_protocol(&env, &sig_inputs);

        // Verify that the returned signature is valid.
        let verifier_id = random_node_id_excluding(sig_inputs.receivers().get());
        let verifier_crypto_component = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .build();

        assert!(verifier_crypto_component
            .verify_combined_sig(&sig_inputs, &signature)
            .is_ok());
    }

    #[test]
    fn should_fail_combine_sig_shares_with_insufficient_shares() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

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
        let result = crypto_for(combiner_id, &env.crypto_components)
            .combine_sig_shares(&inputs, &sig_shares);
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold {threshold, share_count}
            if threshold == inputs.reconstruction_threshold().get() && share_count == (threshold as usize - 1)
        ));
    }

    #[test]
    fn should_verify_combined_sig_successfully() {
        use ic_crypto_internal_basic_sig_ecdsa_secp256k1 as ecdsa_secp256k1;
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let quadruple =
            generate_presig_quadruple(&env, AlgorithmId::ThresholdEcdsaSecp256k1, &key_transcript);

        let master_public_key =
            get_tecdsa_master_public_key(&key_transcript).expect("Master key extraction failed");
        let (inputs, public_key) = {
            let derivation_path = ExtendedDerivationPath {
                caller: PrincipalId::new_user_test_id(1),
                derivation_path: vec![],
            };

            let hashed_message = rng.gen::<[u8; 32]>();
            let seed = Randomness::from(rng.gen::<[u8; 32]>());

            let inputs = ThresholdEcdsaSigInputs::new(
                &derivation_path,
                &hashed_message,
                seed,
                quadruple,
                key_transcript,
            )
            .expect("failed to create signature inputs");
            let public_key = derive_tecdsa_public_key(&master_public_key, &derivation_path)
                .expect("Public key derivation failed");
            (inputs, public_key)
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
        let result = crypto_for(verifier_id, &env.crypto_components)
            .verify_combined_sig(&inputs, &combined_sig);
        assert!(result.is_ok());
        let ecdsa_sig = ecdsa_secp256k1::types::SignatureBytes(
            <[u8; 64]>::try_from(combined_sig.signature).expect("Expected 64 bytes"),
        );
        let ecdsa_pk = ecdsa_secp256k1::types::PublicKeyBytes(public_key.public_key);
        assert!(
            ecdsa_secp256k1::api::verify(&ecdsa_sig, inputs.hashed_message(), &ecdsa_pk).is_ok(),
            "ECDSA sig verification failed"
        );
    }
}

mod get_tecdsa_master_public_key {
    use super::*;

    #[test]
    fn should_return_ecdsa_public_key() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
        let result = get_tecdsa_master_public_key(&key_transcript);
        assert!(result.is_ok());
        let master_public_key = result.expect("Master key extraction failed");
        assert_eq!(master_public_key.algorithm_id, AlgorithmId::EcdsaSecp256k1);
        assert_eq!(master_public_key.public_key.len(), 33); // 1 byte header + 32 bytes of field element
    }

    #[test]
    fn should_derive_equal_ecdsa_public_keys() {
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
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
        let mut rng = thread_rng();

        let subnet_size = rng.gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let key_transcript = generate_key_transcript(&env, AlgorithmId::ThresholdEcdsaSecp256k1);
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
}

mod verify_dealing_private {
    use super::*;
    use ic_crypto_test_utils_canister_threshold_sigs::IntoBuilder;
    use ic_types::crypto::canister_threshold_sig::error::IDkgVerifyDealingPrivateError;

    #[test]
    fn should_verify_dealing_private() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id);
        let receiver_id = random_receiver_id(&params);
        let receiver = crypto_for(receiver_id, &env.crypto_components);

        let result = receiver.verify_dealing_private(&params, &signed_dealing);

        assert!(result.is_ok());
    }

    #[test]
    fn should_verify_dealing_private_with_wrong_signature() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let signed_dealing_with_corrupted_signature =
            create_signed_dealing(&params, &env.crypto_components, dealer_id)
                .into_builder()
                .corrupt_signature()
                .build();
        let receiver_id = random_receiver_id(&params);
        let receiver = crypto_for(receiver_id, &env.crypto_components);

        let (result_verify_public, result_verify_private) = verify_dealing_public_and_private(
            receiver,
            &params,
            &signed_dealing_with_corrupted_signature,
        );

        assert!(matches!(
            (result_verify_public, result_verify_private),
            (
                Err(IDkgVerifyDealingPublicError::InvalidSignature { .. }),
                Ok(())
            )
        ));
    }

    #[test]
    fn should_verify_when_dealer_is_also_a_receiver() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id);
        let dealer = crypto_for(dealer_id, &env.crypto_components);

        let result = dealer.verify_dealing_private(&params, &signed_dealing);

        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_on_wrong_transcript_id() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let dealer = crypto_for(dealer_id, &env.crypto_components);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id);
        let receiver_id = random_receiver_id(&params);
        let receiver = crypto_for(receiver_id, &env.crypto_components);

        let result = receiver.verify_dealing_private(
            &params,
            &signed_dealing
                .into_builder()
                .corrupt_transcript_id()
                .build_with_signature(&params, dealer, dealer_id),
        );

        assert!(
            matches!( result, Err(IDkgVerifyDealingPrivateError::InvalidArgument(reason)) if reason.starts_with("mismatching transcript IDs"))
        );
    }

    #[test]
    fn should_fail_on_wrong_internal_dealing_raw() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let dealer = crypto_for(dealer_id, &env.crypto_components);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id);
        let receiver_id = random_receiver_id(&params);
        let receiver = crypto_for(receiver_id, &env.crypto_components);

        let result = receiver.verify_dealing_private(
            &params,
            &signed_dealing
                .into_builder()
                .corrupt_internal_dealing_raw_by_flipping_bit()
                .build_with_signature(&params, dealer, dealer_id),
        );

        assert!(
            matches!( result, Err(IDkgVerifyDealingPrivateError::InvalidArgument(reason)) if reason.starts_with("failed to deserialize internal dealing"))
        );
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

    #[test]
    fn should_run_verify_dealing_public() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);

        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id);

        let verifier_id =
            random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);
        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_verify_dealing_public_with_invalid_signature() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id)
            .into_builder()
            .corrupt_signature()
            .build();

        let verifier_id =
            random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert!(matches!( result,
            Err(IDkgVerifyDealingPublicError::InvalidSignature { error, .. })
            if error.contains("Invalid basic signature on signed iDKG dealing from signer")
        ));
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_transcript_id() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let dealer = crypto_for(dealer_id, &env.crypto_components);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id)
            .into_builder()
            .corrupt_transcript_id()
            .build_with_signature(&params, dealer, dealer_id);

        let verifier_id =
            random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert!(matches!(
            result,
            Err(IDkgVerifyDealingPublicError::TranscriptIdMismatch)
        ));
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_dealer_id() {
        let subnet_size = thread_rng().gen_range(2..10); //need at least 2 nodes to have a dealer and another node
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let non_dealer_node = *params
            .dealers()
            .get()
            .iter()
            .find(|node_id| **node_id != dealer_id)
            .expect("not enough nodes");
        let non_dealer = crypto_for(non_dealer_node, &env.crypto_components);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id)
            .into_builder()
            .with_dealer_id(non_dealer_node)
            .build_with_signature(&params, non_dealer, non_dealer_node);

        let verifier_id =
            random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert!(matches!(
            result,
            Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason == "InvalidProof"
        ));
    }

    #[test]
    fn should_fail_verify_dealing_public_with_wrong_internal_dealing_raw() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);
        let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let dealer_id = random_dealer_id(&params);
        let dealer = crypto_for(dealer_id, &env.crypto_components);
        let signed_dealing = create_signed_dealing(&params, &env.crypto_components, dealer_id)
            .into_builder()
            .corrupt_internal_dealing_raw_by_flipping_bit()
            .build_with_signature(&params, dealer, dealer_id);

        let verifier_id =
            random_node_id_excluding(&env.crypto_components.keys().cloned().collect());
        let verifier = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(verifier_id)
            .build();

        let result = verifier.verify_dealing_public(&params, &signed_dealing);

        assert!(matches!(
            result,
            Err(IDkgVerifyDealingPublicError::InvalidDealing {reason}) if reason.starts_with("SerializationError")
        ));
    }
}

mod verify_initial_dealings {
    use super::*;

    #[test]
    fn should_successfully_verify_initial_dealing() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let (initial_dealings, reshare_of_unmasked_params) = generate_initial_dealings(&env, false);

        let verifier = random_receiver_id(&reshare_of_unmasked_params);
        assert!(crypto_for(verifier, &env.crypto_components)
            .verify_initial_dealings(&reshare_of_unmasked_params, &initial_dealings)
            .is_ok());
    }

    #[test]
    fn should_fail_on_mismatching_transcript_params() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let (initial_dealings, reshare_of_unmasked_params) = generate_initial_dealings(&env, false);
        let other_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let verifier = random_receiver_id(&reshare_of_unmasked_params);
        assert!(matches!(
            crypto_for(verifier, &env.crypto_components)
                .verify_initial_dealings(&other_params, &initial_dealings),
            Err(IDkgVerifyInitialDealingsError::MismatchingTranscriptParams)
        ));
    }

    #[test]
    fn should_fail_if_public_verification_fails() {
        let subnet_size = thread_rng().gen_range(1..10);
        let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

        let (initial_dealings_with_first_currupted, reshare_of_unmasked_params) =
            generate_initial_dealings(&env, true);

        let verifier = random_receiver_id(&reshare_of_unmasked_params);
        let result = crypto_for(verifier, &env.crypto_components).verify_initial_dealings(
            &reshare_of_unmasked_params,
            &initial_dealings_with_first_currupted,
        );
        assert!(
            matches!(result, Err(IDkgVerifyInitialDealingsError::PublicVerificationFailure { verify_dealing_public_error, ..})
                if matches!(verify_dealing_public_error, IDkgVerifyDealingPublicError::InvalidSignature { .. })
            )
        );
    }

    fn generate_initial_dealings(
        env: &CanisterThresholdSigTestEnvironment,
        corrupt_first_dealing: bool,
    ) -> (InitialIDkgDealings, IDkgTranscriptParams) {
        let initial_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let initial_transcript =
            run_idkg_and_create_and_verify_transcript(&initial_params, &env.crypto_components);

        let unmasked_params = build_params_from_previous(
            initial_params,
            IDkgTranscriptOperation::ReshareOfMasked(initial_transcript),
        );
        let unmasked_transcript =
            run_idkg_and_create_and_verify_transcript(&unmasked_params, &env.crypto_components);

        let reshare_of_unmasked_params = build_params_from_previous(
            unmasked_params,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        );
        let signed_dealings = load_previous_transcripts_and_create_signed_dealings(
            &reshare_of_unmasked_params,
            &env.crypto_components,
        );
        let mut signed_dealings_vec = signed_dealings
            .into_iter()
            .map(|(_dealer_id, signed_dealing)| signed_dealing)
            .collect::<Vec<_>>();
        if corrupt_first_dealing {
            if let Some(first_signed_dealing) = signed_dealings_vec.first_mut() {
                let corrupted_sig = {
                    let mut sig_clone = first_signed_dealing.signature.signature.get_ref().clone();
                    sig_clone.0.push(0xff);
                    BasicSigOf::new(sig_clone)
                };
                first_signed_dealing.signature.signature = corrupted_sig;
            }
        }
        let initial_dealings =
            InitialIDkgDealings::new(reshare_of_unmasked_params.clone(), signed_dealings_vec)
                .expect("failed to create initial dealings");

        (initial_dealings, reshare_of_unmasked_params)
    }
}

mod open_transcript {
    use super::*;

    #[test]
    fn should_open_transcript_successfully() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let result = crypto_for(opener_id, &env.crypto_components).open_transcript(
            &transcript,
            complainer_id,
            &complaint,
        );
        assert!(result.is_ok(), "Unexpected failure: {:?}", result);
    }

    #[test]
    fn should_fail_open_transcript_with_invalid_share() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = complainer_id; // opener's share is invalid
        let result = crypto_for(opener_id, &env.crypto_components).open_transcript(
            &transcript,
            complainer_id,
            &complaint,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IDkgOpenTranscriptError::InternalError { .. })
        ));
        assert!(
            format!("{:?}", result).contains("InvalidCommitment"),
            "result: {:?}",
            result
        );
    }

    #[test]
    fn should_fail_open_transcript_when_missing_a_dealing() {
        let (env, mut transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        // Remove the corrupted dealing from the transcript.
        transcript.verified_dealings.remove(
            &transcript
                .index_for_dealer_id(complaint.dealer_id)
                .expect("Missing dealer of corrupted dealing"),
        );

        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);
        let result = crypto_for(opener_id, &env.crypto_components).open_transcript(
            &transcript,
            complainer_id,
            &complaint,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IDkgOpenTranscriptError::InternalError { .. })
        ));
        assert!(
            format!("{:?}", result).contains("MissingDealing"),
            "result: {:?}",
            result
        );
    }

    #[test]
    fn should_fail_open_transcript_with_an_invalid_complaint() {
        let (env, transcript, mut complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        // Set "wrong" dealer_id in the complaint
        complaint.dealer_id = random_dealer_id_excluding(&transcript, complaint.dealer_id);

        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);
        let result = crypto_for(opener_id, &env.crypto_components).open_transcript(
            &transcript,
            complainer_id,
            &complaint,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IDkgOpenTranscriptError::InternalError { .. })
        ));
        assert!(
            format!("{:?}", result).contains("InvalidComplaint"),
            "result: {:?}",
            result
        );
    }

    #[test]
    fn should_fail_open_transcript_with_a_valid_complaint_but_wrong_transcript() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();

        // Create another environment of the same size, and generate a trancript for it.
        let env_2 = CanisterThresholdSigTestEnvironment::new(env.crypto_components.len());
        let params_2 = env_2.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
        let transcript_2 =
            run_idkg_and_create_and_verify_transcript(&params_2, &env_2.crypto_components);

        // Try `open_transcript` but with a wrong transcript.
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);
        let result = crypto_for(opener_id, &env.crypto_components).open_transcript(
            &transcript_2,
            complainer_id,
            &complaint,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IDkgOpenTranscriptError::InternalError { .. })
        ));
        assert!(
            format!("{:?}", result).contains("InvalidArgumentMismatchingTranscriptIDs"),
            "result: {:?}",
            result
        );
    }
}

mod verify_opening {
    use super::*;

    #[test]
    fn should_verify_opening_successfully() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let opening = crypto_for(opener_id, &env.crypto_components)
            .open_transcript(&transcript, complainer_id, &complaint)
            .expect("Unexpected failure of open_transcript");
        let verifier_id = random_receiver_id(
            &env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1),
        );
        let result = crypto_for(verifier_id, &env.crypto_components).verify_opening(
            &transcript,
            opener_id,
            &opening,
            &complaint,
        );
        assert!(result.is_ok(), "Failure of verify_opening(): {:?}", result);
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_transcript_id_in_opening() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let mut opening = crypto_for(opener_id, &env.crypto_components)
            .open_transcript(&transcript, complainer_id, &complaint)
            .expect("Unexpected failure of open_transcript");
        let wrong_transcript_id = dummy_idkg_transcript_id_for_tests(1);
        assert_ne!(
            opening.transcript_id, wrong_transcript_id,
            "Unexpected collision with a random transcript_id"
        );
        opening.transcript_id = wrong_transcript_id;
        let verifier_id = random_receiver_id(
            &env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1),
        );
        let result = crypto_for(verifier_id, &env.crypto_components).verify_opening(
            &transcript,
            opener_id,
            &opening,
            &complaint,
        );
        assert!(
            matches!(result, Err(IDkgVerifyOpeningError::TranscriptIdMismatch)),
            "{:?}",
            result
        );
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_transcript_id_in_complaint() {
        let (env, transcript, mut complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let opening = crypto_for(opener_id, &env.crypto_components)
            .open_transcript(&transcript, complainer_id, &complaint)
            .expect("Unexpected failure of open_transcript");
        let wrong_transcript_id = dummy_idkg_transcript_id_for_tests(1);
        assert_ne!(
            complaint.transcript_id, wrong_transcript_id,
            "Unexpected collision with a random transcript_id"
        );
        complaint.transcript_id = wrong_transcript_id;
        let verifier_id = random_receiver_id(
            &env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1),
        );
        let result = crypto_for(verifier_id, &env.crypto_components).verify_opening(
            &transcript,
            opener_id,
            &opening,
            &complaint,
        );
        assert!(
            matches!(result, Err(IDkgVerifyOpeningError::TranscriptIdMismatch)),
            "{:?}",
            result
        );
    }

    #[test]
    fn should_fail_verify_opening_with_inconsistent_dealer_id() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let mut opening = crypto_for(opener_id, &env.crypto_components)
            .open_transcript(&transcript, complainer_id, &complaint)
            .expect("Unexpected failure of open_transcript");
        opening.dealer_id = random_dealer_id_excluding(&transcript, opening.dealer_id);
        let verifier_id = random_receiver_id(
            &env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1),
        );
        let result = crypto_for(verifier_id, &env.crypto_components).verify_opening(
            &transcript,
            opener_id,
            &opening,
            &complaint,
        );
        assert!(
            matches!(result, Err(IDkgVerifyOpeningError::DealerIdMismatch)),
            "{:?}",
            result
        );
    }

    #[test]
    fn should_fail_verify_opening_when_opener_is_not_a_receiver() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let opening = crypto_for(opener_id, &env.crypto_components)
            .open_transcript(&transcript, complainer_id, &complaint)
            .expect("Unexpected failure of open_transcript");
        let verifier_id = random_receiver_id(
            &env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1),
        );
        let wrong_opener_id = node_id(123456789);
        assert!(
            !transcript.receivers.get().contains(&wrong_opener_id),
            "Wrong opener_id unexpectedly in receivers"
        );
        let result = crypto_for(verifier_id, &env.crypto_components).verify_opening(
            &transcript,
            wrong_opener_id,
            &opening,
            &complaint,
        );
        assert!(
            matches!(
                result,
                Err(IDkgVerifyOpeningError::MissingOpenerInReceivers { .. })
            ),
            "{:?}",
            result
        );
    }

    #[test]
    fn should_fail_verify_opening_with_corrupted_opening() {
        let (env, transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let mut opening = crypto_for(opener_id, &env.crypto_components)
            .open_transcript(&transcript, complainer_id, &complaint)
            .expect("Unexpected failure of open_transcript");
        opening
            .internal_opening_raw
            .truncate(opening.internal_opening_raw.len() - 1);
        let verifier_id = random_receiver_id(
            &env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1),
        );
        let result = crypto_for(verifier_id, &env.crypto_components).verify_opening(
            &transcript,
            opener_id,
            &opening,
            &complaint,
        );
        assert!(
            matches!(result, Err(IDkgVerifyOpeningError::InternalError { .. })),
            "{:?}",
            result
        );
    }

    #[test]
    fn should_fail_verify_opening_when_dealing_is_missing() {
        let (env, mut transcript, complaint, complainer_id) =
            environment_with_transcript_and_complaint();
        let opener_id = random_receiver_id_excluding(&transcript.receivers, complainer_id);

        let opening = crypto_for(opener_id, &env.crypto_components)
            .open_transcript(&transcript, complainer_id, &complaint)
            .expect("Unexpected failure of open_transcript");
        let verifier_id = random_receiver_id(
            &env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1),
        );
        let dealings = transcript.verified_dealings.clone();
        let (dealer_index, _signed_dealing) = dealings
            .iter()
            .find(|(_index, batch_signed_dealing)| {
                batch_signed_dealing.dealer_id() == complaint.dealer_id
            })
            .expect("Inconsistent transcript");
        transcript.verified_dealings.remove(dealer_index);
        let result = crypto_for(verifier_id, &env.crypto_components).verify_opening(
            &transcript,
            opener_id,
            &opening,
            &complaint,
        );
        assert!(
            matches!(
                result,
                Err(IDkgVerifyOpeningError::MissingDealingInTranscript { .. })
            ),
            "{:?}",
            result
        );
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
        let transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
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
        derivation_path: vec![],
    };

    ThresholdEcdsaSigInputs::new(
        &derivation_path,
        &[0u8; 32],
        Randomness::from([0_u8; 32]),
        fake_presig_quadruple,
        fake_key,
    )
    .expect("failed to create signature inputs")
}

/// Corrupts the dealing by modifying the ciphertext intended for the specified receiver.
fn corrupt_signed_dealing_for_one_receiver(
    dealing_index_to_corrupt: NodeIndex,
    dealings: &mut BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
    receiver_index: NodeIndex,
) {
    let mut signed_dealing = dealings
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

/// Sets up a testing environment for canister treshold signatures for a subnet size
/// picked randomly in a range [2..10], runs IDKG to generate transcript, corrupts
/// a random dealing for a random receiver, and generates the corresponding complaint.
/// Returns the environment, the corrupted transcript, the complaint and the
/// corresponding complainer id.
fn environment_with_transcript_and_complaint() -> (
    CanisterThresholdSigTestEnvironment,
    IDkgTranscript,
    IDkgComplaint,
    NodeId,
) {
    let rng = &mut thread_rng();
    // need min. 1 non-complaining node, and enough nodes that after
    // removing all but collection threshold # of dealings, at least
    // one dealing remains to corrupt

    let subnet_size = rng.gen_range(4..10);
    let env = CanisterThresholdSigTestEnvironment::new(subnet_size);

    let params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let mut transcript = run_idkg_and_create_and_verify_transcript(&params, &env.crypto_components);
    let (complainer, complaint) = generate_single_complaint(&mut transcript, &params, &env, rng);
    let complainer_id = complainer.get_node_id();

    (env, transcript, complaint, complainer_id)
}

fn generate_single_complaint<'a>(
    transcript: &mut IDkgTranscript,
    params: &IDkgTranscriptParams,
    env: &'a CanisterThresholdSigTestEnvironment,
    rng: &mut ThreadRng,
) -> (&'a TempCryptoComponent, IDkgComplaint) {
    let (complainer, _, mut complaints) = generate_complaints(transcript, 1, params, env, rng);
    (
        complainer,
        complaints.pop().expect("expected one complaint"),
    )
}

fn generate_complaints<'a>(
    transcript: &mut IDkgTranscript,
    number_of_complaints: usize,
    params: &IDkgTranscriptParams,
    env: &'a CanisterThresholdSigTestEnvironment,
    rng: &mut ThreadRng,
) -> (&'a TempCryptoComponent, Vec<NodeIndex>, Vec<IDkgComplaint>) {
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
        .iter()
        .map(|(index, _signed_dealing)| *index)
        .choose_multiple(rng, number_of_complaints);
    assert_eq!(dealing_indices_to_corrupt.len(), number_of_complaints);

    let complainer_id = random_receiver_id(params);
    let complainer_index = params
        .receiver_index(complainer_id)
        .expect(&*format!("Missing receiver {:?}", complainer_id));
    dealing_indices_to_corrupt
        .iter()
        .for_each(|index_to_corrupt| {
            corrupt_signed_dealing_for_one_receiver(
                *index_to_corrupt,
                &mut transcript.verified_dealings,
                complainer_index,
            )
        });

    let complainer = crypto_for(complainer_id, &env.crypto_components);
    let complaints = {
        let complaints = complainer
            .load_transcript(transcript)
            .expect("expected complaints");
        assert_eq!(complaints.len(), number_of_complaints);
        complaints
    };

    (complainer, dealing_indices_to_corrupt, complaints)
}
