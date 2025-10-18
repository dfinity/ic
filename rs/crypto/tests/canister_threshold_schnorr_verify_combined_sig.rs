use assert_matches::assert_matches;
use ic_crypto::get_master_public_key_from_transcript;
use ic_crypto_internal_threshold_sig_canister_threshold_sig_test_utils::{
    verify_bip340_signature_using_third_party, verify_ed25519_signature_using_third_party,
    verify_taproot_signature_using_third_party,
};
use ic_crypto_test_utils_canister_threshold_sigs::{
    CorruptBytes, IntoBuilder, generate_key_transcript, random_crypto_component_not_in_receivers,
    run_tschnorr_protocol, schnorr::environment_with_sig_inputs,
    schnorr_sig_share_from_each_receiver,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_utils_canister_threshold_sig::derive_threshold_public_key;
use ic_interfaces::crypto::ThresholdSchnorrSigVerifier;
use ic_types::crypto::canister_threshold_sig::{
    ThresholdSchnorrSigInputs, error::ThresholdSchnorrVerifyCombinedSigError, idkg::IDkgTranscript,
};
use ic_types::crypto::{AlgorithmId, ExtendedDerivationPath};

#[test]
fn should_verify_combined_sig() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs.as_ref());
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
        let signature = combiner_crypto_component
            .combine_sig_shares(&inputs.as_ref(), &sig_shares)
            .expect("Failed to generate signature");
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let result = verifier_crypto_component.verify_combined_sig(&inputs.as_ref(), &signature);

        assert_eq!(result, Ok(()));
    }
}

#[test]
fn should_verify_combined_signature_with_usual_basic_sig_verification() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let combined_sig = run_tschnorr_protocol(&env, &inputs.as_ref(), rng);
        let master_public_key = get_master_public_key_from_transcript(inputs.key_transcript())
            .expect("Master key extraction failed");
        let canister_public_key = derive_threshold_public_key(
            &master_public_key,
            &ExtendedDerivationPath {
                caller: inputs.caller,
                derivation_path: inputs.derivation_path.clone(),
            },
        )
        .expect("Public key derivation failed");

        match alg {
            AlgorithmId::ThresholdSchnorrBip340 => {
                if let Some(ttr) = inputs.taproot_tree_root.as_deref() {
                    assert!(verify_taproot_signature_using_third_party(
                        &canister_public_key.public_key,
                        &combined_sig.signature,
                        inputs.as_ref().message(),
                        ttr,
                    ))
                } else {
                    assert!(verify_bip340_signature_using_third_party(
                        &canister_public_key.public_key,
                        &combined_sig.signature,
                        inputs.as_ref().message(),
                    ))
                }
            }
            AlgorithmId::ThresholdEd25519 => {
                assert!(verify_ed25519_signature_using_third_party(
                    &canister_public_key.public_key,
                    &combined_sig.signature,
                    inputs.as_ref().message(),
                ))
            }
            alg if alg.is_threshold_schnorr() => {
                panic!("this test is not implemented for {alg:?}")
            }
            _ => panic!("unexpected algorithm {alg:?}"),
        }
    }
}

#[test]
fn should_run_threshold_schnorr_protocol_with_single_node() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..=1, alg, rng);
        let signature = run_tschnorr_protocol(&env, &inputs.as_ref(), rng);
        let verifier = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        assert_eq!(
            verifier.verify_combined_sig(&inputs.as_ref(), &signature),
            Ok(())
        );
    }
}

#[test]
fn should_fail_verifying_corrupted_combined_sig() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs.as_ref());
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
        let corrupted_signature = combiner_crypto_component
            .combine_sig_shares(&inputs.as_ref(), &sig_shares)
            .expect("Failed to generate signature")
            .clone_with_bit_flipped();
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let result =
            verifier_crypto_component.verify_combined_sig(&inputs.as_ref(), &corrupted_signature);

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifyCombinedSigError::InvalidSignature)
        );
    }
}

#[test]
fn should_fail_deserializing_signature_with_invalid_length() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs.as_ref());
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
        let mut corrupted_signature = combiner_crypto_component
            .combine_sig_shares(&inputs.as_ref(), &sig_shares)
            .expect("Failed to generate signature");
        corrupted_signature.signature.pop();
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let result =
            verifier_crypto_component.verify_combined_sig(&inputs.as_ref(), &corrupted_signature);

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifyCombinedSigError::SerializationError { .. })
        );
    }
}

#[test]
fn should_fail_when_key_internal_transcript_raw_switched() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, dealers, receivers) = environment_with_sig_inputs(1..10, alg, rng);
        let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs.as_ref());
        let combiner_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
        let signature = combiner_crypto_component
            .combine_sig_shares(&inputs.as_ref(), &sig_shares)
            .expect("Failed to generate signature");
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let another_key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
        assert_ne!(inputs.key_transcript(), &another_key_transcript);
        let key_transcript_with_other_internal_raw = IDkgTranscript {
            internal_transcript_raw: another_key_transcript.internal_transcript_raw,
            ..inputs.key_transcript().clone()
        };
        let inputs_with_other_key_internal_transcript_raw = ThresholdSchnorrSigInputs::new(
            &inputs.caller,
            &inputs.derivation_path,
            &inputs.message,
            inputs.taproot_tree_root.as_deref(),
            &inputs.nonce,
            &inputs.presig_transcript,
            &key_transcript_with_other_internal_raw,
        )
        .expect("invalid Schnorr inputs");

        let result = verifier_crypto_component
            .verify_combined_sig(&inputs_with_other_key_internal_transcript_raw, &signature);

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifyCombinedSigError::InvalidSignature)
        );
    }
}

#[test]
fn should_fail_verifying_combined_sig_for_inputs_with_wrong_message() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let sig_shares = schnorr_sig_share_from_each_receiver(&env, &inputs.as_ref());
        let combiner = random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);
        let signature = combiner
            .combine_sig_shares(&inputs.as_ref(), &sig_shares)
            .expect("Failed to generate signature");
        let verifier_crypto_component =
            random_crypto_component_not_in_receivers(&env, inputs.receivers(), rng);

        let result = verifier_crypto_component.verify_combined_sig(
            &inputs.into_builder().corrupt_message().build().as_ref(),
            &signature,
        );

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifyCombinedSigError::InvalidSignature)
        );
    }
}
