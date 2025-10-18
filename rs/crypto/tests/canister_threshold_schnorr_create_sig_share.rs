use assert_matches::assert_matches;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils_canister_threshold_sigs::{
    generate_key_transcript, random_node_id_excluding, schnorr::environment_with_sig_inputs,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::{IDkgProtocol, ThresholdSchnorrSigner};
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::canister_threshold_sig::error::ThresholdSchnorrCreateSigShareError;
use maplit::hashset;
use std::sync::Arc;

#[test]
fn should_create_signature_share_successfully_with_new_key() {
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let receiver = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);
        receiver.load_tschnorr_sig_transcripts(&inputs.as_ref());
        let result = receiver.create_sig_share(&inputs.as_ref());
        assert_matches!(result, Ok(_));
    }
}

#[test]
fn should_fail_to_create_signature_if_not_receiver() {
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let bad_signer_id = random_node_id_excluding(inputs.receivers().get(), rng);
        let bad_crypto_component = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&env.registry) as Arc<_>)
            .with_node_id(bad_signer_id)
            .with_rng(rng.fork())
            .build();

        assert_eq!(
            bad_crypto_component.create_sig_share(&inputs.as_ref()),
            Err(ThresholdSchnorrCreateSigShareError::NotAReceiver)
        );
    }
}

#[test]
fn should_fail_to_sign_when_input_transcripts_are_not_retained() {
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, dealers, receivers) = environment_with_sig_inputs(1..10, alg, rng);
        let receiver = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);
        receiver.load_tschnorr_sig_transcripts(&inputs.as_ref());
        assert_matches!(receiver.create_sig_share(&inputs.as_ref()), Ok(_));
        let another_key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
        let active_transcripts = hashset!(another_key_transcript);
        assert_eq!(
            receiver.retain_active_transcripts(&active_transcripts),
            Ok(())
        );

        let result = receiver.create_sig_share(&inputs.as_ref());
        assert_matches!(
            result,
            Err(ThresholdSchnorrCreateSigShareError::SecretSharesNotFound { .. })
        );
    }
}

#[test]
fn should_fail_to_sign_when_only_key_transcript_is_not_retained() {
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let receiver = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);
        receiver.load_tschnorr_sig_transcripts(&inputs.as_ref());
        assert_matches!(receiver.create_sig_share(&inputs.as_ref()), Ok(_));
        let active_transcripts = hashset!(inputs.presig_transcript().blinder_unmasked().clone());
        assert_eq!(
            receiver.retain_active_transcripts(&active_transcripts),
            Ok(())
        );

        let result = receiver.create_sig_share(&inputs.as_ref());
        assert_matches!(
            result,
            Err(ThresholdSchnorrCreateSigShareError::SecretSharesNotFound { .. })
        );
    }
}

#[test]
fn should_fail_to_sign_when_only_presig_transcript_is_not_retained() {
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let receiver = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);
        receiver.load_tschnorr_sig_transcripts(&inputs.as_ref());
        assert_matches!(receiver.create_sig_share(&inputs.as_ref()), Ok(_));
        let active_transcripts = hashset!(inputs.key_transcript().clone());
        assert_eq!(
            receiver.retain_active_transcripts(&active_transcripts),
            Ok(())
        );

        let result = receiver.create_sig_share(&inputs.as_ref());
        assert_matches!(
            result,
            Err(ThresholdSchnorrCreateSigShareError::SecretSharesNotFound { .. })
        );
    }
}
