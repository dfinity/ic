use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, CorruptBytes, IntoBuilder, generate_key_transcript,
    random_receiver_id, random_receiver_id_excluding, schnorr::environment_with_sig_inputs,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces::crypto::{ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdSchnorrSigInputs, ThresholdSchnorrSigShare,
    error::ThresholdSchnorrVerifySigShareError, idkg::IDkgTranscript,
};
use ic_types::{NodeId, crypto::AlgorithmId};
use rand::{CryptoRng, RngCore};

#[test]
fn should_verify_sig_share_successfully() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
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
fn should_fail_verifying_inputs_with_wrong_message() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let inputs_with_wrong_message = inputs.clone().into_builder().corrupt_message().build();
        let (signer_id, sig_share) =
            signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
        let verifier = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);

        let result =
            verifier.verify_sig_share(signer_id, &inputs_with_wrong_message.as_ref(), &sig_share);

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifySigShareError::InvalidSignatureShare)
        );
    }
}

#[test]
fn should_fail_verifying_inputs_with_wrong_nonce() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
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
            Err(ThresholdSchnorrVerifySigShareError::InvalidSignatureShare)
        );
    }
}

#[test]
fn should_fail_verifying_corrupted_sig_share() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let (signer_id, corrupted_sig_share) = {
            let (signer_id, sig_share) =
                signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
            (signer_id, sig_share.clone_with_bit_flipped())
        };
        let verifier = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);

        let result = verifier.verify_sig_share(signer_id, &inputs.as_ref(), &corrupted_sig_share);

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifySigShareError::InvalidSignatureShare)
        );
    }
}

#[test]
fn should_verify_sig_share_from_another_signer_when_threshold_1() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
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
fn should_fail_verifying_sig_share_from_another_signer_with_threshold_greater_than_1() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
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
            Err(ThresholdSchnorrVerifySigShareError::InvalidSignatureShare)
        );
    }
}

#[test]
fn should_fail_verifying_sig_share_for_unknown_signer() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
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
            Err(ThresholdSchnorrVerifySigShareError::InvalidArgumentMissingSignerInTranscript { signer_id })
            if signer_id == unknown_signer_id
        );
    }
}

#[test]
fn should_fail_deserializing_invalid_sig_share() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, _, _) = environment_with_sig_inputs(1..10, alg, rng);
        let verifier = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);
        let signer_id = random_receiver_id(inputs.receivers(), rng);
        let invalid_sig_share = ThresholdSchnorrSigShare {
            sig_share_raw: Vec::new(),
        };

        let result = verifier.verify_sig_share(signer_id, &inputs.as_ref(), &invalid_sig_share);

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifySigShareError::SerializationError { .. })
        )
    }
}

#[test]
fn should_fail_when_key_internal_transcript_raw_switched() {
    let rng = &mut reproducible_rng();
    for alg in AlgorithmId::all_threshold_schnorr_algorithms() {
        let (env, inputs, dealers, receivers) = environment_with_sig_inputs(1..10, alg, rng);
        let (signer_id, sig_share) =
            signature_share_from_random_receiver(&env, &inputs.as_ref(), rng);
        let verifier = env
            .nodes
            .random_filtered_by_receivers(inputs.receivers(), rng);

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
            None,
            &inputs.nonce,
            inputs.presig_transcript(),
            &key_transcript_with_other_internal_raw,
        )
        .expect("invalid Schnorr inputs");

        let result = verifier.verify_sig_share(
            signer_id,
            &inputs_with_other_key_internal_transcript_raw,
            &sig_share,
        );

        assert_matches!(
            result,
            Err(ThresholdSchnorrVerifySigShareError::InvalidSignatureShare)
        );
    }
}

fn signature_share_from_random_receiver<R: RngCore + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    inputs: &ThresholdSchnorrSigInputs,
    rng: &mut R,
) -> (NodeId, ThresholdSchnorrSigShare) {
    let signer = env
        .nodes
        .random_filtered_by_receivers(inputs.receivers(), rng);
    signer.load_tschnorr_sig_transcripts(inputs);
    let sig_share = signer
        .create_sig_share(inputs)
        .expect("failed to create sig share");
    (signer.id(), sig_share)
}
