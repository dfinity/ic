use super::*;
use crate::crypto::canister_threshold_sig::error::{
    EcdsaPresignatureQuadrupleCreationError, ThresholdEcdsaSigInputsCreationError,
};
use crate::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
use crate::{Height, NodeId, RegistryVersion, SubnetId};
use assert_matches::assert_matches;
use ic_crypto_test_utils_canister_threshold_sigs::{ordered_node_id, set_of_nodes};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn should_create_quadruples_correctly() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (mut kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);

    let kappa_unmasked_supported_types = vec![
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            random_transcript_id(rng),
        )),
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random),
    ];

    for kappa_unmasked_type in kappa_unmasked_supported_types {
        kappa_unmasked.transcript_type = kappa_unmasked_type;

        let result = EcdsaPreSignatureQuadruple::new(
            kappa_unmasked.clone(),
            lambda_masked.clone(),
            kappa_times_lambda.clone(),
            key_times_lambda.clone(),
        );
        assert!(result.is_ok());

        let quadruple = result.unwrap();
        assert_eq!(quadruple.kappa_unmasked(), &kappa_unmasked);
        assert_eq!(quadruple.lambda_masked(), &lambda_masked);
        assert_eq!(quadruple.kappa_times_lambda(), &kappa_times_lambda);
        assert_eq!(quadruple.key_times_lambda(), &key_times_lambda);
    }
}

#[test]
fn should_not_create_quadruples_with_inconsistent_algorithms() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_algorithm_id = AlgorithmId::Tls;

    let (mut kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);
    kappa_unmasked.algorithm_id = wrong_algorithm_id;
    assert_ne!(kappa_unmasked.algorithm_id, lambda_masked.algorithm_id);

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert_matches!(
        quadruple,
        Err(EcdsaPresignatureQuadrupleCreationError::InconsistentAlgorithmIds)
    );
}

#[test]
fn should_not_create_quadruples_with_inconsistent_receivers() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_receivers = set_of_nodes(&[1, 2, 3, 4]);

    let (mut kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);
    kappa_unmasked.receivers = IDkgReceivers::new(wrong_receivers).unwrap();
    assert_ne!(kappa_unmasked.receivers, lambda_masked.receivers);

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert_matches!(
        quadruple,
        Err(EcdsaPresignatureQuadrupleCreationError::InconsistentReceivers)
    );
}

#[test]
fn should_not_create_quadruples_for_kappa_with_wrong_type() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let kappa_unmasked_unsupported_types = vec![
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(
            random_transcript_id(rng),
        )),
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(rng),
            random_transcript_id(rng),
        )),
    ];

    for wrong_kappa_unmasked_type in kappa_unmasked_unsupported_types {
        let (mut kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
            transcripts_for_quadruple(common_receivers.clone(), rng);
        assert_ne!(kappa_unmasked.transcript_type, wrong_kappa_unmasked_type);
        kappa_unmasked.transcript_type = wrong_kappa_unmasked_type;

        let quadruple = EcdsaPreSignatureQuadruple::new(
            kappa_unmasked.clone(),
            lambda_masked,
            kappa_times_lambda,
            key_times_lambda,
        );
        assert_matches!(quadruple, Err(EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
            if error == format!("`kappa_unmasked` transcript expected to have type `Unmasked` with `ReshareMasked` or `Random` origin, but found transcript of type {:?}",kappa_unmasked.transcript_type)
        );
    }
}

#[test]
fn should_not_create_quadruples_for_lambda_with_wrong_type() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_lambda_masked_type = IDkgTranscriptType::Unmasked(
        IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(random_transcript_id(rng)),
    );

    let (kappa_unmasked, mut lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);
    assert_ne!(lambda_masked.transcript_type, wrong_lambda_masked_type);
    lambda_masked.transcript_type = wrong_lambda_masked_type;

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert_matches!(quadruple, Err(EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error == format!("`lambda_masked` transcript expected to have type `Masked` with `Random` origin, but found transcript of type {:?}",lambda_masked.transcript_type)
    );
}

#[test]
fn should_not_create_quadruples_for_kappa_times_lambda_with_wrong_origin() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(rng),
            random_transcript_id(rng),
        ));

    let (kappa_unmasked, lambda_masked, mut kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);
    assert_ne!(
        kappa_times_lambda.transcript_type,
        wrong_kappa_times_lambda_type
    );
    kappa_times_lambda.transcript_type = wrong_kappa_times_lambda_type.clone();

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked.clone(),
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert_matches!(quadruple, Err(EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
          if error == format!("`kappa_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},{:?})`, but found transcript of type {:?}", kappa_unmasked.transcript_id, lambda_masked.transcript_id, wrong_kappa_times_lambda_type)
    );
}

#[test]
fn should_not_create_quadruples_for_kappa_times_lambda_of_wrong_type() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);

    let (kappa_unmasked, lambda_masked, mut kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);
    assert_ne!(
        kappa_times_lambda.transcript_type,
        wrong_kappa_times_lambda_type
    );
    kappa_times_lambda.transcript_type = wrong_kappa_times_lambda_type.clone();

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked.clone(),
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert_matches!(quadruple, Err(EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error == format!("`kappa_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},{:?})`, but found transcript of type {:?}", kappa_unmasked.transcript_id, lambda_masked.transcript_id, wrong_kappa_times_lambda_type)
    );
}

#[test]
fn should_not_create_quadruples_for_key_times_lambda_with_wrong_origin() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(rng),
            random_transcript_id(rng),
        ));

    let (kappa_unmasked, lambda_masked, kappa_times_lambda, mut key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);
    assert_ne!(
        key_times_lambda.transcript_type,
        wrong_key_times_lambda_type
    );
    key_times_lambda.transcript_type = wrong_key_times_lambda_type.clone();

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert_matches!(quadruple, Err(EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error == format!("`key_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked(_,{:?})`, but found transcript of type {:?}", lambda_masked.transcript_id, wrong_key_times_lambda_type)
    );
}

#[test]
fn should_not_create_quadruples_for_key_times_lambda_with_wrong_type() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);

    let (kappa_unmasked, lambda_masked, kappa_times_lambda, mut key_times_lambda) =
        transcripts_for_quadruple(common_receivers, rng);
    assert_ne!(
        key_times_lambda.transcript_type,
        wrong_key_times_lambda_type
    );
    key_times_lambda.transcript_type = wrong_key_times_lambda_type.clone();

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert_matches!(quadruple, Err(EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error == format!("`key_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked(_,{:?})`, but found transcript of type {:?}", lambda_masked.transcript_id, wrong_key_times_lambda_type)
    );
}

#[test]
fn should_create_ecdsa_inputs_correctly() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers.clone(), rng);

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());

    let derivation_path = derivation_path();
    let hashed_message = hashed_message();
    let nonce = nonce();
    let quadruple = quadruple.unwrap();
    let result = ThresholdEcdsaSigInputs::new(
        &derivation_path,
        &hashed_message,
        nonce,
        quadruple.clone(),
        key_transcript.clone(),
    );
    assert!(result.is_ok());

    let ecdsa_inputs = result.unwrap();
    assert_eq!(ecdsa_inputs.derivation_path(), &derivation_path);
    assert_eq!(ecdsa_inputs.hashed_message(), &hashed_message);
    assert_eq!(ecdsa_inputs.nonce(), &nonce);
    assert_eq!(ecdsa_inputs.presig_quadruple(), &quadruple);
    assert_eq!(ecdsa_inputs.key_transcript(), &key_transcript);
    assert_eq!(
        ecdsa_inputs.reconstruction_threshold(),
        key_transcript.reconstruction_threshold()
    );
    assert_eq!(ecdsa_inputs.receivers(), &key_transcript.receivers);
    assert_eq!(ecdsa_inputs.algorithm_id(), key_transcript.algorithm_id);
    for node_id in common_receivers.iter() {
        assert!(ecdsa_inputs.index_for_signer_id(*node_id).is_some());
        assert_eq!(
            ecdsa_inputs.index_for_signer_id(*node_id),
            key_transcript.index_for_signer_id(*node_id)
        );
    }
}

#[test]
fn should_not_create_ecdsa_inputs_with_inconsistent_algorithm() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, mut key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers, rng);

    let wrong_algorithm = AlgorithmId::Tls;
    assert_ne!(key_transcript.algorithm_id, wrong_algorithm);

    key_transcript.algorithm_id = wrong_algorithm;

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());

    let ecdsa_inputs = ThresholdEcdsaSigInputs::new(
        &derivation_path(),
        &hashed_message(),
        nonce(),
        quadruple.unwrap(),
        key_transcript,
    );

    assert_matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::InconsistentAlgorithmIds)
    );
}

#[test]
fn should_not_create_ecdsa_inputs_with_unsupported_algorithm() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (
        mut kappa_unmasked,
        mut lambda_masked,
        mut kappa_times_lambda,
        mut key_times_lambda,
        mut key_transcript,
    ) = transcripts_for_ecdsa_inputs(common_receivers, rng);

    let wrong_algorithm = AlgorithmId::Tls;
    assert_ne!(key_transcript.algorithm_id, wrong_algorithm);

    kappa_unmasked.algorithm_id = wrong_algorithm;
    lambda_masked.algorithm_id = wrong_algorithm;
    kappa_times_lambda.algorithm_id = wrong_algorithm;
    key_times_lambda.algorithm_id = wrong_algorithm;
    key_transcript.algorithm_id = wrong_algorithm;

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());

    let ecdsa_inputs = ThresholdEcdsaSigInputs::new(
        &derivation_path(),
        &hashed_message(),
        nonce(),
        quadruple.unwrap(),
        key_transcript,
    );

    assert_matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::UnsupportedAlgorithm)
    );
}

#[test]
fn should_not_create_ecdsa_inputs_with_invalid_hash_length() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers, rng);

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());

    let ecdsa_inputs = ThresholdEcdsaSigInputs::new(
        &derivation_path(),
        &[1u8; 33],
        nonce(),
        quadruple.unwrap(),
        key_transcript,
    );

    assert_matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::InvalidHashLength)
    );
}

#[test]
fn should_not_create_ecdsa_inputs_with_distinct_receivers() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_receivers = IDkgReceivers::new(set_of_nodes(&[1, 2, 3, 4])).unwrap();
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, mut key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers, rng);

    assert_ne!(key_transcript.receivers, wrong_receivers);

    key_transcript.receivers = wrong_receivers;

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());

    let ecdsa_inputs = ThresholdEcdsaSigInputs::new(
        &derivation_path(),
        &hashed_message(),
        nonce(),
        quadruple.unwrap(),
        key_transcript,
    );

    assert_matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::InconsistentReceivers)
    );
}

#[test]
fn should_not_create_ecdsa_inputs_for_quadruple_with_wrong_origin() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, mut key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers, rng);

    let wrong_key_transcript_id = random_transcript_id(rng);
    assert_ne!(key_transcript.transcript_id, wrong_key_transcript_id);

    key_transcript.transcript_id = wrong_key_transcript_id;

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());

    let ecdsa_inputs = ThresholdEcdsaSigInputs::new(
        &derivation_path(),
        &hashed_message(),
        nonce(),
        quadruple.clone().unwrap(),
        key_transcript.clone(),
    );
    assert_matches!(ecdsa_inputs, Err(ThresholdEcdsaSigInputsCreationError::InvalidQuadrupleOrigin(error))
        if error == format!("Quadruple transcript `key_times_lambda` expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},_)`, but found transcript of type {:?}", key_transcript.transcript_id, quadruple.unwrap().key_times_lambda().transcript_type)
    );
}

#[test]
fn bincode_serialization_of_extended_derivation_path_has_stable_representation() {
    let bytes = bincode::serialize(&derivation_path()).expect("failed to serialize");
    let expected_bytes: Vec<u8> = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 105, 110, 110,
        101, 114, 32, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 32, 112, 97, 116, 104,
    ];
    assert_eq!(bytes, expected_bytes);
}

#[test]
fn bincode_deserialization_of_extended_derivation_path_is_backward_compatible() {
    let stable_bytes: Vec<u8> = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 105, 110, 110,
        101, 114, 32, 100, 101, 114, 105, 118, 97, 116, 105, 111, 110, 32, 112, 97, 116, 104,
    ];
    let computed_derivation_path: ExtendedDerivationPath =
        bincode::deserialize(&stable_bytes).expect("failed to deserialize");
    let expected_derivation_path = derivation_path();
    assert_eq!(computed_derivation_path, expected_derivation_path);
}

#[test]
fn serde_cbor_deserialization_of_extended_derivation_path_is_backward_compatible() {
    let stable_bytes: Vec<u8> = vec![
        162, 102, 99, 97, 108, 108, 101, 114, 64, 111, 100, 101, 114, 105, 118, 97, 116, 105, 111,
        110, 95, 112, 97, 116, 104, 129, 149, 24, 105, 24, 110, 24, 110, 24, 101, 24, 114, 24, 32,
        24, 100, 24, 101, 24, 114, 24, 105, 24, 118, 24, 97, 24, 116, 24, 105, 24, 111, 24, 110,
        24, 32, 24, 112, 24, 97, 24, 116, 24, 104,
    ];
    let computed_derivation_path: ExtendedDerivationPath =
        serde_cbor::from_slice(&stable_bytes).expect("failed to deserialize");
    let expected_derivation_path = derivation_path();
    assert_eq!(computed_derivation_path, expected_derivation_path);
}

#[test]
fn should_return_correct_index_for_signer_id_from_threshold_ecdsa_sig_inputs() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[42, 43, 45, 128]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers, rng);

    let quadruple = EcdsaPreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());

    let derivation_path = derivation_path();
    let hashed_message = hashed_message();
    let nonce = nonce();
    let quadruple = quadruple.unwrap();
    let inputs = ThresholdEcdsaSigInputs::new(
        &derivation_path,
        &hashed_message,
        nonce,
        quadruple.clone(),
        key_transcript.clone(),
    )
    .expect("failed to create ThresholdEcdsaSigInputs");

    assert_eq!(inputs.index_for_signer_id(ordered_node_id(42)), Some(0));
    assert_eq!(inputs.index_for_signer_id(ordered_node_id(43)), Some(1));
    assert_eq!(inputs.index_for_signer_id(ordered_node_id(44)), None);
    assert_eq!(inputs.index_for_signer_id(ordered_node_id(45)), Some(2));
    assert_eq!(inputs.index_for_signer_id(ordered_node_id(46)), None);
    assert_eq!(inputs.index_for_signer_id(ordered_node_id(128)), Some(3));
}

#[test]
fn should_create_schnorr_presignature_correctly() {
    let rng = &mut reproducible_rng();
    let receivers = set_of_nodes(&[1, 2, 3]);
    let transcript_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random);
    let presignature_transcript = schnorr_transcript(receivers.clone(), transcript_type, rng);
    let result = SchnorrPreSignatureTranscript::new(presignature_transcript.clone());
    assert_matches!(result, Ok(presignature) if presignature.blinder_unmasked() == &presignature_transcript);
}

#[test]
fn should_not_create_schnorr_presignature_with_invalid_algorithm_id() {
    let rng = &mut reproducible_rng();
    let receivers = set_of_nodes(&[1, 2, 3]);
    let transcript_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random);
    let mut presignature_transcript = schnorr_transcript(receivers.clone(), transcript_type, rng);
    let unsupported_algorithm = AlgorithmId::Tls;
    presignature_transcript.algorithm_id = unsupported_algorithm;
    let result = SchnorrPreSignatureTranscript::new(presignature_transcript.clone());
    assert_matches!(
        result,
        Err( error::ThresholdSchnorrPresignatureTranscriptCreationError::UnsupportedAlgorithm(internal_error))
        if internal_error == unsupported_algorithm.to_string()
    );
}

#[test]
fn should_not_create_schnorr_presignature_with_invalid_origin() {
    let rng = &mut reproducible_rng();
    let receivers = set_of_nodes(&[1, 2, 3]);
    let transcript_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random);
    let mut presignature_transcript = schnorr_transcript(receivers.clone(), transcript_type, rng);
    let random_transcript_id = random_transcript_id(rng);
    let invalid_transcript_types = [
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            random_transcript_id,
        )),
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(
            random_transcript_id,
        )),
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id,
            random_transcript_id,
        )),
    ];
    for invalid_transcript_type in invalid_transcript_types {
        presignature_transcript.transcript_type = invalid_transcript_type.clone();
        let result = SchnorrPreSignatureTranscript::new(presignature_transcript.clone());
        assert_matches!(
            result,
            Err( error::ThresholdSchnorrPresignatureTranscriptCreationError::InvalidTranscriptOrigin(internal_error))
            if internal_error == format!(
                "Expected unmasked transcript with origin `Random`, but found transcript of type {invalid_transcript_type:?}"
            )
        );
    }
}

#[test]
fn should_create_schnorr_sig_inputs_correctly() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (presignature_transcript_raw, key_transcript) =
        transcripts_for_schnorr_sig_inputs(common_receivers.clone(), rng);

    let presignature_transcript = SchnorrPreSignatureTranscript::new(presignature_transcript_raw)
        .expect("failed to created presignature transcript");

    let derivation_path = derivation_path();
    let message = message_in_size_range(0..1_000, rng);
    let nonce = nonce();
    let tschnorr_sig_inputs = ThresholdSchnorrSigInputs::new(
        &derivation_path,
        &message,
        nonce,
        presignature_transcript.clone(),
        key_transcript.clone(),
    )
    .expect("failed to create threshold Schnorr signature inputs");

    assert_eq!(tschnorr_sig_inputs.derivation_path(), &derivation_path);
    assert_eq!(tschnorr_sig_inputs.message(), &message);
    assert_eq!(tschnorr_sig_inputs.nonce(), &nonce);
    assert_eq!(
        tschnorr_sig_inputs.presig_transcript(),
        &presignature_transcript
    );
    assert_eq!(tschnorr_sig_inputs.key_transcript(), &key_transcript);
    assert_eq!(
        tschnorr_sig_inputs.reconstruction_threshold(),
        key_transcript.reconstruction_threshold()
    );
    assert_eq!(tschnorr_sig_inputs.receivers(), &key_transcript.receivers);
    assert_eq!(
        AsRef::<IDkgReceivers>::as_ref(&tschnorr_sig_inputs),
        &key_transcript.receivers
    );
    assert_eq!(
        tschnorr_sig_inputs.algorithm_id(),
        key_transcript.algorithm_id
    );
    for node_id in common_receivers.iter() {
        assert!(tschnorr_sig_inputs.index_for_signer_id(*node_id).is_some());
        assert_eq!(
            tschnorr_sig_inputs.index_for_signer_id(*node_id),
            key_transcript.index_for_signer_id(*node_id)
        );
    }
}

#[test]
fn should_fail_creating_schnorr_sig_inputs_with_inconsistent_algorithms() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (presignature_transcript_raw, key_transcript) =
        transcripts_for_schnorr_sig_inputs(common_receivers, rng);

    let mut presignature_transcript =
        SchnorrPreSignatureTranscript::new(presignature_transcript_raw)
            .expect("failed to created presignature transcript");

    let derivation_path = derivation_path();
    let message = message_in_size_range(0..1_000, rng);
    let nonce = nonce();

    {
        let mut key_transcript = key_transcript.clone();
        key_transcript.algorithm_id = AlgorithmId::Tls;
        assert_eq!(
            ThresholdSchnorrSigInputs::new(
                &derivation_path,
                &message,
                nonce,
                presignature_transcript.clone(),
                key_transcript,
            ),
            Err(
                error::ThresholdSchnorrSigInputsCreationError::InconsistentAlgorithmIds(
                    AlgorithmId::ThresholdSchnorrBip340.to_string(),
                    AlgorithmId::Tls.to_string()
                )
            )
        );
    }

    presignature_transcript.blinder_unmasked.algorithm_id = AlgorithmId::Tls;
    assert_eq!(
        ThresholdSchnorrSigInputs::new(
            &derivation_path,
            &message,
            nonce,
            presignature_transcript,
            key_transcript,
        ),
        Err(
            error::ThresholdSchnorrSigInputsCreationError::InconsistentAlgorithmIds(
                AlgorithmId::Tls.to_string(),
                AlgorithmId::ThresholdSchnorrBip340.to_string(),
            )
        )
    );
}

#[test]
fn should_fail_creating_schnorr_sig_inputs_with_unsupported_algorithm() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (presignature_transcript_raw, mut key_transcript) =
        transcripts_for_schnorr_sig_inputs(common_receivers, rng);

    let mut presignature_transcript =
        SchnorrPreSignatureTranscript::new(presignature_transcript_raw)
            .expect("failed to created presignature transcript");

    let derivation_path = derivation_path();
    let message = message_in_size_range(0..1_000, rng);
    let nonce = nonce();

    let unsupported_algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
    key_transcript.algorithm_id = unsupported_algorithm;
    presignature_transcript.blinder_unmasked.algorithm_id = unsupported_algorithm;
    assert_eq!(
        ThresholdSchnorrSigInputs::new(
            &derivation_path,
            &message,
            nonce,
            presignature_transcript,
            key_transcript,
        ),
        Err(
            error::ThresholdSchnorrSigInputsCreationError::UnsupportedAlgorithm(
                unsupported_algorithm.to_string()
            )
        )
    );
}

#[test]
fn should_fail_creating_schnorr_sig_inputs_with_inconsistent_receivers() {
    let rng = &mut reproducible_rng();
    let receivers_presig = set_of_nodes(&[1, 2, 3]);
    let receivers_key = set_of_nodes(&[4, 2, 3]);
    let presignature_transcript_type =
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random);
    let presignature_transcript_raw =
        schnorr_transcript(receivers_presig.clone(), presignature_transcript_type, rng);

    let key_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(rng),
    ));
    let key_transcript = schnorr_transcript(receivers_key.clone(), key_type, rng);

    let presignature_transcript = SchnorrPreSignatureTranscript::new(presignature_transcript_raw)
        .expect("failed to created presignature transcript");

    assert_eq!(
        ThresholdSchnorrSigInputs::new(
            &derivation_path(),
            &message_in_size_range(0..1_000, rng),
            nonce(),
            presignature_transcript,
            key_transcript,
        ),
        Err(error::ThresholdSchnorrSigInputsCreationError::InconsistentReceivers)
    );
}

#[test]
fn should_fail_creating_schnorr_sig_inputs_with_invalid_transcript_origin() {
    let rng = &mut reproducible_rng();
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (presignature_transcript_raw, key_transcript) =
        transcripts_for_schnorr_sig_inputs(common_receivers, rng);

    let mut presignature_transcript =
        SchnorrPreSignatureTranscript::new(presignature_transcript_raw)
            .expect("failed to created presignature transcript");

    let derivation_path: ExtendedDerivationPath = derivation_path();
    let message = message_in_size_range(0..1_000, rng);
    let nonce = nonce();

    let invalid_transcript_types = [
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            random_transcript_id(rng),
        )),
        IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(
            random_transcript_id(rng),
        )),
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(rng),
            random_transcript_id(rng),
        )),
    ];
    for invalid_transcript_type in invalid_transcript_types {
        presignature_transcript.blinder_unmasked.transcript_type = invalid_transcript_type.clone();
        assert_matches!(
            ThresholdSchnorrSigInputs::new(
                &derivation_path,
                &message,
                nonce,
                presignature_transcript.clone(),
                key_transcript.clone(),
            ),
            Err(error::ThresholdSchnorrSigInputsCreationError::InvalidPreSignatureOrigin(internal_error))
            if internal_error == format!("Presignature transcript: {invalid_transcript_type:?}")
        );
    }
}

// A randomized way to get non-repeating IDs.
fn random_transcript_id<R: Rng + CryptoRng>(rng: &mut R) -> IDkgTranscriptId {
    let id = rng.gen();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
    let height = Height::from(rng.gen::<u64>());

    IDkgTranscriptId::new(subnet, id, height)
}

fn transcript<R: Rng + CryptoRng>(
    receivers: BTreeSet<NodeId>,
    transcript_type: IDkgTranscriptType,
    rng: &mut R,
) -> IDkgTranscript {
    IDkgTranscript {
        transcript_id: random_transcript_id(rng),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}

fn schnorr_transcript<R: Rng + CryptoRng>(
    receivers: BTreeSet<NodeId>,
    transcript_type: IDkgTranscriptType,
    rng: &mut R,
) -> IDkgTranscript {
    IDkgTranscript {
        transcript_id: random_transcript_id(rng),
        receivers: IDkgReceivers::new(receivers).expect("failed to create IDKG receivers"),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdSchnorrBip340,
        internal_transcript_raw: vec![1, 2, 3],
    }
}

fn transcripts_for_quadruple<R: Rng + CryptoRng>(
    receivers: BTreeSet<NodeId>,
    rng: &mut R,
) -> (
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
) {
    let kappa_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(rng),
    ));
    let kappa_unmasked_transcript = transcript(receivers.clone(), kappa_type, rng);

    let lambda_type = IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);
    let lambda_masked_transcript = transcript(receivers.clone(), lambda_type, rng);

    let kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            kappa_unmasked_transcript.transcript_id,
            lambda_masked_transcript.transcript_id,
        ));
    let kappa_times_lambda_transcript = transcript(receivers.clone(), kappa_times_lambda_type, rng);

    let key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(rng),
            lambda_masked_transcript.transcript_id,
        ));
    let key_times_lambda_transcript = transcript(receivers, key_times_lambda_type, rng);

    (
        kappa_unmasked_transcript,
        lambda_masked_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
    )
}

fn transcripts_for_ecdsa_inputs<R: Rng + CryptoRng>(
    receivers: BTreeSet<NodeId>,
    rng: &mut R,
) -> (
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
) {
    let key_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(rng),
    ));
    let key_transcript = transcript(receivers.clone(), key_type, rng);

    let kappa_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(rng),
    ));
    let kappa_unmasked_transcript = transcript(receivers.clone(), kappa_type, rng);

    let lambda_type = IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);
    let lambda_masked_transcript = transcript(receivers.clone(), lambda_type, rng);

    let kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            kappa_unmasked_transcript.transcript_id,
            lambda_masked_transcript.transcript_id,
        ));
    let kappa_times_lambda_transcript = transcript(receivers.clone(), kappa_times_lambda_type, rng);

    let key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            key_transcript.transcript_id,
            lambda_masked_transcript.transcript_id,
        ));
    let key_times_lambda_transcript = transcript(receivers, key_times_lambda_type, rng);

    (
        kappa_unmasked_transcript,
        lambda_masked_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
        key_transcript,
    )
}

fn transcripts_for_schnorr_sig_inputs<R: Rng + CryptoRng>(
    receivers: BTreeSet<NodeId>,
    rng: &mut R,
) -> (IDkgTranscript, IDkgTranscript) {
    let blinder_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random);
    let blinder_unmasked_transcript = schnorr_transcript(receivers.clone(), blinder_type, rng);

    let key_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(rng),
    ));
    let key_transcript = schnorr_transcript(receivers.clone(), key_type, rng);

    (blinder_unmasked_transcript, key_transcript)
}

fn derivation_path() -> ExtendedDerivationPath {
    ExtendedDerivationPath {
        caller: Default::default(),
        derivation_path: vec![b"inner derivation path".to_vec()],
    }
}

fn nonce() -> Randomness {
    Randomness::new([42u8; 32])
}

fn hashed_message() -> Vec<u8> {
    vec![123; 32]
}

fn message_in_size_range<R: Rng + CryptoRng>(
    range: core::ops::Range<usize>,
    rng: &mut R,
) -> Vec<u8> {
    let size = rng.gen_range(range);
    vec![123; size]
}
