use super::*;
use crate::crypto::canister_threshold_sig::error::{
    PresignatureQuadrupleCreationError, ThresholdEcdsaSigInputsCreationError,
};
use crate::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
use ic_base_types::{NodeId, RegistryVersion, SubnetId};
use ic_crypto_test_utils_canister_threshold_sigs::set_of_nodes;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn should_create_quadruples_successfully() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers);

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(quadruple.is_ok());
}

#[test]
fn should_not_create_quadruples_with_inconsistent_algorithms() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_algorithm_id = AlgorithmId::Tls;

    let (mut kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    kappa_unmasked.algorithm_id = wrong_algorithm_id;
    assert_ne!(kappa_unmasked.algorithm_id, lambda_masked.algorithm_id);

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(matches!(
        quadruple,
        Err(PresignatureQuadrupleCreationError::InconsistentAlgorithmIds)
    ));
}

#[test]
fn should_not_create_quadruples_with_inconsistent_receivers() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_receivers = set_of_nodes(&[1, 2, 3, 4]);

    let (mut kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    kappa_unmasked.receivers = IDkgReceivers::new(wrong_receivers).unwrap();
    assert_ne!(kappa_unmasked.receivers, lambda_masked.receivers);

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(matches!(
        quadruple,
        Err(PresignatureQuadrupleCreationError::InconsistentReceivers)
    ));
}

#[test]
fn should_not_create_quadruples_for_kappa_with_wrong_type() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_kappa_unmasked_type = IDkgTranscriptType::Unmasked(
        IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(random_transcript_id()),
    );

    let (mut kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    assert_ne!(kappa_unmasked.transcript_type, wrong_kappa_unmasked_type);
    kappa_unmasked.transcript_type = wrong_kappa_unmasked_type;

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked.clone(),
        lambda_masked,
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(
        matches!(quadruple, Err(PresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error==format!("`kappa_unmasked` transcript expected to have type `Unmasked` with `ReshareMasked` origin, but found transcript of type {:?}",kappa_unmasked.transcript_type))
    );
}

#[test]
fn should_not_create_quadruples_for_lambda_with_wrong_type() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_lambda_masked_type = IDkgTranscriptType::Unmasked(
        IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(random_transcript_id()),
    );

    let (kappa_unmasked, mut lambda_masked, kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    assert_ne!(lambda_masked.transcript_type, wrong_lambda_masked_type);
    lambda_masked.transcript_type = wrong_lambda_masked_type;

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(
        matches!(quadruple, Err(PresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error==format!("`lambda_masked` transcript expected to have type `Masked` with `Random` origin, but found transcript of type {:?}",lambda_masked.transcript_type))
    );
}

#[test]
fn should_not_create_quadruples_for_kappa_times_lambda_with_wrong_origin() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(),
            random_transcript_id(),
        ));

    let (kappa_unmasked, lambda_masked, mut kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    assert_ne!(
        kappa_times_lambda.transcript_type,
        wrong_kappa_times_lambda_type
    );
    kappa_times_lambda.transcript_type = wrong_kappa_times_lambda_type.clone();

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked.clone(),
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(
        matches!(quadruple, Err(PresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
          if error==format!("`kappa_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},{:?})`, but found transcript of type {:?}", kappa_unmasked.transcript_id, lambda_masked.transcript_id, wrong_kappa_times_lambda_type))
    );
}

#[test]
fn should_not_create_quadruples_for_kappa_times_lambda_of_wrong_type() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);

    let (kappa_unmasked, lambda_masked, mut kappa_times_lambda, key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    assert_ne!(
        kappa_times_lambda.transcript_type,
        wrong_kappa_times_lambda_type
    );
    kappa_times_lambda.transcript_type = wrong_kappa_times_lambda_type.clone();

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked.clone(),
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(
        matches!(quadruple, Err(PresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error==format!("`kappa_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},{:?})`, but found transcript of type {:?}", kappa_unmasked.transcript_id, lambda_masked.transcript_id, wrong_kappa_times_lambda_type))
    );
}

#[test]
fn should_not_create_quadruples_for_key_times_lambda_with_wrong_origin() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(),
            random_transcript_id(),
        ));

    let (kappa_unmasked, lambda_masked, kappa_times_lambda, mut key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    assert_ne!(
        key_times_lambda.transcript_type,
        wrong_key_times_lambda_type
    );
    key_times_lambda.transcript_type = wrong_key_times_lambda_type.clone();

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(
        matches!(quadruple, Err(PresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error==format!("`key_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked(_,{:?})`, but found transcript of type {:?}", lambda_masked.transcript_id, wrong_key_times_lambda_type))
    );
}

#[test]
fn should_not_create_quadruples_for_key_times_lambda_with_wrong_type() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);

    let (kappa_unmasked, lambda_masked, kappa_times_lambda, mut key_times_lambda) =
        transcripts_for_quadruple(common_receivers);
    assert_ne!(
        key_times_lambda.transcript_type,
        wrong_key_times_lambda_type
    );
    key_times_lambda.transcript_type = wrong_key_times_lambda_type.clone();

    let quadruple = PreSignatureQuadruple::new(
        kappa_unmasked,
        lambda_masked.clone(),
        kappa_times_lambda,
        key_times_lambda,
    );
    assert!(
        matches!(quadruple, Err(PresignatureQuadrupleCreationError::InvalidTranscriptOrigin(error))
        if error==format!("`key_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked(_,{:?})`, but found transcript of type {:?}", lambda_masked.transcript_id, wrong_key_times_lambda_type))
    );
}

#[test]
fn should_create_ecdsa_inputs_successfully() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers);

    let quadruple = PreSignatureQuadruple::new(
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

    assert!(ecdsa_inputs.is_ok());
}

#[test]
fn should_not_create_ecdsa_inputs_with_inconsistent_algorithm() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, mut key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers);

    let wrong_algorithm = AlgorithmId::Tls;
    assert_ne!(key_transcript.algorithm_id, wrong_algorithm);

    key_transcript.algorithm_id = wrong_algorithm;

    let quadruple = PreSignatureQuadruple::new(
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

    assert!(matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::InconsistentAlgorithmIds)
    ));
}

#[test]
fn should_not_create_ecdsa_inputs_with_unsupported_algorithm() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (
        mut kappa_unmasked,
        mut lambda_masked,
        mut kappa_times_lambda,
        mut key_times_lambda,
        mut key_transcript,
    ) = transcripts_for_ecdsa_inputs(common_receivers);

    let wrong_algorithm = AlgorithmId::Tls;
    assert_ne!(key_transcript.algorithm_id, wrong_algorithm);

    kappa_unmasked.algorithm_id = wrong_algorithm;
    lambda_masked.algorithm_id = wrong_algorithm;
    kappa_times_lambda.algorithm_id = wrong_algorithm;
    key_times_lambda.algorithm_id = wrong_algorithm;
    key_transcript.algorithm_id = wrong_algorithm;

    let quadruple = PreSignatureQuadruple::new(
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

    assert!(matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::UnsupportedAlgorithm)
    ));
}

#[test]
fn should_not_create_ecdsa_inputs_with_invalid_hash_length() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers);

    let quadruple = PreSignatureQuadruple::new(
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

    assert!(matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::InvalidHashLength)
    ));
}

#[test]
fn should_not_create_ecdsa_inputs_with_distinct_receivers() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let wrong_receivers = IDkgReceivers::new(set_of_nodes(&[1, 2, 3, 4])).unwrap();
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, mut key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers);

    assert_ne!(key_transcript.receivers, wrong_receivers);

    key_transcript.receivers = wrong_receivers;

    let quadruple = PreSignatureQuadruple::new(
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

    assert!(matches!(
        ecdsa_inputs,
        Err(ThresholdEcdsaSigInputsCreationError::InconsistentReceivers)
    ));
}

#[test]
fn should_not_create_ecdsa_inputs_for_quadruple_with_wrong_origin() {
    let common_receivers = set_of_nodes(&[1, 2, 3]);
    let (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, mut key_transcript) =
        transcripts_for_ecdsa_inputs(common_receivers);

    let wrong_key_transcript_id = random_transcript_id();
    assert_ne!(key_transcript.transcript_id, wrong_key_transcript_id);

    key_transcript.transcript_id = wrong_key_transcript_id;

    let quadruple = PreSignatureQuadruple::new(
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
    assert!(
        matches!(ecdsa_inputs, Err(ThresholdEcdsaSigInputsCreationError::InvalidQuadrupleOrigin(error))
        if error==format!("Quadruple transcript `key_times_lambda` expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},_)`, but found transcript of type {:?}", key_transcript.transcript_id, quadruple.unwrap().key_times_lambda().transcript_type))
    );
}

// A randomized way to get non-repeating IDs.
pub fn random_transcript_id() -> IDkgTranscriptId {
    const SUBNET_ID: u64 = 314159;

    let rng = &mut rand::thread_rng();
    let id = rng.gen();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(SUBNET_ID));

    IDkgTranscriptId::new(subnet, id)
}

pub fn transcript(
    receivers: BTreeSet<NodeId>,
    transcript_type: IDkgTranscriptType,
) -> IDkgTranscript {
    IDkgTranscript {
        transcript_id: random_transcript_id(),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}

pub fn transcripts_for_quadruple(
    receivers: BTreeSet<NodeId>,
) -> (
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
) {
    let kappa_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(),
    ));
    let kappa_unmasked_transcript = transcript(receivers.clone(), kappa_type);

    let lambda_type = IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);
    let lambda_masked_transcript = transcript(receivers.clone(), lambda_type);

    let kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            kappa_unmasked_transcript.transcript_id,
            lambda_masked_transcript.transcript_id,
        ));
    let kappa_times_lambda_transcript = transcript(receivers.clone(), kappa_times_lambda_type);

    let key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            random_transcript_id(),
            lambda_masked_transcript.transcript_id,
        ));
    let key_times_lambda_transcript = transcript(receivers, key_times_lambda_type);

    (
        kappa_unmasked_transcript,
        lambda_masked_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
    )
}

pub fn transcripts_for_ecdsa_inputs(
    receivers: BTreeSet<NodeId>,
) -> (
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
    IDkgTranscript,
) {
    let key_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(),
    ));
    let key_transcript = transcript(receivers.clone(), key_type);

    let kappa_type = IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(),
    ));
    let kappa_unmasked_transcript = transcript(receivers.clone(), kappa_type);

    let lambda_type = IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);
    let lambda_masked_transcript = transcript(receivers.clone(), lambda_type);

    let kappa_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            kappa_unmasked_transcript.transcript_id,
            lambda_masked_transcript.transcript_id,
        ));
    let kappa_times_lambda_transcript = transcript(receivers.clone(), kappa_times_lambda_type);

    let key_times_lambda_type =
        IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
            key_transcript.transcript_id,
            lambda_masked_transcript.transcript_id,
        ));
    let key_times_lambda_transcript = transcript(receivers, key_times_lambda_type);

    (
        kappa_unmasked_transcript,
        lambda_masked_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
        key_transcript,
    )
}

fn derivation_path() -> ExtendedDerivationPath {
    ExtendedDerivationPath {
        caller: Default::default(),
        derivation_path: vec![],
    }
}

fn nonce() -> Randomness {
    Randomness::new([42u8; 32])
}

fn hashed_message() -> Vec<u8> {
    vec![0u8; 32]
}
