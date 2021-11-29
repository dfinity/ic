use ic_base_types::PrincipalId;
use ic_crypto_test_utils_canister_threshold_sigs::{
    build_params_from_previous, run_idkg_and_create_transcript, CanisterThresholdSigTestEnvironment,
};
use ic_interfaces::crypto::{IDkgProtocol, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner};
use ic_test_utilities::crypto::{crypto_for, temp_crypto_components_for};
use ic_test_utilities::types::ids::NODE_1;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealers, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgOpening,
    IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
    IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
};
use ic_types::crypto::canister_threshold_sig::{
    PreSignatureQuadruple, ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs,
    ThresholdEcdsaSigShare,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, Randomness, RegistryVersion};
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

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

    let key_transcript = {
        let masked_key_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let masked_key_transcript =
            run_idkg_and_create_transcript(&masked_key_params, &env.crypto_components);

        let unmasked_key_params = build_params_from_previous(
            masked_key_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
        );

        run_idkg_and_create_transcript(&unmasked_key_params, &env.crypto_components)
    };

    let lambda_params = env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);
    let lambda_transcript = run_idkg_and_create_transcript(&lambda_params, &env.crypto_components);

    let kappa_transcript = {
        let masked_kappa_params =
            env.params_for_random_sharing(AlgorithmId::ThresholdEcdsaSecp256k1);

        let masked_kappa_transcript =
            run_idkg_and_create_transcript(&masked_kappa_params, &env.crypto_components);

        let unmasked_kappa_params = build_params_from_previous(
            masked_kappa_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_kappa_transcript),
        );

        run_idkg_and_create_transcript(&unmasked_kappa_params, &env.crypto_components)
    };

    let kappa_times_lambda_transcript = {
        let kappa_times_lambda_params = build_params_from_previous(
            lambda_params.clone(),
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                kappa_transcript.clone(),
                lambda_transcript.clone(),
            ),
        );

        run_idkg_and_create_transcript(&kappa_times_lambda_params, &env.crypto_components)
    };

    let key_times_lambda_transcript = {
        let key_times_lambda_params = build_params_from_previous(
            lambda_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(key_transcript, lambda_transcript.clone()),
        );

        run_idkg_and_create_transcript(&key_times_lambda_params, &env.crypto_components)
    };

    PreSignatureQuadruple::new(
        kappa_transcript,
        lambda_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
    )
    .expect("Failed to build PreSignatureQuadruple");
}

#[test]
fn should_run_verify_dealing_public() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params_for(NODE_1);
    let dealing = IDkgDealing {
        transcript_id: IDkgTranscriptId(1),
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
        transcript_id: IDkgTranscriptId(1),
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
fn should_run_sign_share() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let inputs = fake_sig_inputs();
    let result = crypto_for(NODE_1, &crypto_components).sign_share(&inputs);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_sig_share() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let inputs = fake_sig_inputs();
    let msg = ThresholdEcdsaSigShare {
        sig_share_raw: vec![],
    };
    let result = crypto_for(NODE_1, &crypto_components).verify_sig_share(NODE_1, &inputs, &msg);
    assert!(result.is_ok());
}

#[test]
fn should_run_combine_sig_shares() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let inputs = fake_sig_inputs();
    let result = crypto_for(NODE_1, &crypto_components).combine_sig_shares(&inputs, &[]);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_combined_sig() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let inputs = fake_sig_inputs();
    let fake_signature = ThresholdEcdsaCombinedSignature { signature: vec![] };
    let result =
        crypto_for(NODE_1, &crypto_components).verify_combined_sig(&inputs, &fake_signature);
    assert!(result.is_ok());
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
        IDkgTranscriptId(1),
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
        transcript_id: IDkgTranscriptId(1),
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
        transcript_id: IDkgTranscriptId(1),
        dealer_id: NODE_1,
        internal_complaint_raw: vec![],
    }
}

fn fake_opening() -> IDkgOpening {
    IDkgOpening {
        transcript_id: IDkgTranscriptId(1),
        dealer_id: NODE_1,
        internal_opening_raw: vec![],
    }
}

fn fake_key_and_presig_quadruple() -> (IDkgTranscript, PreSignatureQuadruple) {
    let mut nodes = BTreeSet::new();
    nodes.insert(NODE_1);

    let original_kappa_id = IDkgTranscriptId(1);
    let kappa_id = IDkgTranscriptId(2);
    let lambda_id = IDkgTranscriptId(3);
    let key_id = IDkgTranscriptId(4);

    let fake_kappa = IDkgTranscript {
        transcript_id: kappa_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            original_kappa_id,
        )),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };

    let fake_lambda = IDkgTranscript {
        transcript_id: lambda_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };

    let fake_kappa_times_lambda = IDkgTranscript {
        transcript_id: IDkgTranscriptId(40),
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(
            IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(kappa_id, lambda_id),
        ),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };

    let fake_key = IDkgTranscript {
        transcript_id: key_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            IDkgTranscriptId(50),
        )),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };

    let fake_key_times_lambda = IDkgTranscript {
        transcript_id: IDkgTranscriptId(50),
        receivers: IDkgReceivers::new(nodes).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(
            IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(key_id, lambda_id),
        ),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
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

fn fake_sig_inputs() -> ThresholdEcdsaSigInputs {
    let (fake_key, fake_presig_quadruple) = fake_key_and_presig_quadruple();

    ThresholdEcdsaSigInputs::new(
        PrincipalId::new_user_test_id(1),
        &[],
        &[],
        Randomness::from([0_u8; 32]),
        fake_presig_quadruple,
        fake_key,
    )
    .expect("failed to create signature inputs")
}
