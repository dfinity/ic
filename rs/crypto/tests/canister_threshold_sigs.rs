use ic_base_types::PrincipalId;
use ic_crypto_internal_types::sign::canister_threshold_sig::{
    CspIDkgComplaint, CspIDkgDealing, CspIDkgOpening, CspThresholdSignatureMsg,
};
use ic_interfaces::crypto::{IDkgTranscriptGenerator, ThresholdEcdsaSignature};
use ic_test_utilities::crypto::{crypto_for, temp_crypto_components_for};
use ic_test_utilities::types::ids::NODE_1;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealers, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgOpening,
    IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
    IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
};
use ic_types::crypto::canister_threshold_sig::{
    PreSignatureQuadruple, ThresholdSignatureInputs, ThresholdSignatureMsg,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NumberOfNodes, RegistryVersion};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn should_run_create_dealing() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params();
    let result = crypto_for(NODE_1, &crypto_components).create_dealing(&params);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_dealing_public() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params();
    let dealing = IDkgDealing {
        internal_dealing: CspIDkgDealing {},
    };
    let result = crypto_for(NODE_1, &crypto_components).verify_dealing_public(&params, &dealing);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_dealing_private() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params();
    let dealing = IDkgDealing {
        internal_dealing: CspIDkgDealing {},
    };
    let result = crypto_for(NODE_1, &crypto_components).verify_dealing_private(&params, &dealing);
    assert!(result.is_ok());
}

#[test]
fn should_run_create_transcript() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let params = fake_params();
    let result =
        crypto_for(NODE_1, &crypto_components).create_transcript(&params, &BTreeMap::new());
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_transcript() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let transcript = fake_transcript();
    let result = crypto_for(NODE_1, &crypto_components).verify_transcript(&transcript);
    assert!(result.is_ok());
}

#[test]
fn should_run_load_transcript() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let transcript = fake_transcript();
    let result = crypto_for(NODE_1, &crypto_components).load_transcript(&transcript);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_complaint() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let complaint = fake_complaint();
    let result = crypto_for(NODE_1, &crypto_components).verify_complaint(
        IDkgTranscriptId(1),
        NODE_1,
        &complaint,
    );
    assert!(result.is_ok());
}

#[test]
fn should_run_open_transcript() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let complaint = fake_complaint();
    let result =
        crypto_for(NODE_1, &crypto_components).open_transcript(IDkgTranscriptId(1), &complaint);
    assert!(result.is_ok());
}

#[test]
fn should_run_verify_opening() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let opening = fake_opening();
    let complaint = fake_complaint();
    let result = crypto_for(NODE_1, &crypto_components).verify_opening(
        IDkgTranscriptId(1),
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
fn should_run_sign_threshold() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let inputs = fake_sig_inputs();
    let result = crypto_for(NODE_1, &crypto_components).sign_threshold(&inputs);
    assert!(result.is_ok());
}

#[test]
fn should_run_validate_threshold_sig_share() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let inputs = fake_sig_inputs();
    let msg = ThresholdSignatureMsg {
        internal_msg: CspThresholdSignatureMsg {},
    };
    let result =
        crypto_for(NODE_1, &crypto_components).validate_threshold_sig_share(NODE_1, &inputs, &msg);
    assert!(result.is_ok());
}

#[test]
fn should_run_combine_threshold_sig_shares() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let inputs = fake_sig_inputs();
    let result = crypto_for(NODE_1, &crypto_components).combine_threshold_sig_shares(&inputs, &[]);
    assert!(result.is_ok());
}

#[test]
fn should_run_get_ecdsa_public_key() {
    let crypto_components = temp_crypto_components_for(&[NODE_1]);
    let key_transcript = fake_transcript();
    let result = crypto_for(NODE_1, &crypto_components)
        .get_ecdsa_public_key(PrincipalId::new_user_test_id(1), key_transcript);
    assert!(result.is_ok());
}

fn fake_params() -> IDkgTranscriptParams {
    let mut nodes = BTreeSet::new();
    nodes.insert(NODE_1);

    IDkgTranscriptParams::new(
        IDkgTranscriptId(1),
        NumberOfNodes::from(1),
        IDkgDealers::new(nodes.clone()).unwrap(),
        NumberOfNodes::from(1),
        IDkgReceivers::new(nodes).unwrap(),
        NumberOfNodes::from(1),
        RegistryVersion::from(0),
        AlgorithmId::Placeholder,
        IDkgTranscriptOperation::Random,
    )
}

fn fake_transcript() -> IDkgTranscript {
    let mut nodes = BTreeSet::new();
    nodes.insert(NODE_1);

    IDkgTranscript {
        transcript_id: IDkgTranscriptId(1),
        receivers: IDkgReceivers::new(nodes).unwrap(),
        registry_version: RegistryVersion::from(0),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
    }
}

fn fake_complaint() -> IDkgComplaint {
    IDkgComplaint {
        transcript_id: IDkgTranscriptId(1),
        dealer_id: NODE_1,
        internal_complaint: CspIDkgComplaint {},
    }
}

fn fake_opening() -> IDkgOpening {
    IDkgOpening {
        transcript_id: IDkgTranscriptId(1),
        dealer_id: NODE_1,
        internal_opening: CspIDkgOpening {},
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
        registry_version: RegistryVersion::from(0),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            original_kappa_id,
        )),
    };

    let fake_lambda = IDkgTranscript {
        transcript_id: lambda_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(0),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
    };

    let fake_kappa_times_lambda = IDkgTranscript {
        transcript_id: IDkgTranscriptId(40),
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(0),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::MaskedTimesMasked(
            original_kappa_id,
            lambda_id,
        )),
    };

    let fake_key = IDkgTranscript {
        transcript_id: key_id,
        receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
        registry_version: RegistryVersion::from(0),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            IDkgTranscriptId(50),
        )),
    };

    let fake_key_times_lambda = IDkgTranscript {
        transcript_id: IDkgTranscriptId(50),
        receivers: IDkgReceivers::new(nodes).unwrap(),
        registry_version: RegistryVersion::from(0),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(
            IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(key_id, lambda_id),
        ),
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

fn fake_sig_inputs() -> ThresholdSignatureInputs {
    let (fake_key, fake_presig_quadruple) = fake_key_and_presig_quadruple();

    ThresholdSignatureInputs::new(
        PrincipalId::new_user_test_id(1),
        1,
        vec![],
        fake_presig_quadruple,
        fake_key,
    )
    .expect("failed to create signature inputs")
}
