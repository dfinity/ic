use ic_crypto_internal_types::sign::canister_threshold_sig::{
    CspIDkgComplaint, CspIDkgDealing, CspIDkgOpening,
};
use ic_interfaces::crypto::IDkgTranscriptGenerator;
use ic_test_utilities::crypto::{crypto_for, temp_crypto_components_for};
use ic_test_utilities::types::ids::NODE_1;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealers, IDkgDealing, IDkgOpening, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptParams, IDkgTranscriptType,
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
        IDkgTranscriptType::RandomSkinny,
        AlgorithmId::Placeholder,
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
