use crate::crypto::canister_threshold_sig::idkg::tests::test_utils::random_transcript_id;
use crate::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgDealers, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgReceivers,
    IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
    IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
};
use crate::crypto::{AlgorithmId, BasicSig, BasicSigOf};
use crate::signature::{BasicSignature, BasicSignatureBatch};
use crate::{Height, NodeId, PrincipalId, RegistryVersion, SubnetId};
use assert_matches::assert_matches;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use maplit::{btreemap, btreeset};
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Itt = IDkgTranscriptType;
type Imto = IDkgMaskedTranscriptOrigin;
type Iuto = IDkgUnmaskedTranscriptOrigin;

#[test]
fn should_succeed_on_correct_transcript() {
    let rng = &mut reproducible_rng();
    let (transcript, params) = valid_transcript_and_params(rng);

    assert!(transcript.verify_consistency_with_params(&params).is_ok());
}

#[test]
fn should_fail_on_mismatching_transcript_ids() {
    let rng = &mut reproducible_rng();
    let (mut transcript, params) = valid_transcript_and_params(rng);

    transcript.transcript_id = transcript.transcript_id.increment();
    assert_ne!(transcript.transcript_id, params.transcript_id());

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(error) if error.contains("mismatching transcript IDs"));
}

#[test]
fn should_fail_on_mismatching_receivers() {
    let rng = &mut reproducible_rng();
    let (mut transcript, params) = valid_transcript_and_params(rng);
    transcript.receivers = {
        let mut receivers = transcript.receivers.get().clone();
        receivers.insert(node_id(99999));
        IDkgReceivers::new(receivers).expect("failed to create receivers")
    };
    assert_ne!(transcript.receivers, *params.receivers());

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(error) if error.contains("mismatching receivers"));
}

#[test]
fn should_fail_on_mismatching_registry_versions() {
    let rng = &mut reproducible_rng();
    let (mut transcript, params) = valid_transcript_and_params(rng);
    transcript.registry_version = RegistryVersion::from(transcript.registry_version.get() + 1);
    assert_ne!(transcript.registry_version, params.registry_version());

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(error) if error.contains("mismatching registry versions"));
}

#[test]
fn should_fail_on_mismatching_algorithm_ids() {
    let rng = &mut reproducible_rng();
    let (mut transcript, params) = valid_transcript_and_params(rng);
    transcript.algorithm_id = AlgorithmId::RsaSha256;
    assert_ne!(transcript.algorithm_id, params.algorithm_id());

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(error) if error.contains("mismatching algorithm IDs"));
}

#[test]
fn should_fail_on_mismatching_transcript_types_for_operation_type_random() {
    let rng = &mut reproducible_rng();
    let (mut transcript, mut params) = valid_transcript_and_params(rng);
    params.operation_type = IDkgTranscriptOperation::Random;

    transcript.transcript_type = Itt::Unmasked(Iuto::ReshareMasked(dummy_transcript_id()));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Unmasked(Iuto::ReshareUnmasked(dummy_transcript_id()));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Masked(Imto::UnmaskedTimesMasked(
        dummy_transcript_id(),
        dummy_transcript_id(),
    ));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));
}

#[test]
fn should_fail_on_mismatching_transcript_types_for_operation_type_reshare_of_masked() {
    let rng = &mut reproducible_rng();
    let (mut transcript, mut params) = valid_transcript_and_params(rng);
    params.operation_type = IDkgTranscriptOperation::ReshareOfMasked(dummy_transcript());

    transcript.transcript_type = Itt::Masked(Imto::Random);
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Unmasked(Iuto::ReshareUnmasked(dummy_transcript_id()));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Masked(Imto::UnmaskedTimesMasked(
        dummy_transcript_id(),
        dummy_transcript_id(),
    ));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));
}

#[test]
fn should_fail_on_mismatching_transcript_types_for_operation_type_reshare_of_unmasked() {
    let rng = &mut reproducible_rng();
    let (mut transcript, mut params) = valid_transcript_and_params(rng);
    params.operation_type = IDkgTranscriptOperation::ReshareOfUnmasked(dummy_transcript());

    transcript.transcript_type = Itt::Masked(Imto::Random);
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Unmasked(Iuto::ReshareMasked(dummy_transcript_id()));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Masked(Imto::UnmaskedTimesMasked(
        dummy_transcript_id(),
        dummy_transcript_id(),
    ));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));
}

#[test]
fn should_fail_on_mismatching_transcript_types_for_operation_type_unmasked_times_masked() {
    let rng = &mut reproducible_rng();
    let (mut transcript, mut params) = valid_transcript_and_params(rng);
    params.operation_type =
        IDkgTranscriptOperation::UnmaskedTimesMasked(dummy_transcript(), dummy_transcript());

    transcript.transcript_type = Itt::Masked(Imto::Random);
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Unmasked(Iuto::ReshareMasked(dummy_transcript_id()));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));

    transcript.transcript_type = Itt::Unmasked(Iuto::ReshareUnmasked(dummy_transcript_id()));
    let result = transcript.verify_consistency_with_params(&params);
    assert_matches!(result, Err(e) if e.contains("does not match transcript type derived"));
}

#[test]
fn should_fail_on_insufficient_num_of_dealings() {
    let rng = &mut reproducible_rng();
    let (mut transcript, mut params) = valid_transcript_and_params(rng);
    params.dealers = dealers(btreeset! {node_id(1), node_id(2), node_id(3), node_id(4)});
    transcript.verified_dealings = Arc::new(
        btreemap! {0 => batch_signed_dealing(node_id(42), params.receivers.get().clone())},
    );

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(e) if e.contains("insufficient number of dealings (1<2)"));
}

#[test]
fn should_fail_on_dealing_from_non_dealer() {
    let rng = &mut reproducible_rng();
    let (mut transcript, mut params) = valid_transcript_and_params(rng);
    params.dealers = dealers(btreeset! {node_id(1), node_id(2), node_id(3)});
    transcript.verified_dealings = Arc::new(
        btreemap! {0 => batch_signed_dealing(node_id(999), params.receivers.get().clone())},
    );

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(e) if e.contains("transcript contains dealings from non-dealer"));
}

#[test]
fn should_fail_on_mismatching_dealer_indexes() {
    let rng = &mut reproducible_rng();
    let (mut transcript, mut params) = valid_transcript_and_params(rng);
    params.dealers = dealers(btreeset! {node_id(3), node_id(1), node_id(2)});
    transcript.verified_dealings =
        Arc::new(btreemap! {0 => batch_signed_dealing(node_id(2), params.receivers.get().clone())});

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(e)
            if e.contains("mismatching dealer indexes in transcript (0) and \
                          params (1) for dealer gfvbo-licaa-aaaaa-aaaap-2ai")
    );
}

#[test]
fn should_fail_on_ineligible_signer() {
    let rng = &mut reproducible_rng();
    let (mut transcript, params) = valid_transcript_and_params(rng);
    let non_receiver = node_id(99999);
    assert!(!params.receivers.contains(non_receiver));
    let first_dealer_index = *transcript.verified_dealings.keys().next().unwrap();
    let verified_dealings = Arc::get_mut(&mut transcript.verified_dealings)
        .expect("No other refs to verified_dealings");
    verified_dealings
        .get_mut(&first_dealer_index)
        .unwrap()
        .signature
        .signatures_map
        .insert(non_receiver, BasicSigOf::from(BasicSig(vec![])));

    let result = transcript.verify_consistency_with_params(&params);

    assert_matches!(result, Err(e)
            if e.contains(&format!("ineligible signers (non-receivers) for \
                           dealer index {first_dealer_index}: {{{non_receiver}}}"))
    );
}

fn valid_transcript_and_params<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (IDkgTranscript, IDkgTranscriptParams) {
    let transcript_id = random_transcript_id(rng);
    let dealers = dealers(btreeset! {node_id(42), node_id(43), node_id(44)});
    let receivers = receivers(btreeset! {node_id(45), node_id(46)});
    let registry_version = RegistryVersion::from(234);
    let algorithm_id = AlgorithmId::ThresholdEcdsaSecp256k1;

    let transcript = IDkgTranscript {
        verified_dealings: Arc::new(btreemap! {
            0 => batch_signed_dealing(node_id(42), receivers.get().clone()),
            1 => batch_signed_dealing(node_id(43), receivers.get().clone()),
            2 => batch_signed_dealing(node_id(44), receivers.get().clone()),
        }),
        transcript_id,
        receivers: receivers.clone(),
        registry_version,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id,
        internal_transcript_raw: dummy_internal_transcript_raw(),
    };

    let params = IDkgTranscriptParams::new(
        transcript_id,
        dealers.get().clone(),
        receivers.get().clone(),
        registry_version,
        algorithm_id,
        IDkgTranscriptOperation::Random,
    )
    .expect("failed to create params");

    (transcript, params)
}

fn batch_signed_dealing(dealer_id: NodeId, signers: BTreeSet<NodeId>) -> BatchSignedIDkgDealing {
    let dealing = IDkgDealing {
        transcript_id: dummy_transcript_id(),
        internal_dealing_raw: dummy_internal_dealing_raw(),
    };
    let signed_dealing = SignedIDkgDealing {
        content: dealing,
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(vec![1, 2, 3])),
            signer: dealer_id,
        },
    };
    let mut signatures_map = BTreeMap::new();
    for signer in signers {
        signatures_map.insert(signer, BasicSigOf::from(BasicSig(vec![])));
    }
    BatchSignedIDkgDealing {
        content: signed_dealing,
        signature: BasicSignatureBatch { signatures_map },
    }
}

fn dummy_transcript() -> IDkgTranscript {
    IDkgTranscript {
        verified_dealings: Arc::new(btreemap! {
            0 => batch_signed_dealing(node_id(42), BTreeSet::new()),
            1 => batch_signed_dealing(node_id(43), BTreeSet::new()),
            3 => batch_signed_dealing(node_id(45), BTreeSet::new())
        }),
        transcript_id: dummy_transcript_id(),
        receivers: dummy_receivers(),
        registry_version: dummy_registry_version(),
        transcript_type: dummy_transcript_type(),
        algorithm_id: dummy_algorithm_id(),
        internal_transcript_raw: dummy_internal_transcript_raw(),
    }
}

fn dummy_transcript_id() -> IDkgTranscriptId {
    IDkgTranscriptId::new(subnet_id(0), 0, Height::new(0))
}

fn dummy_receivers() -> IDkgReceivers {
    IDkgReceivers::new(btreeset! {node_id(0)}).expect("failed to create receivers")
}

fn receivers(receivers: BTreeSet<NodeId>) -> IDkgReceivers {
    IDkgReceivers::new(receivers).expect("failed to create receivers")
}

fn dealers(dealers: BTreeSet<NodeId>) -> IDkgDealers {
    IDkgDealers::new(dealers).expect("failed to create dealers")
}

fn dummy_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
}

fn dummy_registry_version() -> RegistryVersion {
    RegistryVersion::from(0)
}

fn dummy_algorithm_id() -> AlgorithmId {
    AlgorithmId::ThresholdEcdsaSecp256k1
}

fn dummy_internal_transcript_raw() -> Vec<u8> {
    vec![]
}

fn dummy_internal_dealing_raw() -> Vec<u8> {
    vec![]
}

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}
