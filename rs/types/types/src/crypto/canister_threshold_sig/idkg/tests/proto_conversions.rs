use crate::crypto::ExtendedDerivationPath;
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscriptId, IDkgTranscriptOperation,
    InitialIDkgDealings, SignedIDkgDealing,
};
use crate::{Height, NodeId, PrincipalId};

use crate::Id;
use crate::crypto::canister_threshold_sig::idkg::IDkgDealingSupport;
use crate::crypto::canister_threshold_sig::idkg::tests::test_utils::{
    create_idkg_params, mock_transcript, mock_unmasked_transcript_type,
};
use crate::crypto::{BasicSig, BasicSigOf, CryptoHash};
use crate::signature::BasicSignature;
use assert_matches::assert_matches;
use ic_base_types::SubnetId;
use ic_crypto_test_utils_canister_threshold_sigs::set_of_nodes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::registry::subnet::v1::ExtendedDerivationPath as ExtendedDerivationPathProto;
use ic_protobuf::registry::subnet::v1::IDkgComplaint as IDkgComplaintProto;
use ic_protobuf::registry::subnet::v1::IDkgOpening as IDkgOpeningProto;
use ic_protobuf::registry::subnet::v1::InitialIDkgDealings as InitialIDkgDealingsProto;
use ic_protobuf::types::v1::IDkgDealingSupport as IDkgDealingSupportProto;
use ic_protobuf::types::v1::PrincipalId as PrincipalIdProto;
use rand::distributions::Standard;
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;
use std::convert::TryFrom;

#[test]
fn should_correctly_serialize_and_deserialize_idkg_opening() {
    let opening = idkg_opening();
    let proto = IDkgOpeningProto::from(&opening);
    let parsing_result = IDkgOpening::try_from(&proto);
    assert!(parsing_result.is_ok(), "{:?}", parsing_result.err());
    let parsed = parsing_result.unwrap();
    assert_eq!(opening, parsed);
}

#[test]
fn should_correctly_serialize_and_deserialize_idkg_complaint() {
    let complaint = idkg_complaint();
    let proto = IDkgComplaintProto::from(&complaint);
    let parsing_result = IDkgComplaint::try_from(&proto);
    assert!(parsing_result.is_ok(), "{:?}", parsing_result.err());
    let parsed = parsing_result.unwrap();
    assert_eq!(complaint, parsed);
}

#[test]
fn should_correctly_serialize_and_deserialize_initial_dealings() {
    let rng = &mut reproducible_rng();
    let initial_dealings = initial_dealings(rng);
    let proto = InitialIDkgDealingsProto::from(&initial_dealings);
    let parsing_result = InitialIDkgDealings::try_from(&proto);
    assert!(parsing_result.is_ok(), "{:?}", parsing_result.err());
    let parsed = parsing_result.unwrap();
    assert_eq!(initial_dealings, parsed);
}

#[test]
fn should_correctly_serialize_and_deserialize_extended_derivation_path() {
    let rng = &mut reproducible_rng();
    let derivation_path = dummy_extended_derivation_path(rng);
    let proto = ExtendedDerivationPathProto::from(derivation_path.clone());
    let parsing_result = ExtendedDerivationPath::try_from(proto);
    assert!(parsing_result.is_ok(), "{:?}", parsing_result.err());
    let parsed = parsing_result.unwrap();
    assert_eq!(derivation_path, parsed);
}

#[test]
fn should_correctly_serialize_and_deserialize_dealing_support() {
    let rng = &mut reproducible_rng();
    for _ in 0..100 {
        let dealing_support = dummy_dealing_support(rng);
        let proto = IDkgDealingSupportProto::from(&dealing_support);
        assert_matches!(
            IDkgDealingSupport::try_from(&proto),
            Ok(decoded_dealing_support)
            if decoded_dealing_support == dealing_support
        );
    }
}

#[test]
fn should_fail_parsing_extended_derivation_path_proto_without_caller() {
    let rng = &mut reproducible_rng();
    let derivation_path = dummy_extended_derivation_path(rng);
    let mut proto = ExtendedDerivationPathProto::from(derivation_path);
    proto.caller = None;
    let parsing_result = ExtendedDerivationPath::try_from(proto);
    assert_matches!(parsing_result,
        Err(ProxyDecodeError::MissingField(field)) if field == "ExtendedDerivationPath::caller");
}

#[test]
fn should_fail_parsing_extended_derivation_path_proto_with_malformed_caller() {
    let rng = &mut reproducible_rng();
    let derivation_path = dummy_extended_derivation_path(rng);
    let mut proto = ExtendedDerivationPathProto::from(derivation_path);
    proto.caller = Some(PrincipalIdProto { raw: vec![42; 42] });
    let parsing_result = ExtendedDerivationPath::try_from(proto);
    assert_matches!(parsing_result, Err(ProxyDecodeError::InvalidPrincipalId(_)));
}

fn initial_dealings_without_empty_or_default_data<R: Rng + CryptoRng>(
    rng: &mut R,
) -> InitialIDkgDealings {
    let previous_receivers = set_of_nodes(&[35, 36, 37, 38]);
    let previous_transcript = mock_transcript(
        Some(previous_receivers),
        mock_unmasked_transcript_type(rng),
        rng,
    );
    let dealers = set_of_nodes(&[35, 36, 38]);
    let receivers = set_of_nodes(&[39, 40, 41]);

    // For a Resharing Unmasked transcript, the dealer set should be a subset of the previous receiver set.
    assert!(dealers.is_subset(previous_transcript.receivers.get()));

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
        rng,
    );
    let dealings = mock_signed_dealings(params.transcript_id(), &dealers, rng);

    InitialIDkgDealings::new(params, dealings)
        .expect("Failed creating IDkgInitialDealings for testing")
}

fn dummy_extended_derivation_path<R: Rng + CryptoRng>(rng: &mut R) -> ExtendedDerivationPath {
    let path_len = rng.next_u32() % 10;
    let user_id = rng.next_u64();
    let mut derivation_path = vec![];
    for _ in 0..(path_len) {
        let entry_len = rng.next_u32() % 256;
        derivation_path.push(rng.sample_iter(Standard).take(entry_len as usize).collect())
    }
    ExtendedDerivationPath {
        caller: PrincipalId::new_user_test_id(user_id),
        derivation_path,
    }
}

fn initial_dealings<R: Rng + CryptoRng>(rng: &mut R) -> InitialIDkgDealings {
    initial_dealings_without_empty_or_default_data(rng)
}

fn idkg_opening() -> IDkgOpening {
    IDkgOpening {
        transcript_id: IDkgTranscriptId::new(
            SubnetId::new(PrincipalId::new_subnet_test_id(0xabcd)),
            1234,
            Height::new(42),
        ),
        dealer_id: NodeId::new(PrincipalId::new_user_test_id(0xabcd)),
        internal_opening_raw: "Dummy idkg opening".to_string().into_bytes(),
    }
}

fn idkg_complaint() -> IDkgComplaint {
    let opening = idkg_opening();
    IDkgComplaint {
        transcript_id: opening.transcript_id,
        dealer_id: opening.dealer_id,
        internal_complaint_raw: opening.internal_opening_raw,
    }
}

fn mock_signed_dealings<R: Rng + CryptoRng>(
    transcript_id: IDkgTranscriptId,
    dealers: &BTreeSet<NodeId>,
    rng: &mut R,
) -> Vec<SignedIDkgDealing> {
    dealers
        .iter()
        .map(|node_id| mock_signed_dealing(transcript_id, node_id, rng))
        .collect()
}

fn mock_signed_dealing<R: Rng + CryptoRng>(
    transcript_id: IDkgTranscriptId,
    node_id: &NodeId,
    rng: &mut R,
) -> SignedIDkgDealing {
    SignedIDkgDealing {
        content: IDkgDealing {
            transcript_id,
            internal_dealing_raw: random_bytes(0..100, rng),
        },
        signature: mock_sig(*node_id, rng),
    }
}

fn mock_sig<T, R: Rng + CryptoRng>(node_id: NodeId, rng: &mut R) -> BasicSignature<T> {
    BasicSignature {
        signature: BasicSigOf::new(BasicSig(random_bytes(0..100, rng))),
        signer: node_id,
    }
}

fn dummy_dealing_support<R: Rng + CryptoRng>(rng: &mut R) -> IDkgDealingSupport {
    let transcript_id = IDkgTranscriptId::new(
        SubnetId::new(PrincipalId::new_subnet_test_id(rng.r#gen())),
        rng.r#gen(),
        Height::from(rng.r#gen::<u64>()),
    );
    let dealer_id = NodeId::new(PrincipalId::new_user_test_id(rng.r#gen()));
    let sig_share = mock_sig(dealer_id, rng);
    IDkgDealingSupport {
        transcript_id,
        dealer_id,
        dealing_hash: Id::from(CryptoHash(random_bytes(0..100, rng))),
        sig_share,
    }
}

fn random_bytes<R: Rng + CryptoRng>(range: std::ops::Range<usize>, rng: &mut R) -> Vec<u8> {
    let len = rng.random_range(range);
    rng.sample_iter(Standard).take(len).collect()
}
