#![allow(clippy::unwrap_used)]

use crate::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscriptId, IDkgTranscriptOperation,
    InitialIDkgDealings, SignedIDkgDealing,
};
use crate::crypto::canister_threshold_sig::ExtendedDerivationPath;
use crate::{Height, NodeId, PrincipalId};

use crate::crypto::canister_threshold_sig::idkg::tests::test_utils::{
    create_idkg_params, mock_transcript, mock_unmasked_transcript_type,
};
use crate::crypto::{BasicSig, BasicSigOf};
use crate::signature::BasicSignature;
use assert_matches::assert_matches;
use ic_base_types::SubnetId;
use ic_crypto_test_utils_canister_threshold_sigs::set_of_nodes;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::registry::subnet::v1::ExtendedDerivationPath as ExtendedDerivationPathProto;
use ic_protobuf::registry::subnet::v1::IDkgComplaint as IDkgComplaintProto;
use ic_protobuf::registry::subnet::v1::IDkgOpening as IDkgOpeningProto;
use ic_protobuf::registry::subnet::v1::InitialIDkgDealings as InitialIDkgDealingsProto;
use ic_protobuf::types::v1::PrincipalId as PrincipalIdProto;
use rand::distributions::Standard;
use rand::{Rng, RngCore};
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
    let initial_dealings = initial_dealings();
    let proto = InitialIDkgDealingsProto::from(&initial_dealings);
    let parsing_result = InitialIDkgDealings::try_from(&proto);
    assert!(parsing_result.is_ok(), "{:?}", parsing_result.err());
    let parsed = parsing_result.unwrap();
    assert_eq!(initial_dealings, parsed);
}

#[test]
fn should_correctly_serialize_and_deserialize_extended_derivation_path() {
    let derivation_path = dummy_extended_derivation_path();
    let proto = ExtendedDerivationPathProto::from(derivation_path.clone());
    let parsing_result = ExtendedDerivationPath::try_from(proto);
    assert!(parsing_result.is_ok(), "{:?}", parsing_result.err());
    let parsed = parsing_result.unwrap();
    assert_eq!(derivation_path, parsed);
}

#[test]
fn should_fail_parsing_extended_derivation_path_proto_without_caller() {
    let derivation_path = dummy_extended_derivation_path();
    let mut proto = ExtendedDerivationPathProto::from(derivation_path);
    proto.caller = None;
    let parsing_result = ExtendedDerivationPath::try_from(proto);
    assert_matches!(parsing_result,
        Err(ProxyDecodeError::MissingField(field)) if field == "ExtendedDerivationPath::caller");
}

#[test]
fn should_fail_parsing_extended_derivation_path_proto_with_malformed_caller() {
    let derivation_path = dummy_extended_derivation_path();
    let mut proto = ExtendedDerivationPathProto::from(derivation_path);
    proto.caller = Some(PrincipalIdProto { raw: vec![42; 42] });
    let parsing_result = ExtendedDerivationPath::try_from(proto);
    assert_matches!(parsing_result, Err(ProxyDecodeError::InvalidPrincipalId(_)));
}

fn initial_dealings_without_empty_or_default_data() -> InitialIDkgDealings {
    let previous_receivers = set_of_nodes(&[35, 36, 37, 38]);
    let previous_transcript =
        mock_transcript(Some(previous_receivers), mock_unmasked_transcript_type());
    let dealers = set_of_nodes(&[35, 36, 38]);
    let receivers = set_of_nodes(&[39, 40, 41]);

    // For a Resharing Unmasked transcript, the dealer set should be a subset of the previous receiver set.
    assert!(dealers.is_subset(previous_transcript.receivers.get()));

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
    );
    let dealings = mock_signed_dealings(params.transcript_id(), &dealers);

    InitialIDkgDealings::new(params, dealings)
        .expect("Failed creating IDkgInitialDealings for testing")
}

fn dummy_extended_derivation_path() -> ExtendedDerivationPath {
    let rng = &mut rand::thread_rng();
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
fn initial_dealings() -> InitialIDkgDealings {
    initial_dealings_without_empty_or_default_data()
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

fn mock_signed_dealings(
    transcript_id: IDkgTranscriptId,
    dealers: &BTreeSet<NodeId>,
) -> Vec<SignedIDkgDealing> {
    let mut dealings = Vec::new();
    for node_id in dealers {
        let signed_dealing = SignedIDkgDealing {
            content: IDkgDealing {
                transcript_id,
                internal_dealing_raw: format!("Dummy raw dealing for dealer {}", node_id)
                    .into_bytes(),
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: *node_id,
            },
        };
        dealings.push(signed_dealing);
    }
    dealings
}
