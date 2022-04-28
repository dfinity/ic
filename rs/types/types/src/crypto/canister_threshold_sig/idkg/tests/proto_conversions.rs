#![allow(clippy::unwrap_used)]

use crate::crypto::canister_threshold_sig::error::ExtendedDerivationPathSerializationError;
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgTranscriptId, IDkgTranscriptOperation, InitialIDkgDealings,
};
use crate::crypto::canister_threshold_sig::ExtendedDerivationPath;
use crate::{NodeId, PrincipalId};

use crate::crypto::canister_threshold_sig::idkg::tests::test_utils::{
    create_params_for_dealers, mock_transcript, mock_unmasked_transcript_type,
};
use ic_crypto_test_utils_canister_threshold_sigs::set_of_nodes;
use ic_protobuf::registry::subnet::v1::ExtendedDerivationPath as ExtendedDerivationPathProto;
use ic_protobuf::registry::subnet::v1::InitialIDkgDealings as InitialIDkgDealingsProto;
use ic_protobuf::types::v1::PrincipalId as PrincipalIdProto;
use rand::distributions::Standard;
use rand::{Rng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

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
    assert!(matches!(
        parsing_result,
        Err(ExtendedDerivationPathSerializationError::MissingCaller)
    ));
}

#[test]
fn should_fail_parsing_extended_derivation_path_proto_with_malformed_caller() {
    let derivation_path = dummy_extended_derivation_path();
    let mut proto = ExtendedDerivationPathProto::from(derivation_path);
    proto.caller = Some(PrincipalIdProto { raw: vec![42; 42] });
    let parsing_result = ExtendedDerivationPath::try_from(proto);
    assert!(matches!(
        parsing_result,
        Err(ExtendedDerivationPathSerializationError::InvalidCaller { .. })
    ));
}

fn initial_dealings_without_empty_or_default_data() -> InitialIDkgDealings {
    let previous_receivers = set_of_nodes(&[35, 36, 37, 38]);
    let previous_transcript =
        mock_transcript(Some(previous_receivers), mock_unmasked_transcript_type());
    let dealers = set_of_nodes(&[35, 36, 38]);

    // For a Resharing Unmasked transcript, the dealer set should be a subset of the previous receiver set.
    assert!(dealers.is_subset(previous_transcript.receivers.get()));

    let params = create_params_for_dealers(
        &dealers,
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
    );
    let dealings = mock_dealings(params.transcript_id(), &dealers);

    InitialIDkgDealings::new(params, dealings)
        .expect("Failed creating IDkgInitialDealings for testing")
}

fn dummy_extended_derivation_path() -> ExtendedDerivationPath {
    let mut rng = rand::thread_rng();
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

fn mock_dealings(
    transcript_id: IDkgTranscriptId,
    dealers: &BTreeSet<NodeId>,
) -> BTreeMap<NodeId, IDkgDealing> {
    let mut dealings = BTreeMap::new();
    for node_id in dealers {
        let dealing = IDkgDealing {
            transcript_id,
            dealer_id: *node_id,
            internal_dealing_raw: format!("Dummy raw dealing for dealer {}", node_id).into_bytes(),
        };
        dealings.insert(*node_id, dealing);
    }
    dealings
}
