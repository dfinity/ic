#![allow(clippy::unwrap_used)]

use super::*;
use ic_crypto_test_utils_canister_threshold_sigs::{
    create_params_for_dealers, mock_transcript, mock_unmasked_transcript_type, set_of_nodes,
};

#[test]
fn should_correctly_serialize_and_deserialize() {
    let initial_dealings = initial_dealings();
    let proto = idkg_initial_dealings_to_proto(initial_dealings.clone());
    let parsing_result = idkg_initial_dealings_from_proto(proto);
    assert!(parsing_result.is_ok(), "{:?}", parsing_result.err());
    let parsed = parsing_result.unwrap();
    assert_eq!(initial_dealings, parsed);
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
