use crate::NodeId;
use crate::crypto::canister_threshold_sig::error::InitialIDkgDealingsValidationError;
use crate::crypto::canister_threshold_sig::idkg::tests::test_utils::{
    create_idkg_params, mock_masked_transcript_type, mock_transcript,
    mock_unmasked_transcript_type, random_transcript_id,
};
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgTranscriptId, IDkgTranscriptOperation, InitialIDkgDealings, SignedIDkgDealing,
};
use crate::crypto::{BasicSig, BasicSigOf};
use crate::signature::BasicSignature;
use assert_matches::assert_matches;
use ic_crypto_test_utils_canister_threshold_sigs::{ordered_node_id, set_of_nodes};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use std::collections::BTreeSet;

#[test]
fn should_not_create_initial_dealings_with_wrong_operation() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&[1, 2, 3]);
    let receivers = set_of_nodes(&[4, 5, 6]);

    let random_params =
        create_idkg_params(&dealers, &receivers, IDkgTranscriptOperation::Random, rng);
    let initial_dealings_for_random = InitialIDkgDealings::new(random_params, Vec::new());

    // Random transcript creation not enabled for XNet resharing
    assert_eq!(
        initial_dealings_for_random.unwrap_err(),
        InitialIDkgDealingsValidationError::InvalidTranscriptOperation
    );

    let masked_transcript =
        mock_transcript(Some(dealers.clone()), mock_masked_transcript_type(), rng);

    let masked_params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfMasked(masked_transcript.clone()),
        rng,
    );

    let initial_dealings_for_reshare_unmasked = InitialIDkgDealings::new(masked_params, Vec::new());

    // Reshare masked transcript not enabled for XNet resharing
    assert_eq!(
        initial_dealings_for_reshare_unmasked.unwrap_err(),
        InitialIDkgDealingsValidationError::InvalidTranscriptOperation
    );

    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let unmasked_times_masked_params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
        rng,
    );

    let initial_dealings_for_product =
        InitialIDkgDealings::new(unmasked_times_masked_params, Vec::new());

    // Unmasked times masked transcript creation not enabled for XNet resharing
    assert_eq!(
        initial_dealings_for_product.unwrap_err(),
        InitialIDkgDealingsValidationError::InvalidTranscriptOperation
    );
}

#[test]
fn should_not_create_initial_dealings_with_insufficient_dealings() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());
    let receivers = set_of_nodes(&(7..15).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );

    let insufficient_dealers = set_of_nodes(&[0, 1, 3, 4]);

    let insufficient_len = insufficient_dealers.len();
    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    // `insufficient_dealers` should be less than the initial dealings collection threshold
    assert!(insufficient_len < collection_threshold as usize);

    let insufficient_dealings = mock_signed_dealings(params.transcript_id, &insufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, insufficient_dealings);

    assert_eq!(
        initial_dealings.unwrap_err(),
        InitialIDkgDealingsValidationError::UnsatisfiedCollectionThreshold {
            threshold: collection_threshold,
            dealings_count: insufficient_len as u32
        }
    );
}

#[test]
fn should_not_create_initial_dealings_when_dealers_and_receivers_not_disjoint() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());
    let receivers = set_of_nodes(&(5..12).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );

    let dealings = mock_signed_dealings(params.transcript_id, &dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);
    assert_eq!(
        initial_dealings,
        Err(InitialIDkgDealingsValidationError::DealersAndReceiversNotDisjoint)
    );
}

#[test]
fn should_create_initial_dealings_with_sufficient_dealings() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());
    let receivers = set_of_nodes(&(7..15).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );

    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    let sufficient_dealers = set_of_nodes(&[0, 1, 2, 3, 5, 6]);
    let sufficient_len = sufficient_dealers.len();

    // `sufficient_dealers` should be no less than the initial dealings collection threshold
    assert!(sufficient_len > collection_threshold as usize);

    let dealings = mock_signed_dealings(params.transcript_id, &sufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);
    assert!(initial_dealings.is_ok());
    // The initial dealings should contain a minimum number of dealings
    assert_eq!(
        initial_dealings.unwrap().dealings.len(),
        collection_threshold as usize
    );
}

#[test]
fn should_create_initial_dealings_with_minimum_dealings() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());
    let receivers = set_of_nodes(&(7..15).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );
    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    let min_dealers = set_of_nodes(&[0, 1, 2, 3, 6]);
    let min_dealers_len = min_dealers.len();

    // `min_dealers` should contain collection threshold many dealings.
    assert_eq!(min_dealers_len, collection_threshold as usize);

    let dealings = mock_signed_dealings(params.transcript_id, &min_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);
    assert!(initial_dealings.is_ok());
    // The initial dealings should contain a minimum number of dealings
    assert_eq!(initial_dealings.unwrap().dealings.len(), min_dealers_len);
}

#[test]
fn should_not_include_multiple_dealings_from_the_same_dealer() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());
    let receivers = set_of_nodes(&(7..15).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );

    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    let sufficient_dealers = set_of_nodes(&[0, 1, 2, 3, 5]);
    let sufficient_len = sufficient_dealers.len();

    // `sufficient_dealers` should be no less than the initial dealings collection threshold
    assert!(sufficient_len >= collection_threshold as usize);

    let mut dealings = mock_signed_dealings(params.transcript_id, &sufficient_dealers);
    let mut duplicate = dealings[0].clone();
    let duplicate_dealer = duplicate.dealer_id();
    duplicate.content.internal_dealing_raw = "Different dealing from the same dealer"
        .to_string()
        .into_bytes();
    assert_ne!(dealings[0], duplicate);
    dealings.push(duplicate);

    let res = InitialIDkgDealings::new(params, dealings);

    assert_eq!(
        res.unwrap_err(),
        InitialIDkgDealingsValidationError::MultipleDealingsFromSameDealer {
            node_id: duplicate_dealer
        }
    );
}

#[test]
fn should_not_create_initial_dealings_with_wrong_dealers() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());
    let receivers = set_of_nodes(&(7..15).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );

    // Node 100 is not part of the dealers
    assert!(!dealers.contains(&ordered_node_id(100)));

    let sufficient_dealers = set_of_nodes(&[1, 2, 3, 4, 100]);
    let sufficient_len = sufficient_dealers.len();
    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    // `sufficient_dealers` should be no less than the initial dealings collection threshold
    assert!(sufficient_len >= collection_threshold as usize);

    let dealings = mock_signed_dealings(params.transcript_id, &sufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);

    assert_eq!(
        initial_dealings.unwrap_err(),
        InitialIDkgDealingsValidationError::DealerNotAllowed {
            node_id: ordered_node_id(100)
        }
    );
}

#[test]
fn should_not_create_initial_dealings_with_mismatching_transcript_id() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());
    let receivers = set_of_nodes(&(7..15).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript = mock_transcript(
        Some(dealers.clone()),
        mock_unmasked_transcript_type(rng),
        rng,
    );

    let params = create_idkg_params(
        &dealers,
        &receivers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
        rng,
    );

    let sufficient_dealers = set_of_nodes(&[1, 2, 3, 14, 18]);
    let sufficient_len = sufficient_dealers.len();
    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    // `sufficient_dealers` should be no less than the initial dealings collection threshold
    assert!(sufficient_len >= collection_threshold as usize);

    let wrong_transcript_id = random_transcript_id(rng);

    assert_ne!(params.transcript_id, wrong_transcript_id);

    let dealings = mock_signed_dealings(wrong_transcript_id, &sufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);

    assert_eq!(
        initial_dealings.unwrap_err(),
        InitialIDkgDealingsValidationError::MismatchingDealing
    );
}

#[test]
fn should_not_deserialize_if_invariants_violated() {
    let rng = &mut reproducible_rng();
    let dealers = set_of_nodes(&[1, 2, 3]);
    let receivers = set_of_nodes(&[4, 5, 6]);
    let random_params =
        create_idkg_params(&dealers, &receivers, IDkgTranscriptOperation::Random, rng);
    let initial_dealings_with_violated_invariants_created_without_new_constructor =
        InitialIDkgDealings {
            params: random_params,
            dealings: vec![],
        };
    let serialization: Vec<u8> = serde_cbor::to_vec(
        &initial_dealings_with_violated_invariants_created_without_new_constructor,
    )
    .expect("serialization failed");

    let deserialization_result = serde_cbor::from_slice::<InitialIDkgDealings>(&serialization);

    assert_matches!(deserialization_result, Err(serde_error)
        if serde_error.to_string().contains("invariants violated: InvalidTranscriptOperation")
    );
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
                internal_dealing_raw: format!("Dummy raw dealing for dealer {node_id}")
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
