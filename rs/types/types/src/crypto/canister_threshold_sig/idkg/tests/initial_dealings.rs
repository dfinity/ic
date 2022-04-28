use crate::crypto::canister_threshold_sig::error::InitialIDkgDealingsValidationError;
use crate::crypto::canister_threshold_sig::idkg::tests::test_utils::{
    create_params_for_dealers, mock_masked_transcript_type, mock_transcript,
    mock_unmasked_transcript_type, random_transcript_id,
};
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgTranscriptId, IDkgTranscriptOperation, InitialIDkgDealings,
};
use crate::NodeId;
use ic_crypto_test_utils_canister_threshold_sigs::{node_id, set_of_nodes};
use std::collections::BTreeMap;

// TODO(CRP-1403): Add tests for successful creation of initial dealings.

#[test]
fn should_not_create_initial_dealings_with_wrong_operation() {
    let dealers = set_of_nodes(&[1, 2, 3]);

    let random_params = create_params_for_dealers(&dealers, IDkgTranscriptOperation::Random);
    let initial_dealings_for_random = InitialIDkgDealings::new(random_params, BTreeMap::new());

    // Random transcript creation not enabled for XNet resharing
    assert_eq!(
        initial_dealings_for_random.unwrap_err(),
        InitialIDkgDealingsValidationError::InvalidTranscriptOperation
    );

    let masked_transcript = mock_transcript(Some(dealers.clone()), mock_masked_transcript_type());

    let masked_params = create_params_for_dealers(
        &dealers,
        IDkgTranscriptOperation::ReshareOfMasked(masked_transcript.clone()),
    );

    let initial_dealings_for_reshare_unmasked =
        InitialIDkgDealings::new(masked_params, BTreeMap::new());

    // Reshare masked transcript not enabled for XNet resharing
    assert_eq!(
        initial_dealings_for_reshare_unmasked.unwrap_err(),
        InitialIDkgDealingsValidationError::InvalidTranscriptOperation
    );

    let unmasked_transcript =
        mock_transcript(Some(dealers.clone()), mock_unmasked_transcript_type());

    let unmasked_times_masked_params = create_params_for_dealers(
        &dealers,
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
    );

    let initial_dealings_for_product =
        InitialIDkgDealings::new(unmasked_times_masked_params, BTreeMap::new());

    // Unmasked times masked transcript creation not enabled for XNet resharing
    assert_eq!(
        initial_dealings_for_product.unwrap_err(),
        InitialIDkgDealingsValidationError::InvalidTranscriptOperation
    );
}

#[test]
fn should_not_create_initial_dealings_with_insufficient_dealings() {
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript =
        mock_transcript(Some(dealers.clone()), mock_unmasked_transcript_type());

    let params = create_params_for_dealers(
        &dealers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
    );

    let insufficient_dealers: Vec<u64> = vec![0, 1, 3, 4];

    let insufficient_len = insufficient_dealers.len();
    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    // `insufficient_dealers` should be less than the initial dealings collection threshold
    assert!(insufficient_len < collection_threshold as usize);

    let insufficient_dealings = mock_dealings(params.transcript_id, &insufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params.clone(), insufficient_dealings);

    assert_eq!(
        initial_dealings.unwrap_err(),
        InitialIDkgDealingsValidationError::UnsatisfiedCollectionThreshold {
            threshold: collection_threshold,
            dealings_count: insufficient_len as u32
        }
    );

    let sufficient_dealers = vec![1, 2, 3, 5, 6];
    let sufficient_len = sufficient_dealers.len();

    // `sufficient_dealers` should be no less than the initial dealings collection threshold
    assert!(sufficient_len >= collection_threshold as usize);

    let dealings = mock_dealings(params.transcript_id, &sufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);

    assert!(initial_dealings.is_ok());
}

#[test]
fn should_not_create_initial_dealings_with_wrong_dealers() {
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript =
        mock_transcript(Some(dealers.clone()), mock_unmasked_transcript_type());

    let params = create_params_for_dealers(
        &dealers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
    );

    // Node 100 is not part of the dealers
    assert!(dealers.get(&node_id(100)).is_none());

    let sufficient_dealers = vec![1, 2, 3, 4, 100];
    let sufficient_len = sufficient_dealers.len();
    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    // `sufficient_dealers` should be no less than the initial dealings collection threshold
    assert!(sufficient_len >= collection_threshold as usize);

    let dealings = mock_dealings(params.transcript_id, &sufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);

    assert_eq!(
        initial_dealings.unwrap_err(),
        InitialIDkgDealingsValidationError::DealerNotAllowed {
            node_id: node_id(100)
        }
    );
}

#[test]
fn should_not_create_initial_dealings_with_mismatching_transcript_id() {
    let dealers = set_of_nodes(&(0..7).collect::<Vec<_>>());

    // Transcript to be reshared
    let unmasked_transcript =
        mock_transcript(Some(dealers.clone()), mock_unmasked_transcript_type());

    let params = create_params_for_dealers(
        &dealers,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript),
    );

    let sufficient_dealers = vec![1, 2, 3, 14, 18];
    let sufficient_len = sufficient_dealers.len();
    let collection_threshold = params
        .unverified_dealings_collection_threshold()
        .unwrap()
        .get();

    // `sufficient_dealers` should be no less than the initial dealings collection threshold
    assert!(sufficient_len >= collection_threshold as usize);

    let wrong_transcript_id = random_transcript_id();

    assert_ne!(params.transcript_id, wrong_transcript_id);

    let dealings = mock_dealings(wrong_transcript_id, &sufficient_dealers);
    let initial_dealings = InitialIDkgDealings::new(params, dealings);

    assert_eq!(
        initial_dealings.unwrap_err(),
        InitialIDkgDealingsValidationError::MismatchingDealing
    );
}

fn mock_dealings(
    transcript_id: IDkgTranscriptId,
    dealers: &[u64],
) -> BTreeMap<NodeId, IDkgDealing> {
    let mut dealings = BTreeMap::new();

    for &i in dealers {
        let node_id = node_id(i);
        let dealing = IDkgDealing {
            transcript_id,
            dealer_id: node_id,
            internal_dealing_raw: vec![],
        };
        dealings.insert(node_id, dealing);
    }
    dealings
}
