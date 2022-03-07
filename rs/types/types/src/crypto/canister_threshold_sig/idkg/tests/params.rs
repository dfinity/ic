use super::super::*;
use crate::crypto::AlgorithmId;
use crate::RegistryVersion;
use crate::{NodeId, PrincipalId, SubnetId};
use maplit::btreeset;
use std::collections::BTreeSet;

#[test]
fn should_return_correct_dealer_index_for_random() {
    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(42));
    dealers.insert(node_id(43));
    dealers.insert(node_id(45));

    let params = IDkgTranscriptParams::new(
        transcript_id_generator(),
        dealers.clone(),
        dealers,
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        IDkgTranscriptOperation::Random,
    )
    .expect("Should be able to create IDKG params");

    // For a random transcript the dealer index correspond to its position in the dealer set
    assert_eq!(params.dealer_index(node_id(42)), Some(0));
    assert_eq!(params.dealer_index(node_id(43)), Some(1));
    assert_eq!(params.dealer_index(node_id(44)), None);
    assert_eq!(params.dealer_index(node_id(45)), Some(2));
    assert_eq!(params.dealer_index(node_id(46)), None);
}

#[test]
fn should_return_correct_dealer_index_for_reshare_masked() {
    let mut previous_receivers = BTreeSet::new();
    previous_receivers.insert(node_id(35));
    previous_receivers.insert(node_id(36));
    previous_receivers.insert(node_id(37));
    previous_receivers.insert(node_id(38));

    let previous_transcript =
        mock_transcript(Some(previous_receivers), mock_masked_transcript_type());

    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(35));
    dealers.insert(node_id(36));
    dealers.insert(node_id(38));

    // For a Resharing Masked transcript, the dealer set should be a subset of the previous receiver set.
    assert!(dealers.is_subset(previous_transcript.receivers.get()));

    let params = IDkgTranscriptParams::new(
        transcript_id_generator(),
        dealers.clone(),
        dealers,
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        IDkgTranscriptOperation::ReshareOfMasked(previous_transcript),
    )
    .expect("Should be able to create IDKG params");

    // For resharing a masked transcript the dealer index correspond to its position in the `previous_receiver` set
    assert_eq!(params.dealer_index(node_id(35)), Some(0));
    assert_eq!(params.dealer_index(node_id(36)), Some(1));
    // Node 37 is not included in the dealer set, thus it does not have a dealer index.
    assert_eq!(params.dealer_index(node_id(37)), None);
    assert_eq!(params.dealer_index(node_id(38)), Some(3));
    assert_eq!(params.dealer_index(node_id(39)), None);
}

#[test]
fn should_return_correct_dealer_index_for_reshare_unmasked() {
    let mut previous_receivers = BTreeSet::new();
    previous_receivers.insert(node_id(35));
    previous_receivers.insert(node_id(36));
    previous_receivers.insert(node_id(37));
    previous_receivers.insert(node_id(38));

    let previous_transcript =
        mock_transcript(Some(previous_receivers), mock_unmasked_transcript_type());

    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(35));
    dealers.insert(node_id(36));
    dealers.insert(node_id(38));

    // For a Resharing Unmasked transcript, the dealer set should be a subset of the previous receiver set.
    assert!(dealers.is_subset(previous_transcript.receivers.get()));

    let params = IDkgTranscriptParams::new(
        transcript_id_generator(),
        dealers.clone(),
        dealers,
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
    )
    .expect("Should be able to create IDKG params");

    // For resharing an unmasked transcript the dealer index correspond to its position in the `previous_receiver` set
    assert_eq!(params.dealer_index(node_id(35)), Some(0));
    assert_eq!(params.dealer_index(node_id(36)), Some(1));
    // Node 37 is not included in the dealer set, thus it does not have a dealer index.
    assert_eq!(params.dealer_index(node_id(37)), None);
    assert_eq!(params.dealer_index(node_id(38)), Some(3));
    assert_eq!(params.dealer_index(node_id(39)), None);
}

#[test]
fn should_return_correct_dealer_index_for_unmasked_times_masked() {
    let mut previous_receivers = BTreeSet::new();
    previous_receivers.insert(node_id(35));
    previous_receivers.insert(node_id(36));
    previous_receivers.insert(node_id(37));
    previous_receivers.insert(node_id(38));

    let previous_unmasked_transcript = mock_transcript(
        Some(previous_receivers.clone()),
        mock_unmasked_transcript_type(),
    );
    let previous_masked_transcript =
        mock_transcript(Some(previous_receivers), mock_masked_transcript_type());

    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(35));
    dealers.insert(node_id(36));
    dealers.insert(node_id(38));

    // For unmasked times masked transcript, the dealer set should be a subset of the previous receiver set.
    assert!(dealers.is_subset(previous_unmasked_transcript.receivers.get()));
    assert!(dealers.is_subset(previous_masked_transcript.receivers.get()));

    let params = IDkgTranscriptParams::new(
        transcript_id_generator(),
        dealers.clone(),
        dealers,
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        IDkgTranscriptOperation::UnmaskedTimesMasked(
            previous_unmasked_transcript,
            previous_masked_transcript,
        ),
    )
    .expect("Should be able to create IDKG params");

    // For an unmasked times masked transcript the dealer index correspond to its position in the `previous_receiver` set
    assert_eq!(params.dealer_index(node_id(35)), Some(0));
    assert_eq!(params.dealer_index(node_id(36)), Some(1));
    // Node 37 is not included in the dealer set, thus it does not have a dealer index.
    assert_eq!(params.dealer_index(node_id(37)), None);
    assert_eq!(params.dealer_index(node_id(38)), Some(3));
    assert_eq!(params.dealer_index(node_id(39)), None);
}

#[test]
fn should_return_correct_receiver_index() {
    let params = IDkgTranscriptParams::new(
        transcript_id_generator(),
        btreeset! {node_id(42), node_id(43), node_id(45)},
        btreeset! {node_id(43), node_id(45), node_id(46)},
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        IDkgTranscriptOperation::Random,
    )
    .expect("Should be able to create IDKG params");

    assert_eq!(params.receiver_index(node_id(42)), None);
    assert_eq!(params.receiver_index(node_id(43)), Some(0));
    assert_eq!(params.receiver_index(node_id(44)), None);
    assert_eq!(params.receiver_index(node_id(45)), Some(1));
    assert_eq!(params.receiver_index(node_id(46)), Some(2));
}

#[test]
fn should_create_random() {
    check_params_creation(None, IDkgTranscriptOperation::Random, None);
}

#[test]
fn should_not_create_with_empty_dealers() {
    let empty_dealers = BTreeSet::new();

    let result = IDkgTranscriptParams::new(
        transcript_id_generator(),
        empty_dealers,
        btreeset! {node_id(1)},
        RegistryVersion::from(0),
        AlgorithmId::Placeholder, // should be ThresholdEcdsaSecp256k1 !
        IDkgTranscriptOperation::Random,
    );

    assert!(matches!(
        result,
        Err(IDkgParamsValidationError::DealersEmpty)
    ));
}

#[test]
fn should_not_create_with_empty_receivers() {
    let empty_receivers = BTreeSet::new();

    let result = IDkgTranscriptParams::new(
        transcript_id_generator(),
        btreeset! {node_id(1)},
        empty_receivers,
        RegistryVersion::from(0),
        AlgorithmId::Placeholder, // should be ThresholdEcdsaSecp256k1 !
        IDkgTranscriptOperation::Random,
    );

    assert!(matches!(
        result,
        Err(IDkgParamsValidationError::ReceiversEmpty)
    ));
}

#[test]
fn should_not_create_reshare_masked_with_too_few_dealers() {
    // 13 receivers will require (4+1)=5 shares for recombination
    let previous_transcript = {
        let mut previous_receivers = BTreeSet::new();
        for i in 1..14 {
            previous_receivers.insert(node_id(i));
        }

        mock_transcript(Some(previous_receivers), mock_masked_transcript_type())
    };

    // 5 dealers (and receivers),
    // which means tolerated_faulty_nodes=1,
    // so collection_threshold is (5+1)=6
    let mut nodes = BTreeSet::new();
    nodes.insert(node_id(1));
    nodes.insert(node_id(2));
    nodes.insert(node_id(3));
    nodes.insert(node_id(4));
    nodes.insert(node_id(5));
    check_params_creation(
        Some(nodes),
        IDkgTranscriptOperation::ReshareOfMasked(previous_transcript),
        Some(IDkgParamsValidationError::UnsatisfiedCollectionThreshold {
            threshold: 6,
            dealer_count: 5,
        }),
    );
}

#[test]
fn should_not_create_reshare_unmasked_with_too_few_dealers() {
    // 13 receivers will require (4+1)=5 shares for recombination
    let previous_transcript = {
        let mut previous_receivers = BTreeSet::new();
        for i in 1..14 {
            previous_receivers.insert(node_id(i));
        }

        mock_transcript(Some(previous_receivers), mock_unmasked_transcript_type())
    };

    // 5 dealers (and receivers),
    // which means tolerated_faulty_nodes=1,
    // so collection_threshold is (5+1)=6
    let mut nodes = BTreeSet::new();
    nodes.insert(node_id(1));
    nodes.insert(node_id(2));
    nodes.insert(node_id(3));
    nodes.insert(node_id(4));
    nodes.insert(node_id(5));
    check_params_creation(
        Some(nodes),
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
        Some(IDkgParamsValidationError::UnsatisfiedCollectionThreshold {
            threshold: 6,
            dealer_count: 5,
        }),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_too_few_dealers() {
    // 10 receivers will require 7 shares for recombination, after multiplication
    let (previous_unmasked, previous_masked) = {
        let mut previous_receivers = BTreeSet::new();
        for i in 1..11 {
            previous_receivers.insert(node_id(i));
        }

        let previous_unmasked = mock_transcript(
            Some(previous_receivers.clone()),
            mock_unmasked_transcript_type(),
        );
        let previous_masked =
            mock_transcript(Some(previous_receivers), mock_masked_transcript_type());

        (previous_unmasked, previous_masked)
    };

    // 8 dealers (and receivers),
    // which means tolerated_faulty_nodes=2,
    // so collection_threshold is (7+2)=9
    let mut nodes = BTreeSet::new();
    nodes.insert(node_id(1));
    nodes.insert(node_id(2));
    nodes.insert(node_id(3));
    nodes.insert(node_id(4));
    nodes.insert(node_id(5));
    nodes.insert(node_id(6));
    nodes.insert(node_id(7));
    nodes.insert(node_id(8));
    check_params_creation(
        Some(nodes),
        IDkgTranscriptOperation::UnmaskedTimesMasked(previous_unmasked, previous_masked),
        Some(IDkgParamsValidationError::UnsatisfiedCollectionThreshold {
            threshold: 9,
            dealer_count: 8,
        }),
    );
}

#[test]
fn should_not_create_with_placeholder_algid() {
    let mut nodes = BTreeSet::new();
    nodes.insert(node_id(1));

    let result = IDkgTranscriptParams::new(
        transcript_id_generator(),
        nodes.clone(),
        nodes,
        RegistryVersion::from(0),
        AlgorithmId::Placeholder, // should be ThresholdEcdsaSecp256k1 !
        IDkgTranscriptOperation::Random,
    );

    assert!(matches!(
        result.unwrap_err(),
        IDkgParamsValidationError::UnsupportedAlgorithmId {
            algorithm_id: AlgorithmId::Placeholder
        }
    ));
}

#[test]
fn should_not_create_with_wrong_algid() {
    let mut nodes = BTreeSet::new();
    nodes.insert(node_id(1));

    let result = IDkgTranscriptParams::new(
        transcript_id_generator(),
        nodes.clone(),
        nodes,
        RegistryVersion::from(0),
        AlgorithmId::RsaSha256, // should be ThresholdEcdsaSecp256k1 !
        IDkgTranscriptOperation::Random,
    );

    assert!(matches!(
        result.unwrap_err(),
        IDkgParamsValidationError::UnsupportedAlgorithmId {
            algorithm_id: AlgorithmId::RsaSha256
        }
    ));
}

#[test]
fn should_not_create_reshare_masked_with_wrong_original_type() {
    let previous_transcript = mock_transcript(
        None,
        mock_unmasked_transcript_type(), // should be masked!
    );

    check_params_creation(
        Some(previous_transcript.receivers.get().clone()), // same as previous
        IDkgTranscriptOperation::ReshareOfMasked(previous_transcript),
        Some(IDkgParamsValidationError::WrongTypeForOriginalTranscript),
    );
}

#[test]
fn should_not_create_reshare_masked_with_disjoint_original_receivers() {
    let previous_transcript = mock_transcript(None, mock_masked_transcript_type());

    // New node set that's disjoint from previous receivers
    let new_nodes = disjoint_set();
    assert!(new_nodes.is_disjoint(previous_transcript.receivers.get()));
    check_params_creation(
        Some(new_nodes),
        IDkgTranscriptOperation::ReshareOfMasked(previous_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

#[test]
fn should_not_create_reshare_masked_with_superset_of_original_receivers() {
    let previous_transcript = mock_transcript(None, mock_masked_transcript_type());

    // New node set that's a superset of the previous receivers
    let mut new_nodes = previous_transcript.receivers.get().clone();
    new_nodes.insert(
        *disjoint_set()
            .iter()
            .next()
            .expect("we know this isn't empty"),
    );
    assert!(new_nodes.len() > previous_transcript.receivers.get().len());
    check_params_creation(
        Some(new_nodes),
        IDkgTranscriptOperation::ReshareOfMasked(previous_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

#[test]
fn should_not_create_reshare_unmasked_with_wrong_original_type() {
    let previous_transcript = mock_transcript(
        None,
        mock_masked_transcript_type(), // should be unmasked!
    );

    check_params_creation(
        Some(previous_transcript.receivers.get().clone()), // same as previous
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
        Some(IDkgParamsValidationError::WrongTypeForOriginalTranscript),
    );
}

#[test]
fn should_not_create_reshare_unmasked_with_disjoint_original_receivers() {
    let previous_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    // New node set that's disjoint from previous receivers
    let new_nodes = disjoint_set();
    assert!(new_nodes.is_disjoint(previous_transcript.receivers.get()));
    check_params_creation(
        Some(new_nodes),
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

#[test]
fn should_not_create_reshare_unmasked_with_superset_of_original_receivers() {
    let previous_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    // New node set that's a superset of the previous receivers
    let mut new_nodes = previous_transcript.receivers.get().clone();
    new_nodes.insert(
        *disjoint_set()
            .iter()
            .next()
            .expect("we know this isn't empty"),
    );
    assert!(new_nodes.len() > previous_transcript.receivers.get().len());
    check_params_creation(
        Some(new_nodes),
        IDkgTranscriptOperation::ReshareOfUnmasked(previous_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_wrong_left_original_type() {
    let masked_transcript = mock_transcript(
        None,
        mock_masked_transcript_type(), // should be unmasked!
    );

    let masked_transcript_2 = mock_transcript(
        Some(masked_transcript.receivers.get().clone()), // same as above
        mock_masked_transcript_type(),
    );

    check_params_creation(
        Some(masked_transcript.receivers.get().clone()), // same as previous transcripts
        IDkgTranscriptOperation::UnmaskedTimesMasked(masked_transcript, masked_transcript_2),
        Some(IDkgParamsValidationError::WrongTypeForOriginalTranscript),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_wrong_right_original_type() {
    let unmasked_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    let unmasked_transcript_2 = mock_transcript(
        Some(unmasked_transcript.receivers.get().clone()), // same as above
        mock_unmasked_transcript_type(),                   // should be masked!
    );

    check_params_creation(
        Some(unmasked_transcript.receivers.get().clone()), // same as previous transcripts
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, unmasked_transcript_2),
        Some(IDkgParamsValidationError::WrongTypeForOriginalTranscript),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_wrong_original_types() {
    let masked_transcript = mock_transcript(None, mock_masked_transcript_type());

    let unmasked_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    check_params_creation(
        Some(masked_transcript.receivers.get().clone()), // same as previous transcripts
        IDkgTranscriptOperation::UnmaskedTimesMasked(masked_transcript, unmasked_transcript), /* should be otherway around */
        Some(IDkgParamsValidationError::WrongTypeForOriginalTranscript),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_disjoint_original_receivers() {
    let unmasked_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    // New receiver set that's disjoint from unmasked_transcript's receivers
    let new_receivers = disjoint_set();
    assert!(new_receivers.is_disjoint(unmasked_transcript.receivers.get()));
    let masked_transcript = mock_transcript(Some(new_receivers), mock_masked_transcript_type());

    let params_nodes = unmasked_transcript.receivers.get().clone();
    check_params_creation(
        Some(params_nodes),
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_unequal_original_receivers() {
    let unmasked_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    // New receiver set that's a superset of the previous receivers
    let mut new_receivers = unmasked_transcript.receivers.get().clone();
    new_receivers.insert(
        *disjoint_set()
            .iter()
            .next()
            .expect("we know this isn't empty"),
    );
    assert!(new_receivers.len() > unmasked_transcript.receivers.get().len());
    let masked_transcript = mock_transcript(Some(new_receivers), mock_masked_transcript_type());

    let params_nodes = unmasked_transcript.receivers.get().clone();
    check_params_creation(
        Some(params_nodes),
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_dealers_disjoint_from_original_receivers() {
    let unmasked_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    let masked_transcript = mock_transcript(
        Some(unmasked_transcript.receivers.get().clone()), // same as unmasked_transcript
        mock_masked_transcript_type(),
    );

    // New dealer set that's disjoint from previous receivers
    let new_dealers = disjoint_set();
    assert!(new_dealers.is_disjoint(unmasked_transcript.receivers.get()));
    check_params_creation(
        Some(new_dealers),
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

#[test]
fn should_not_create_unmasked_times_masked_with_dealers_unequal_from_original_receivers() {
    let unmasked_transcript = mock_transcript(None, mock_unmasked_transcript_type());

    let masked_transcript = mock_transcript(
        Some(unmasked_transcript.receivers.get().clone()), // same as unmasked_transcript
        mock_masked_transcript_type(),
    );

    // New dealer set that's a superset of the previous receivers
    let mut new_dealers = unmasked_transcript.receivers.get().clone();
    new_dealers.insert(
        *disjoint_set()
            .iter()
            .next()
            .expect("we know this isn't empty"),
    );
    assert!(new_dealers.len() > unmasked_transcript.receivers.get().len());
    check_params_creation(
        Some(new_dealers),
        IDkgTranscriptOperation::UnmaskedTimesMasked(unmasked_transcript, masked_transcript),
        Some(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers),
    );
}

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

fn mock_transcript(
    receivers: Option<BTreeSet<NodeId>>,
    transcript_type: IDkgTranscriptType,
) -> IDkgTranscript {
    let receivers = match receivers {
        Some(receivers) => receivers,
        None => original_node_set(),
    };

    IDkgTranscript {
        transcript_id: transcript_id_generator(),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}

fn original_node_set() -> BTreeSet<NodeId> {
    let mut nodes = BTreeSet::new();
    for i in 1..10 {
        nodes.insert(node_id(i));
    }
    nodes
}

fn disjoint_set() -> BTreeSet<NodeId> {
    let mut nodes = BTreeSet::new();
    for i in 11..20 {
        nodes.insert(node_id(i));
    }

    nodes
}

fn mock_unmasked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        transcript_id_generator(),
    ))
}

fn mock_masked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
}

fn check_params_creation(
    node_set: Option<BTreeSet<NodeId>>,
    operation: IDkgTranscriptOperation,
    expected_error: Option<IDkgParamsValidationError>,
) {
    let node_set = match node_set {
        Some(node_set) => node_set,
        None => {
            let mut node_set = BTreeSet::new();
            for i in 1..10 {
                node_set.insert(node_id(i));
            }
            node_set
        }
    };

    let result = IDkgTranscriptParams::new(
        transcript_id_generator(),
        node_set.clone(),
        node_set,
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        operation,
    );

    match expected_error {
        None => {
            assert!(result.is_ok());
        }
        Some(expected_err) => {
            let err = result.unwrap_err();
            assert_eq!(err, expected_err);
        }
    }
}

// Stupid way to get non-repeating IDs, without needing an RNG
fn transcript_id_generator() -> IDkgTranscriptId {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let transcript_ids: Vec<usize> = (1..100).collect();
    static TRANSCRIPT_ID_POSITION: AtomicUsize = AtomicUsize::new(0);

    let id_pos = TRANSCRIPT_ID_POSITION.load(Ordering::SeqCst);
    TRANSCRIPT_ID_POSITION.fetch_add(1, Ordering::SeqCst);

    let id = transcript_ids[id_pos];
    const SUBNET_ID: u64 = 314159;
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(SUBNET_ID));

    IDkgTranscriptId::new(subnet, id)
}
