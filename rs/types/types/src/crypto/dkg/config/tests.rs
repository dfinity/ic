use super::*;
use crate::{Height, PrincipalId, SubnetId};

pub const NODE_1: u64 = 1;
pub const NODE_2: u64 = 2;
pub const NODE_3: u64 = 3;
pub const NODE_4: u64 = 4;
pub const NODE_5: u64 = 5;
pub const NODE_6: u64 = 6;

pub const DKG_ID: IDkgId = IDkgId {
    instance_id: Height::new(0),
    subnet_id: SubnetId::new(PrincipalId::new(
        10,
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ],
    )),
};

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

#[test]
fn should_create_minimal_config() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1)],
        receivers: vec![node_id(NODE_1)],
        threshold: 1,
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert!(result.is_ok());
}

#[test]
fn should_fail_if_threshold_is_zero() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1)],
        receivers: vec![node_id(NODE_1)],
        threshold: 0,
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert_error(result, DkgConfigValidationError::ThresholdIsZero);
}

#[test]
fn should_fail_if_dealers_empty() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![],
        receivers: vec![node_id(NODE_1)],
        threshold: 1,
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert_error(
        result,
        DkgConfigValidationError::InsufficientDealersForThreshold,
    );
}

#[test]
fn should_set_dealers_count_correctly() {
    let dealers = Dealers::new(vec![node_id(NODE_1), node_id(NODE_2)]).unwrap();

    assert_eq!(dealers.count().get(), 2);
}

#[test]
fn should_fail_if_dealers_contain_duplicates() {
    const DUPLICATE_NODE: u64 = NODE_1;
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![
            node_id(DUPLICATE_NODE),
            node_id(NODE_2),
            node_id(NODE_3),
            node_id(DUPLICATE_NODE),
            node_id(NODE_5),
        ],
        receivers: vec![node_id(NODE_1)],
        threshold: 1,
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert_error(result, DkgConfigValidationError::DuplicateDealers);
}

#[test]
fn should_fail_if_receivers_empty() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1)],
        receivers: vec![],
        threshold: 1,
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert_error(
        result,
        DkgConfigValidationError::InsufficientReceiversForThreshold,
    );
}

#[test]
fn should_set_receivers_count_correctly() {
    let receivers =
        Receivers::new(vec![node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)]).unwrap();

    assert_eq!(receivers.count().get(), 3);
}

#[test]
fn should_fail_if_receivers_contain_duplicates() {
    const DUPLICATE_NODE: u64 = NODE_1;
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1)],
        receivers: vec![
            node_id(DUPLICATE_NODE),
            node_id(NODE_2),
            node_id(NODE_3),
            node_id(NODE_4),
            node_id(DUPLICATE_NODE),
            node_id(NODE_5),
        ],
        threshold: 1,
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert_error(result, DkgConfigValidationError::DuplicateReceivers);
}

#[test]
fn should_fail_if_insufficient_dealers_for_threshold() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1), node_id(NODE_2)],
        receivers: vec![
            node_id(NODE_1),
            node_id(NODE_2),
            node_id(NODE_3),
            node_id(NODE_4),
            node_id(NODE_5),
        ],
        threshold: 3, // threshold 3 requires at least 3 dealers
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert_error(
        result,
        DkgConfigValidationError::InsufficientDealersForThreshold,
    );
}

#[test]
fn should_succeed_if_exactly_enough_dealers_for_threshold() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)],
        receivers: vec![
            node_id(NODE_1),
            node_id(NODE_2),
            node_id(NODE_3),
            node_id(NODE_4),
            node_id(NODE_5),
            node_id(NODE_6),
        ],
        threshold: 3, // threshold 3 requires at least 3 dealers
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert!(result.is_ok());
}

#[test]
fn should_fail_if_insufficient_receivers_for_threshold() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)],
        receivers: vec![
            node_id(NODE_1),
            node_id(NODE_2),
            node_id(NODE_3),
            node_id(NODE_4),
        ],
        threshold: 3, // threshold 3 requires at least 2*3-1 = 5 receivers
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert_error(
        result,
        DkgConfigValidationError::InsufficientReceiversForThreshold,
    );
}

#[test]
fn should_succeed_if_exactly_enough_receivers_for_threshold() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![
            node_id(NODE_1),
            node_id(NODE_2),
            node_id(NODE_3),
            node_id(NODE_4),
        ],
        receivers: vec![
            node_id(NODE_1),
            node_id(NODE_2),
            node_id(NODE_3),
            node_id(NODE_4),
            node_id(NODE_5),
        ],
        threshold: 3, // threshold 3 requires at least 2*3-1 = 5 receivers
        resharing_transcript: None,
    };

    let result = DkgConfig::new(params);

    assert!(result.is_ok());
}

#[test]
fn should_fail_if_dealer_is_missing_in_resharing_committee() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1), node_id(NODE_2)],
        receivers: vec![node_id(NODE_1)],
        threshold: 1,
        resharing_transcript: Some(transcript_with_committee(&[Some(node_id(NODE_2)), None])),
    };

    let result = DkgConfig::new(params);

    assert_error(
        result,
        DkgConfigValidationError::MissingDealerInResharingCommittee,
    );
}

#[test]
fn should_succeed_if_resharing_committee_contains_dealers() {
    let params = DkgConfigData {
        dkg_id: DKG_ID,
        dealers: vec![node_id(NODE_1), node_id(NODE_2)],
        receivers: vec![node_id(NODE_1)],
        threshold: 1,
        resharing_transcript: Some(transcript_with_committee(&[
            Some(node_id(NODE_2)),
            None,
            Some(node_id(NODE_5)),
            None,
            Some(node_id(NODE_1)),
        ])),
    };

    let result = DkgConfig::new(params);

    assert!(result.is_ok());
}

#[test]
fn should_return_config_values() {
    let (dkg_id, dealers, receivers, threshold, resharing_transcript) = (
        DKG_ID,
        vec![node_id(NODE_1), node_id(NODE_2)],
        vec![node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)],
        2,
        None,
    );
    let params = DkgConfigData {
        dkg_id,
        dealers: dealers.clone(),
        receivers: receivers.clone(),
        threshold,
        resharing_transcript: resharing_transcript.clone(),
    };

    let config = DkgConfig::new(params).unwrap();

    assert_eq!(config.dkg_id(), dkg_id);
    assert_eq!(config.receivers().get(), &receivers[..]);
    assert_eq!(config.receivers().count().get(), 3);
    assert_eq!(config.dealers().get(), &dealers);
    assert_eq!(config.dealers().count().get(), 2);
    assert_eq!(config.threshold(), &DkgThreshold::new(threshold).unwrap());
    assert_eq!(config.resharing_transcript(), &resharing_transcript);
}

fn transcript_with_committee(committee: &[Option<NodeId>]) -> Transcript {
    Transcript {
        dkg_id: DKG_ID,
        committee: committee.to_vec(),
        transcript_bytes: TranscriptBytes(vec![]),
    }
}

fn assert_error(
    config_result: Result<DkgConfig, DkgConfigValidationError>,
    error: DkgConfigValidationError,
) {
    assert_eq!(config_result.unwrap_err(), error);
}
