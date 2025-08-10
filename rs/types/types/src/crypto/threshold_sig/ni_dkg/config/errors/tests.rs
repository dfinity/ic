use super::*;
use crate::crypto::tests::set_of;
use crate::PrincipalId;

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

#[test]
fn should_correctly_display_too_many_receivers_error() {
    let error = NiDkgConfigValidationError::TooManyReceivers { receivers_count: 5 };

    assert_display_msg_eq(
        error,
        "The number of receivers does not fit into NumberOfNodes. Number of receivers: 5",
    );
}

#[test]
fn should_correctly_display_too_many_dealers_error() {
    let error = NiDkgConfigValidationError::TooManyDealers { dealers_count: 200 };

    assert_display_msg_eq(
        error,
        "The number of dealers does not fit into NumberOfNodes. Number of dealers: 200",
    );
}

#[test]
fn should_correctly_display_insufficient_threshold() {
    let error = NiDkgConfigValidationError::InsufficientThreshold {
        threshold: NiDkgThreshold {
            threshold: NumberOfNodes::new(15),
        },
        max_corrupt_receivers: NumberOfNodes::new(15),
    };

    assert_display_msg_eq(
        error,
        "The threshold (value: 15) must be greater than max_corrupt_receivers (value: 15).",
    );
}

#[test]
fn should_correctly_display_insufficient_dealers_error() {
    let error = NiDkgConfigValidationError::InsufficientDealers {
        dealer_count: NumberOfNodes::new(20),
        max_corrupt_dealers: NumberOfNodes::new(30),
    };

    assert_display_msg_eq(
        error,
        "The number of dealers (value: 20) must be greater than max_corrupt_dealers (value: 30).",
    );
}

#[test]
fn should_correctly_display_insufficient_receivers_error() {
    let error = NiDkgConfigValidationError::InsufficientReceivers {
        receiver_count: NumberOfNodes::new(20),
        max_corrupt_receivers: NumberOfNodes::new(15),
        threshold: NiDkgThreshold {
            threshold: NumberOfNodes::new(15),
        },
    };

    assert_display_msg_eq(
        error,
        "The number of receivers (value: 20) must be greater than or equal to max_corrupt_receivers (value: 15) + threshold (value: 15).",
    );
}

#[test]
fn should_correctly_display_dealers_not_in_resharing_committee_error() {
    let error = NiDkgConfigValidationError::DealersNotInResharingCommittee {
        dealers_missing: set_of(&[node_id(1), node_id(3)]),
        dealers_existing: set_of(&[node_id(2)]),
        resharing_committee: set_of(&[node_id(2), node_id(5)]),
    };

    assert_display_msg_eq(
        error,
        "The dealers must all be contained in the resharing committee. Dealers missing in committee: {3jo2y-lqbaa-aaaaa-aaaap-2ai, 32uhy-eydaa-aaaaa-aaaap-2ai}, dealers in committee: {gfvbo-licaa-aaaaa-aaaap-2ai}, resharing committee: {gfvbo-licaa-aaaaa-aaaap-2ai, 2o3ay-vafaa-aaaaa-aaaap-2ai}",
    );
}

#[test]
fn should_correctly_display_insufficient_dealers_in_resharing_committee_error() {
    let error = NiDkgConfigValidationError::InsufficientDealersForResharingThreshold {
        dealer_count: NumberOfNodes::new(2),
        resharing_threshold: NiDkgThreshold {
            threshold: NumberOfNodes::new(3),
        },
    };

    assert_display_msg_eq(
        error,
        "The number of dealers (value: 2) must be greater than or equal to the resharing threshold (value: 3)",
    );
}

#[test]
fn should_correctly_display_threshold_zero_error() {
    let error = NiDkgConfigValidationError::ThresholdZero;

    assert_display_msg_eq(error, "The threshold must not be zero.");
}

fn assert_display_msg_eq(error: NiDkgConfigValidationError, msg: &str) {
    let display_msg = format!("{}", error);
    assert_eq!(display_msg.as_str(), msg);
}
