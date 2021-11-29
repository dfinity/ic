use super::super::*;
use crate::{NodeId, PrincipalId};

const NODE_1: u64 = 1;
const NODE_2: u64 = 2;
const NODE_3: u64 = 3;

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

#[test]
fn should_not_create_empty_receivers() {
    let result = IDkgReceivers::new(BTreeSet::new());

    let err = result.unwrap_err();

    assert!(matches!(err, IDkgParamsValidationError::ReceiversEmpty));
}

#[test]
fn should_create_non_empty_receivers() {
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    let result = IDkgReceivers::new(receivers);

    assert!(result.is_ok());
}

#[test]
fn should_return_correct_receivers() {
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    let result = IDkgReceivers::new(receivers.clone());

    assert_eq!(result.unwrap().get(), &receivers);
}

#[test]
fn should_return_correct_receivers_iter() {
    let mut receivers = vec![node_id(NODE_1), node_id(NODE_2)];

    // The indices should correspond to the natural ordering of the elements:
    receivers.sort();
    let receivers_with_indices: BTreeSet<(NodeIndex, NodeId)> =
        (0..).zip(receivers.iter().copied()).collect();

    // The contents and indices should be correct regardless of the order of
    // insertion:
    for _ in 0..2 {
        receivers.reverse();
        let receivers_only: BTreeSet<NodeId> = receivers.iter().copied().collect();
        let result = IDkgReceivers::new(receivers_only).unwrap();
        let receivers_returned_by_iter: BTreeSet<(NodeIndex, NodeId)> = result.iter().collect();
        assert_eq!(receivers_returned_by_iter, receivers_with_indices);
    }
}

#[test]
fn should_return_correct_receivers_count() {
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    receivers.insert(node_id(NODE_2));
    let result = IDkgReceivers::new(receivers);

    assert_eq!(result.unwrap().count().get(), 2);
}

#[test]
fn should_return_correct_sorted_receiver_position() {
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_3));
    receivers.insert(node_id(NODE_1));
    receivers.insert(node_id(NODE_2));
    let receivers = IDkgReceivers::new(receivers).unwrap();

    assert_eq!(receivers.position(node_id(NODE_1)).unwrap(), 0);
    assert_eq!(receivers.position(node_id(NODE_2)).unwrap(), 1);
    assert_eq!(receivers.position(node_id(NODE_3)).unwrap(), 2);
}

#[test]
fn should_return_none_position_if_node_id_not_in_receivers() {
    let not_a_receiver_node = node_id(NODE_3);
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    receivers.insert(node_id(NODE_2));
    let receivers = IDkgReceivers::new(receivers).unwrap();

    assert!(receivers.position(not_a_receiver_node).is_none());
}

#[test]
fn should_return_correct_reconstruction_threshold() {
    let mut receivers = BTreeSet::new();

    for i in 0..10 {
        for j in 1..4 {
            receivers.insert(node_id(i * 3 + j));
            let result = IDkgReceivers::new(receivers.clone());
            assert_eq!(
                result.unwrap().reconstruction_threshold().get(),
                (i as u32) + 1
            );
        }
    }
}

#[test]
fn should_return_correct_verification_threshold() {
    let mut receivers = BTreeSet::new();

    for i in 0..10 {
        for j in 1..4 {
            receivers.insert(node_id(i * 3 + j));
            let result = IDkgReceivers::new(receivers.clone());
            assert_eq!(
                result.unwrap().verification_threshold().get(),
                2 * (i as u32) + 1
            );
        }
    }
}
