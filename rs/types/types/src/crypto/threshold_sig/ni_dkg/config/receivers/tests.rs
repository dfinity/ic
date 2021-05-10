use super::*;
use crate::PrincipalId;

const NODE_1: u64 = 1;
const NODE_2: u64 = 2;
const NODE_3: u64 = 3;

fn node_id(id: u64) -> NodeId {
    NodeId::new(PrincipalId::new_node_test_id(id))
}

#[test]
fn should_not_create_empty_receivers() {
    let receivers = BTreeSet::new();
    let result = NiDkgReceivers::new(receivers);

    assert_eq!(result, Err(NiDkgConfigValidationError::ReceiversEmpty));
}

#[test]
fn should_create_non_empty_receivers() {
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    let result = NiDkgReceivers::new(receivers);

    assert!(result.is_ok());
}

#[test]
fn should_return_correct_receivers() {
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    let result = NiDkgReceivers::new(receivers.clone());

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
        let result = NiDkgReceivers::new(receivers_only).unwrap();
        let receivers_returned_by_iter: BTreeSet<(NodeIndex, NodeId)> = result.iter().collect();
        assert_eq!(receivers_returned_by_iter, receivers_with_indices);
    }
}

#[test]
fn should_return_correct_receivers_count() {
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    receivers.insert(node_id(NODE_2));
    let result = NiDkgReceivers::new(receivers);

    assert_eq!(result.unwrap().count().get(), 2);
}

#[test]
fn should_return_correct_sorted_receiver_position() {
    let mut receiver_set = BTreeSet::new();
    receiver_set.insert(node_id(NODE_3));
    receiver_set.insert(node_id(NODE_1));
    receiver_set.insert(node_id(NODE_2));
    let dkg_receivers = NiDkgReceivers::new(receiver_set).unwrap();

    assert_eq!(dkg_receivers.position(node_id(NODE_1)).unwrap(), 0);
    assert_eq!(dkg_receivers.position(node_id(NODE_2)).unwrap(), 1);
    assert_eq!(dkg_receivers.position(node_id(NODE_3)).unwrap(), 2);
}

#[test]
fn should_return_none_position_if_node_id_not_in_dealers() {
    let not_a_receiver_node = node_id(NODE_3);
    let mut receivers = BTreeSet::new();
    receivers.insert(node_id(NODE_1));
    receivers.insert(node_id(NODE_2));
    let dealers = NiDkgReceivers::new(receivers).unwrap();

    assert!(dealers.position(not_a_receiver_node).is_none());
}
