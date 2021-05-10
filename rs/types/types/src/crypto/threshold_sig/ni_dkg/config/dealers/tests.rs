use super::*;
use crate::PrincipalId;

const NODE_1: u64 = 1;
const NODE_2: u64 = 2;
const NODE_3: u64 = 3;

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

#[test]
fn should_not_create_empty_dealers() {
    let dealers = BTreeSet::new();
    let result = NiDkgDealers::new(dealers);

    assert_eq!(result, Err(NiDkgConfigValidationError::DealersEmpty));
}

#[test]
fn should_create_non_empty_dealers() {
    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(NODE_1));
    let result = NiDkgDealers::new(dealers);

    assert!(result.is_ok());
}

#[test]
fn should_return_correct_dealers() {
    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(NODE_1));
    let result = NiDkgDealers::new(dealers.clone());

    assert_eq!(result.unwrap().get(), &dealers);
}

#[test]
fn should_return_correct_dealers_iter() {
    let mut dealers = vec![node_id(NODE_1), node_id(NODE_2)];

    // The indices should correspond to the natural ordering of the elements:
    dealers.sort();
    let dealers_with_indices: BTreeSet<(NodeIndex, NodeId)> =
        (0..).zip(dealers.iter().copied()).collect();

    // The contents and indices should be correct regardless of the order of
    // insertion:
    for _ in 0..2 {
        dealers.reverse();
        let dealers_only: BTreeSet<NodeId> = dealers.iter().copied().collect();
        let result = NiDkgReceivers::new(dealers_only).unwrap();
        let dealers_returned_by_iter: BTreeSet<(NodeIndex, NodeId)> = result.iter().collect();
        assert_eq!(dealers_returned_by_iter, dealers_with_indices);
    }
}

#[test]
fn should_return_correct_dealers_count() {
    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(NODE_1));
    dealers.insert(node_id(NODE_2));
    let result = NiDkgDealers::new(dealers);

    assert_eq!(result.unwrap().count().get(), 2);
}

#[test]
fn should_return_correct_sorted_dealer_position() {
    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(NODE_3));
    dealers.insert(node_id(NODE_1));
    dealers.insert(node_id(NODE_2));
    let dealers = NiDkgDealers::new(dealers).unwrap();

    assert_eq!(dealers.position(node_id(NODE_1)).unwrap(), 0);
    assert_eq!(dealers.position(node_id(NODE_2)).unwrap(), 1);
    assert_eq!(dealers.position(node_id(NODE_3)).unwrap(), 2);
}

#[test]
fn should_return_none_position_if_node_id_not_in_dealers() {
    let not_a_dealer_node = node_id(NODE_3);
    let mut dealers = BTreeSet::new();
    dealers.insert(node_id(NODE_1));
    dealers.insert(node_id(NODE_2));
    let dealers = NiDkgDealers::new(dealers).unwrap();

    assert!(dealers.position(not_a_dealer_node).is_none());
}
