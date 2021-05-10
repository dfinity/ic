#![allow(clippy::unwrap_used)]

use super::*;
use crate::sign::threshold_sig::dkg::test_utils::{
    csp_pk_pop_dealing, csp_pk_pop_dealing_2, dealings_with, enc_pk_with_pop, keys_with,
};
use ic_test_utilities::types::ids::{NODE_1, NODE_3, NODE_4};

#[test]
fn should_map_single_dealing_correctly() {
    let (pk, pop, dealing) = csp_pk_pop_dealing();
    let keys = keys_with(NODE_3, pk, pop);
    let dealings = dealings_with(NODE_3, Dealing::from(&dealing));

    let verified_csp_dealings = mapper().convert(&keys, &dealings).unwrap();

    assert_eq!(verified_csp_dealings, vec![((pk, pop), dealing)]);
}

#[test]
fn should_map_multiple_dealings_correctly() {
    let (node1_pk, node1_pop, node1_dealing) = csp_pk_pop_dealing();
    let (node4_pk, node4_pop, node4_dealing) = csp_pk_pop_dealing_2();

    let mut keys = BTreeMap::new();
    keys.insert(NODE_1, enc_pk_with_pop(node1_pk, node1_pop));
    keys.insert(NODE_4, enc_pk_with_pop(node4_pk, node4_pop));
    let mut dealings = BTreeMap::new();
    dealings.insert(NODE_1, Dealing::from(&node1_dealing));
    dealings.insert(NODE_4, Dealing::from(&node4_dealing));

    let csp_dealings = mapper().convert(&keys, &dealings).unwrap();

    assert_eq!(
        csp_dealings,
        vec![
            ((node1_pk, node1_pop), node1_dealing),
            ((node4_pk, node4_pop), node4_dealing),
        ]
    );
}

#[test]
fn should_return_error_if_dealings_empty() {
    let (pk, pop, _) = csp_pk_pop_dealing();
    let keys = keys_with(NODE_3, pk, pop);
    let dealings = BTreeMap::new();

    let result = mapper().convert(&keys, &dealings);

    assert_eq!(
        result.unwrap_err(),
        DealingsToCspDealingsError::DealingsEmpty {}
    );
}

#[test]
fn should_return_error_if_keys_empty() {
    let (_, _, dealing) = csp_pk_pop_dealing();
    let keys = BTreeMap::new();
    let dealings = dealings_with(NODE_3, Dealing::from(&dealing));

    let result = mapper().convert(&keys, &dealings);

    assert_eq!(
        result.unwrap_err(),
        DealingsToCspDealingsError::KeysEmpty {}
    );
}

#[test]
fn should_return_error_if_key_for_dealing_not_found() {
    let (_, _, node1_dealing) = csp_pk_pop_dealing();
    let (node4_pk, node4_pop, node4_dealing) = csp_pk_pop_dealing_2();
    let keys_without_node_1_key = keys_with(NODE_4, node4_pk, node4_pop);
    let mut dealings = BTreeMap::new();
    dealings.insert(NODE_1, Dealing::from(&node1_dealing));
    dealings.insert(NODE_4, Dealing::from(&node4_dealing));

    let result = mapper().convert(&keys_without_node_1_key, &dealings);

    assert_eq!(
        result.unwrap_err(),
        DealingsToCspDealingsError::KeyForDealerNotFound {
            dealer_node_id: NODE_1
        }
    );
}

fn mapper() -> DealingsToCspDealingsImpl {
    DealingsToCspDealingsImpl {}
}
