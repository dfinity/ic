use super::*;
use maplit::{btreemap, btreeset};
use pretty_assertions::assert_eq;

fn nid(n: u8) -> NeuronId {
    NeuronId { id: vec![n] }
}

#[test]
fn test_get_duplicate_followee_groups() {
    // In the following test cases, the followee aliases do not actually matter, but we set them to
    // some realistic values to make the test cases more readable.
    let test_cases = [
        ("Trivial case.", btreeset! {}, btreemap! {}),
        (
            "Rudimentary case: can't have duplicates in a singleton collection.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
            },
            btreemap! {},
        ),
        (
            "Same topic, different neuron IDs.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: None },
            },
            btreemap! {},
        ),
        (
            "Different topics, same neuron ID.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(0), alias: None },
            },
            btreemap! {},
        ),
        (
            "Duplicate neuron ID under the same topic.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
            },
            btreemap! {
                Topic::DappCanisterManagement => btreemap! {
                    nid(0) => vec![
                        ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                        ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                    ],
                },
            },
        ),
        (
            "Multiple duplicates; function under test should be agnostic to the (shuffled) \
             followee order.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: Some("Bob".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: None },
            },
            btreemap! {
                Topic::DappCanisterManagement => btreemap! {
                    nid(0) => vec![
                        ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: None },
                        ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                    ],
                },
                Topic::CriticalDappOperations => btreemap! {
                    nid(1) => vec![
                        ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: None },
                        ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: Some("Bob".to_string()) },
                    ],
                },
            },
        ),
        (
            "Fixed the above configuration by making sure Alice's and Bob's neurons aren't \
             duplicate for the same topic.",
            btreeset! {
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(0), alias: Some("Alice".to_string()) },
                ValidatedFollowee { topic: Topic::DappCanisterManagement, neuron_id: nid(1), alias: Some("Bob".to_string()) },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(0), alias: None },
                ValidatedFollowee { topic: Topic::CriticalDappOperations, neuron_id: nid(1), alias: None },
            },
            btreemap! {},
        ),
    ];

    for (label, followees, expected) in test_cases {
        let observed = get_duplicate_followee_groups(&followees);
        assert_eq!(observed, expected, "{}", label);
    }
}
