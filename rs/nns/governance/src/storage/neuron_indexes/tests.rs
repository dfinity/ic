use super::*;
use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{neuron::Followees, KnownNeuronData},
};
use assert_matches::assert_matches;
use ic_nervous_system_governance::index::{
    neuron_following::NeuronFollowingIndex, neuron_principal::NeuronPrincipalIndex,
};
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::Subaccount;
use maplit::{hashmap, hashset};

#[test]
fn add_remove_neuron() {
    // Step 1: prepare indexes and neurons.
    let mut indexes = new_heap_based();

    let mut neuron = NeuronBuilder::new(
        NeuronId { id: 1 },
        Subaccount::try_from([1u8; 32].as_ref()).unwrap(),
        PrincipalId::new_user_test_id(1),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 1,
        },
        123_456_789,
    )
    .with_hot_keys(vec![
        PrincipalId::new_user_test_id(2),
        PrincipalId::new_user_test_id(3),
    ])
    .with_followees(hashmap! {
        1 => Followees {
            followees: vec![
                NeuronId { id: 2 },
                NeuronId { id: 3 },
                NeuronId { id: 4 },
            ],
        },
    })
    .build();

    neuron.known_neuron_data = Some(KnownNeuronData {
        name: "known neuron data".to_string(),
        description: None,
    });
    let account_id =
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(neuron.subaccount()));

    // Step 2: reading indexes return empty before adding neuron to them.
    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount()),
        None
    );
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1)),
        hashset! {}
    );
    assert_eq!(
        indexes.following().get_followers_by_followee_and_category(
            &NeuronId { id: 2 },
            Topic::try_from(1).unwrap()
        ),
        vec![]
    );
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);
    assert_eq!(
        indexes
            .account_id()
            .get_neuron_id_by_account_id(&account_id),
        None
    );

    // Step 3: adding a neuron.
    assert_eq!(indexes.add_neuron(&neuron), Ok(()));

    // Step 4: verify that reading indexes now return the added neuron.
    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount()),
        Some(NeuronId { id: 1 })
    );
    for principal_num in 1..=3 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(principal_num)),
            hashset! { NeuronId {id: 1} }
        );
    }
    for followee_id in 2..=4 {
        assert_eq!(
            indexes.following().get_followers_by_followee_and_category(
                &NeuronId { id: followee_id },
                Topic::try_from(1).unwrap()
            ),
            vec![NeuronId { id: 1 }]
        );
    }
    assert_eq!(
        indexes.known_neuron().list_known_neuron_ids(),
        vec![NeuronId { id: 1 }]
    );
    assert_eq!(
        indexes
            .account_id()
            .get_neuron_id_by_account_id(&account_id),
        Some(NeuronId { id: 1 })
    );

    // Step 5: remove the neuron.
    assert_eq!(indexes.remove_neuron(&neuron), Ok(()));

    // Step 6: verify that indexes are again empty.
    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount()),
        None
    );
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1)),
        hashset! {}
    );
    assert_eq!(
        indexes.following().get_followers_by_followee_and_category(
            &NeuronId { id: 2 },
            Topic::try_from(1).unwrap()
        ),
        vec![]
    );
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);
    assert_eq!(
        indexes
            .account_id()
            .get_neuron_id_by_account_id(&account_id),
        None
    );
}

fn create_model_neuron_builder(id: u64) -> NeuronBuilder {
    let account = vec![0; 32];

    NeuronBuilder::new(
        NeuronId { id },
        Subaccount::try_from(account.as_slice()).unwrap(),
        PrincipalId::new_user_test_id(id),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 1,
        },
        123_456_789,
    )
    .with_hot_keys(vec![
        PrincipalId::new_user_test_id(id + 1),
        PrincipalId::new_user_test_id(id + 2),
    ])
    .with_followees(hashmap! {
        1 => Followees {
            followees: vec![
                NeuronId { id: id + 1 },
                NeuronId { id: id + 2 },
                NeuronId { id: id + 3 },
            ],
        }
    })
    .with_known_neuron_data(Some(KnownNeuronData {
        name: format!("known neuron data {}", id),
        description: None,
    }))
}

#[test]
fn update_neuron_account_fails() {
    let mut indexes = new_heap_based();
    let neuron = create_model_neuron_builder(1)
        .with_subaccount(Subaccount::try_from([1u8; 32].as_ref()).unwrap())
        .build();
    let neuron_with_different_account = create_model_neuron_builder(1)
        .with_subaccount(Subaccount::try_from([2u8; 32].as_ref()).unwrap())
        .build();

    assert_matches!(
        indexes.update_neuron(&neuron, &neuron_with_different_account),
        Err(NeuronStoreError::SubaccountModified { old_subaccount, new_subaccount })
        if old_subaccount.0 == [1u8; 32] && new_subaccount.0 == [2u8; 32]);
}

#[test]
fn update_neuron_set_controller() {
    let mut indexes = new_heap_based();
    let old_neuron = create_model_neuron_builder(1).build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_controller = PrincipalId::new_user_test_id(1001);
    // Make sure the new controller is different from the old one and not one of the hot keys.
    assert_ne!(new_controller, old_neuron.controller());
    assert!(!old_neuron.hot_keys.contains(&new_controller));

    // Before updating, the neuron can be looked up by the old controller but cannot be by the new
    // one.
    let neuron_id = old_neuron.id();
    assert_eq!(
        indexes.principal().get_neuron_ids(old_neuron.controller()),
        hashset! { neuron_id }
    );
    assert_eq!(
        indexes.principal().get_neuron_ids(new_controller),
        hashset! {}
    );

    let mut new_neuron = old_neuron.clone();

    new_neuron.set_controller(PrincipalId::new_user_test_id(2));

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // After updating the neuron cannot be looked up by the old controller, but the can be by the
    // new one.
    assert_eq!(
        indexes.principal().get_neuron_ids(old_neuron.controller()),
        hashset! {}
    );
    assert_eq!(
        indexes.principal().get_neuron_ids(new_neuron.controller()),
        hashset! { neuron_id }
    );
}

#[test]
fn update_neuron_add_hot_key() {
    // Step 1: prepare a neuron and add it to the indexes.
    let mut indexes = new_heap_based();
    let old_neuron = create_model_neuron_builder(1).build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));

    // Step 2: make sure the new hot key is different from the old ones.
    let new_hot_key = PrincipalId::new_user_test_id(100);
    assert!(!old_neuron.hot_keys.contains(&new_hot_key));

    // Step 3: before updating, the neuron can be looked up by the old hot keys but not by the new.
    let neuron_id = old_neuron.id();
    assert!(!old_neuron.hot_keys.is_empty());
    for old_hot_key in old_neuron.hot_keys.iter() {
        assert_eq!(
            indexes.principal().get_neuron_ids(*old_hot_key),
            hashset! {neuron_id}
        );
    }
    assert_eq!(indexes.principal().get_neuron_ids(new_hot_key), hashset! {});

    // Step 4: make a new neuron and add the new hot key to it.
    let mut new_neuron = old_neuron.clone();
    new_neuron.hot_keys.push(new_hot_key);
    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Step 5: verify that both the old and new hot keys can be used to look up the neuron.
    for hot_key in new_neuron.hot_keys.iter() {
        assert_eq!(
            indexes.principal().get_neuron_ids(*hot_key),
            hashset! {neuron_id}
        );
    }
}

#[test]
fn update_neuron_remove_hot_key() {
    // Step 1: prepare a neuron and add it to the indexes.
    let mut indexes = new_heap_based();
    let old_neuron = create_model_neuron_builder(1).build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));

    // Step 2: before updating, the neuron can be looked up by the hot keys.
    let neuron_id = old_neuron.id();
    assert!(!old_neuron.hot_keys.is_empty());
    for hot_key in old_neuron.hot_keys.iter() {
        assert_eq!(
            indexes.principal().get_neuron_ids(*hot_key),
            hashset! {neuron_id}
        );
    }

    // Step 3: make a new neuron and remove one of the hot keys.
    let mut new_neuron = old_neuron.clone();
    let hot_key_to_remove = new_neuron.hot_keys.pop().unwrap();
    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Step 4: verify that the removed hot key can no longer be used to look up the neuron.
    assert_eq!(
        indexes.principal().get_neuron_ids(hot_key_to_remove),
        hashset! {}
    );

    // Step 5: verify that the remaining hot key can still be used to look up the neuron.
    for hot_key in new_neuron.hot_keys.iter() {
        assert_eq!(
            indexes.principal().get_neuron_ids(*hot_key),
            hashset! {neuron_id}
        );
    }
}

#[test]
fn update_neuron_remove_controller_as_hot_key() {
    // Unfortunately, we currently allow controller to be added as hot key, we need to make sure
    // that when we remove the hot key (that is the same as the controller), the neuron can still be
    // looked up by the controller through the index.

    // Step 1: prepare a neuron with its controller as one of the hot keys and add it to the
    // indexes.
    let mut indexes = new_heap_based();
    let old_neuron = NeuronBuilder::new(
        NeuronId { id: 1 },
        Subaccount::try_from([1u8; 32].as_ref()).unwrap(),
        PrincipalId::new_user_test_id(100),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 1,
        },
        123_456_789,
    )
    .with_hot_keys(vec![
        PrincipalId::new_user_test_id(100),
        PrincipalId::new_user_test_id(101),
    ])
    .build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));

    // Step 2: before updating, the neuron can be looked up by the controller and the hot keys.
    let neuron_id = old_neuron.id();
    for i in 100..=101 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(i)),
            hashset! {neuron_id}
        );
    }

    // Step 3: make a new neuron and remove the controller as a hot key.
    let mut new_neuron = old_neuron.clone();
    new_neuron.hot_keys = vec![PrincipalId::new_user_test_id(101)];
    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // After updating can still be looked up by both
    for i in 100..=101 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(i)),
            hashset! {neuron_id}
        );
    }
}

#[test]
fn update_neuron_set_followees() {
    // Step 1: prepare a neuron with followees and add it to the indexes.
    let mut indexes = new_heap_based();
    let old_neuron = create_model_neuron_builder(1)
        .with_followees(hashmap! {
            1 => Followees {
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 3 },
                    NeuronId { id: 4 },
                ],
            },
            2 => Followees {
                followees: vec![
                    NeuronId { id: 5 },
                    NeuronId { id: 6 },
                ],
            },
        })
        .build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));

    // Step 2: before updating, make sure the neuron can be looked up by the followees.
    let neuron_id = old_neuron.id();
    for i in 2..=4 {
        assert_eq!(
            indexes.following().get_followers_by_followee_and_category(
                &NeuronId { id: i },
                Topic::NeuronManagement
            ),
            vec![neuron_id],
        );
    }
    for i in 5..=6 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&NeuronId { id: i }, Topic::ExchangeRate),
            vec![neuron_id],
        );
    }

    // Step 3: make a new neuron with different followees for one of the topics and update the
    // neuron.
    let mut new_neuron = old_neuron.clone();

    new_neuron.followees = hashmap! {
        Topic::NeuronManagement as i32 => Followees{
            followees: vec![
                NeuronId { id: 2 },
                NeuronId { id: 3 },
                NeuronId { id: 4 },
            ],
        },
        Topic::ExchangeRate as i32 => Followees{
            followees: vec![
                NeuronId { id: 7 },
                NeuronId { id: 8 },
            ],
        },
    };
    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Step 4: after updating, verify the neuron can be looked up by the new followees.
    for i in 2..=4 {
        assert_eq!(
            indexes.following().get_followers_by_followee_and_category(
                &NeuronId { id: i },
                Topic::NeuronManagement
            ),
            vec![neuron_id],
        );
    }
    for i in 5..=6 {
        assert_eq!(
            indexes.following().get_followers_by_followee_and_category(
                &NeuronId { id: i },
                Topic::try_from(2).unwrap()
            ),
            vec![],
        );
    }
    // After updating, the neuron can be looked up by 7, 8 for topic 2.
    for i in 7..=8 {
        assert_eq!(
            indexes.following().get_followers_by_followee_and_category(
                &NeuronId { id: i },
                Topic::try_from(2).unwrap()
            ),
            vec![neuron_id],
        );
    }
}

#[test]
fn update_neuron_add_known_neuron() {
    // Step 1: prepare a neuron without known neuron data and add it to the indexes.
    let mut indexes = new_heap_based();
    let old_neuron = create_model_neuron_builder(1)
        .with_known_neuron_data(None)
        .build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));

    // Step 2: before updating, make sure the neuron cannot be listed as a known neuron.
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);

    // Step 3: make a new neuron with known neuron data and update the neuron.
    let mut new_neuron = old_neuron.clone();
    new_neuron.known_neuron_data = Some(KnownNeuronData {
        name: "known neuron data".to_string(),
        description: None,
    });
    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Step 4: known neuron can be looked up after update.
    assert_eq!(
        indexes.known_neuron().list_known_neuron_ids(),
        vec![new_neuron.id()]
    );
}

#[test]
fn update_neuron_remove_known_neuron() {
    // Step 1: prepare a neuron with known neuron data and add it to the indexes.
    let mut indexes = new_heap_based();
    let old_neuron = create_model_neuron_builder(1)
        .with_known_neuron_data(Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }))
        .build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));

    // Step 2: before updating, make sure the neuron can be listed as a known neuron.
    assert_eq!(
        indexes.known_neuron().list_known_neuron_ids(),
        vec![old_neuron.id()]
    );

    // Step 3: make a new neuron without known neuron data and update the neuron.
    let mut new_neuron = old_neuron.clone();
    new_neuron.known_neuron_data = None;
    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Step 4: known neuron can no longer be looked up after update.
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);
}

#[test]
fn update_neuron_update_known_neuron_name() {
    // Step 1: prepare a neuron with known neuron data and add it to the indexes.
    let mut indexes = new_heap_based();
    let old_neuron = create_model_neuron_builder(1)
        .with_known_neuron_data(Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }))
        .build();
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));

    // Step 2: before updating, make sure the neuron can be looked up by the known neuron name.
    assert!(indexes
        .known_neuron()
        .contains_known_neuron_name("known neuron data"));
    assert!(!indexes
        .known_neuron()
        .contains_known_neuron_name("different known neuron data"));

    // Step 3: make a new neuron with different known neuron name and update the neuron.
    let mut new_neuron = old_neuron.clone();
    new_neuron.known_neuron_data = Some(KnownNeuronData {
        name: "different known neuron data".to_string(),
        description: None,
    });
    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Step 4: the neuron can no longer be looked up by the old known neuron name, but can be by the
    // new one.
    assert!(!indexes
        .known_neuron()
        .contains_known_neuron_name("known neuron data"));
    assert!(indexes
        .known_neuron()
        .contains_known_neuron_name("different known neuron data"));
}
