use super::*;

use crate::pb::v1::{neuron::Followees, KnownNeuronData};

use assert_matches::assert_matches;
use ic_nervous_system_governance::index::{
    neuron_following::NeuronFollowingIndex, neuron_principal::NeuronPrincipalIndex,
};
use ic_nns_common::pb::v1::NeuronId;
use lazy_static::lazy_static;
use maplit::{hashmap, hashset};

#[test]
fn add_remove_neuron() {
    // Step 1: prepare indexes and neurons.
    let mut indexes = new_heap_based();
    let neuron = Neuron {
        id: Some(NeuronId { id: 1 }),
        account: [1u8; 32].to_vec(),
        controller: Some(PrincipalId::new_user_test_id(1)),
        hot_keys: vec![
            PrincipalId::new_user_test_id(2),
            PrincipalId::new_user_test_id(3),
        ],
        followees: hashmap! {
            1 => Followees{
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 3 },
                    NeuronId { id: 4 },
                ],
            },
        },
        known_neuron_data: Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }),
        ..Default::default()
    };

    // Step 2: reading indexes return empty before adding neuron to them.
    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap()),
        None
    );
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1)),
        hashset! {}
    );
    assert_eq!(
        indexes
            .following()
            .get_followers_by_followee_and_category(&2, Signed32::from(1)),
        Vec::<u64>::default()
    );
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);

    // Step 3: adding a neuron.
    assert_eq!(indexes.add_neuron(&neuron), Ok(()));

    // Step 4: verify that reading indexes now return the added neuron.
    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap()),
        Some(NeuronId { id: 1 })
    );
    for principal_num in 1..=3 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(principal_num)),
            hashset! { 1 }
        );
    }
    for followee_id in 2..=4 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&followee_id, Signed32::from(1)),
            vec![1]
        );
    }
    assert_eq!(
        indexes.known_neuron().list_known_neuron_ids(),
        vec![NeuronId { id: 1 }]
    );

    // Step 5: remove the neuron.
    assert_eq!(indexes.remove_neuron(&neuron), Ok(()));

    // Step 6: verify that indexes are again empty.
    assert_eq!(
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap()),
        None
    );
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1)),
        hashset! {}
    );
    assert_eq!(
        indexes
            .following()
            .get_followers_by_followee_and_category(&2, Signed32::from(1)),
        Vec::<u64>::default()
    );
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);
}

lazy_static! {
    // Use MODEL_NEURON for tests where the exact member values are not needed for understanding the
    // test.
    static ref MODEL_NEURON: Neuron = Neuron {
        id: Some(NeuronId { id: 1 }),
        account: [1u8; 32].to_vec(),
        controller: Some(PrincipalId::new_user_test_id(1)),
        hot_keys: vec![
            PrincipalId::new_user_test_id(2),
            PrincipalId::new_user_test_id(3),
        ],
        followees: hashmap! {
            1 => Followees{
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 3 },
                    NeuronId { id: 4 },
                ],
            },
        },
        known_neuron_data: Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }),

        ..Default::default()
    };
}

#[test]
fn update_neuron_id_fails() {
    let mut indexes = new_heap_based();
    let neuron = Neuron {
        id: Some(NeuronId { id: 1 }),
        ..MODEL_NEURON.clone()
    };
    let neuron_with_different_id = Neuron {
        id: Some(NeuronId { id: 2 }),
        ..MODEL_NEURON.clone()
    };

    assert_matches!(indexes.update_neuron(&neuron, &neuron_with_different_id), 
        Err(NeuronStoreError::NeuronIdModified { old_neuron_id, new_neuron_id })
        if old_neuron_id.id == 1 && new_neuron_id.id == 2);
}

#[test]
fn update_neuron_account_fails() {
    let mut indexes = new_heap_based();
    let neuron = Neuron {
        account: [1u8; 32].to_vec(),
        ..MODEL_NEURON.clone()
    };
    let neuron_with_different_account = Neuron {
        account: [2u8; 32].to_vec(),
        ..MODEL_NEURON.clone()
    };

    assert_matches!(
        indexes.update_neuron(&neuron, &neuron_with_different_account), 
        Err(NeuronStoreError::SubaccountModified { old_subaccount, new_subaccount })
        if old_subaccount.0 == [1u8; 32] && new_subaccount.0 == [2u8; 32]);
}

#[test]
fn update_neuron_replace_controller() {
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(1)),
        hot_keys: vec![],
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(2)),
        hot_keys: vec![],
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap().id;
    // Before updating, the neuron can be looked up by the old controller but cannot be by the new
    // one.
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(old_neuron.controller.unwrap()),
        hashset! {neuron_id}
    );
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(new_neuron.controller.unwrap()),
        hashset! {}
    );

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // After updating the neuron cannot be looked up by the old controller, but the can be by the
    // new one.
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(old_neuron.controller.unwrap()),
        hashset! {}
    );
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(new_neuron.controller.unwrap()),
        hashset! {neuron_id}
    );
}

#[test]
fn update_neuron_add_hot_key() {
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(100)),
        hot_keys: vec![
            PrincipalId::new_user_test_id(101),
            PrincipalId::new_user_test_id(102),
        ],
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(100)),
        hot_keys: vec![
            PrincipalId::new_user_test_id(101),
            PrincipalId::new_user_test_id(102),
            PrincipalId::new_user_test_id(103),
        ],
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap().id;
    // Before updating, the neuron can be looked up by 101, 102 but not 103
    for i in 101..=102 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(i)),
            hashset! {neuron_id}
        );
    }
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(103)),
        hashset! {}
    );

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // After updating the neuron cannot be looked up by 101..=103
    for i in 101..=103 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(i)),
            hashset! {neuron_id}
        );
    }
}

#[test]
fn update_neuron_remove_hot_key() {
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(100)),
        hot_keys: vec![
            PrincipalId::new_user_test_id(101),
            PrincipalId::new_user_test_id(102),
        ],
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(100)),
        hot_keys: vec![PrincipalId::new_user_test_id(102)],
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap().id;
    // Before updating, the neuron can be looked up by 101, 102
    for i in 101..=102 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(i)),
            hashset! {neuron_id}
        );
    }

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // After updating the neuron only be looked up by 102
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(102)),
        hashset! {neuron_id}
    );
    assert_eq!(
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(101)),
        hashset! {}
    );
}

#[test]
fn update_neuron_remove_controller_as_hot_key() {
    // Unfortunately, we currently allow controller to be added as hot key, we need to make sure
    // that when we remove the hot key (that is the same as the controller), the neuron can still be
    // looked up by the controller through the index.
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(100)),
        hot_keys: vec![
            PrincipalId::new_user_test_id(100),
            PrincipalId::new_user_test_id(101),
        ],
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(100)),
        hot_keys: vec![PrincipalId::new_user_test_id(101)],
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap().id;
    // Before updating, the neuron can be looked up by 100, 101
    for i in 100..=101 {
        assert_eq!(
            indexes
                .principal()
                .get_neuron_ids(PrincipalId::new_user_test_id(i)),
            hashset! {neuron_id}
        );
    }

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
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        followees: hashmap! {
            1 => Followees{
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 3 },
                    NeuronId { id: 4 },
                ],
            },
            2 => Followees{
                followees: vec![
                    NeuronId { id: 5 },
                    NeuronId { id: 6 },
                ],
            },
        },
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        followees: hashmap! {
            1 => Followees{
                followees: vec![
                    NeuronId { id: 2 },
                    NeuronId { id: 3 },
                    NeuronId { id: 4 },
                ],
            },
            2 => Followees{
                followees: vec![
                    NeuronId { id: 7 },
                    NeuronId { id: 8 },
                ],
            },
        },
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap().id;
    // Before updating, the neuron can be looked up by 2, 3, 4 for topic 1.
    for i in 2..=4 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&i, Signed32::from(1)),
            vec![neuron_id],
        );
    }
    // Before updating, the neuron can be looked up by 5, 6 for topic 2.
    for i in 5..=6 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&i, Signed32::from(2)),
            vec![neuron_id],
        );
    }

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // After updating, the neuron can still be looked up by 2, 3, 4 for topic 1.
    for i in 2..=4 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&i, Signed32::from(1)),
            vec![neuron_id],
        );
    }
    // After updating, the neuron can no longer be looked up by 5, 6 for topic 2.
    for i in 5..=6 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&i, Signed32::from(2)),
            Vec::<u64>::new(),
        );
    }
    // After updating, the neuron can be looked up by 7, 8 for topic 2.
    for i in 7..=8 {
        assert_eq!(
            indexes
                .following()
                .get_followers_by_followee_and_category(&i, Signed32::from(2)),
            vec![neuron_id],
        );
    }
}

#[test]
fn update_neuron_add_known_neuron() {
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        known_neuron_data: None,
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        known_neuron_data: Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }),
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap();
    // No known neurons before update.
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Known neuron can be lookedp up after update.
    assert_eq!(
        indexes.known_neuron().list_known_neuron_ids(),
        vec![neuron_id]
    );
}

#[test]
fn update_neuron_remove_known_neuron() {
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        known_neuron_data: Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }),
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        known_neuron_data: None,
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap();
    // Known neuron can be looked up before update.
    assert_eq!(
        indexes.known_neuron().list_known_neuron_ids(),
        vec![neuron_id]
    );

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    // Known neuron can no longer be looked up after update.
    assert_eq!(indexes.known_neuron().list_known_neuron_ids(), vec![]);
}

#[test]
fn update_neuron_update_known_neuron_name() {
    let mut indexes = new_heap_based();
    let old_neuron = Neuron {
        known_neuron_data: Some(KnownNeuronData {
            name: "known neuron data".to_string(),
            description: None,
        }),
        ..MODEL_NEURON.clone()
    };
    assert_eq!(indexes.add_neuron(&old_neuron), Ok(()));
    let new_neuron = Neuron {
        known_neuron_data: Some(KnownNeuronData {
            name: "different known neuron data".to_string(),
            description: None,
        }),
        ..MODEL_NEURON.clone()
    };
    let neuron_id = MODEL_NEURON.id.unwrap();
    assert!(indexes
        .known_neuron()
        .contains_known_neuron_name("known neuron data"),);

    assert_eq!(indexes.update_neuron(&old_neuron, &new_neuron), Ok(()));

    assert!(!indexes
        .known_neuron()
        .contains_known_neuron_name("known neuron data"),);
    assert!(indexes
        .known_neuron()
        .contains_known_neuron_name("different known neuron data"),);
}
