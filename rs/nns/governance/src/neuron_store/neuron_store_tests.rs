use super::*;
use crate::{
    neuron::types::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::neuron::Followees,
    storage::with_stable_neuron_indexes,
};
use ic_nervous_system_common::SECONDS_PER_DAY;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use maplit::{btreemap, hashmap, hashset};
use num_traits::bounds::LowerBounded;

fn simple_neuron_builder(id: u64) -> NeuronBuilder {
    // Make sure different neurons have different accounts.
    let mut account = vec![0; 32];
    for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }

    NeuronBuilder::new(
        NeuronId { id },
        Subaccount::try_from(account.as_slice()).unwrap(),
        PrincipalId::new_user_test_id(id),
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 1,
            aging_since_timestamp_seconds: 0,
        },
        123_456_789,
    )
}

#[test]
fn test_neuron_add_modify_remove() {
    // Step 1: prepare a neuron and an empty neuron store.
    let neuron = simple_neuron_builder(1)
        .with_cached_neuron_stake_e8s(1)
        .build();
    let neuron_id = neuron.id();
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 2: verify that the neuron store is empty and does not contain the neuron.
    assert_eq!(neuron_store.len(), 0);
    assert!(!neuron_store.contains(neuron_id));

    // Step 3: add the neuron into the neuron store.
    assert_eq!(neuron_store.add_neuron(neuron.clone()), Ok(neuron_id));

    // Step 4: verify that the neuron can be read and the neuron store isn't empty anymore.
    assert_eq!(neuron_store.len(), 1);
    assert!(neuron_store.contains(neuron_id));
    let neuron_read_result = neuron_store.with_neuron(&neuron.id(), |neuron| neuron.clone());
    assert_eq!(neuron_read_result, Ok(neuron.clone()));

    // Step 5: modify the neuron.
    assert_eq!(
        neuron_store.with_neuron_mut(&neuron_id, |neuron| neuron.cached_neuron_stake_e8s = 2),
        Ok(())
    );

    // Step 6: verify that the neuron can still be read and the modification took place.
    assert_eq!(neuron_store.len(), 1);
    assert!(neuron_store.contains(neuron_id));
    let neuron_read_result = neuron_store.with_neuron(&neuron.id(), |neuron| neuron.clone());
    let mut expected_neuron = neuron.clone();
    expected_neuron.cached_neuron_stake_e8s = 2;
    assert_eq!(neuron_read_result, Ok(expected_neuron));

    // Step 7: remove the neuron.
    neuron_store.remove_neuron(&neuron_id);

    // Step 8: verify the neuron store is empty again and the neuron cannot be read anymore.
    assert_eq!(neuron_store.len(), 0);
    assert!(!neuron_store.contains(neuron_id));
    let neuron_read_result = neuron_store.with_neuron(&neuron.id(), |neuron| neuron.clone());
    assert_eq!(
        neuron_read_result,
        Err(NeuronStoreError::not_found(neuron_id))
    );
}

#[test]
fn test_add_neuron_update_indexes() {
    // Step 1: prepare the neuron and neuron store.
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron_builder(1).build(),
    });

    // Step 2: adds a new neuron into neuron store.
    let neuron_2 = simple_neuron_builder(2).build();
    neuron_store.add_neuron(neuron_2.clone()).unwrap();

    // Step 3: verifies that the indexes can be looked up for the new neuron.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron_2.subaccount())
            .unwrap()
    });
    assert_eq!(neuron_id_found_by_subaccount_index, neuron_2.id());

    let expected_account_id =
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(neuron_2.subaccount()));
    let neuron_id_found_by_account_id_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .account_id()
            .get_neuron_id_by_account_id(&expected_account_id)
            .unwrap()
    });
    assert_eq!(neuron_id_found_by_account_id_index, neuron_2.id());
}

#[test]
fn test_remove_neuron_update_indexes() {
    // Step 1: prepare the neuron and neuron store.
    let neuron = simple_neuron_builder(1).build();
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron.id().id => neuron.clone(),
    });

    // Step 2: removes the neuron from neuron store.
    neuron_store.remove_neuron(&neuron.id());

    // Step 3: verifies that the neuron has also been removed from the subaccount index.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount())
    });
    assert_eq!(neuron_id_found_by_subaccount_index, None);

    let expected_account_id =
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(neuron.subaccount()));
    let neuron_id_found_by_account_id_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .account_id()
            .get_neuron_id_by_account_id(&expected_account_id)
    });
    assert_eq!(neuron_id_found_by_account_id_index, None);
}

#[test]
fn test_modify_neuron_update_indexes() {
    // Step 1: prepare the neuron and neuron store.
    let neuron = simple_neuron_builder(1)
        .with_controller(PrincipalId::new_user_test_id(1))
        .build();
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron.id().id => neuron.clone(),
    });

    // Step 2: modifies the controller of the neuron.
    neuron_store
        .with_neuron_mut(&neuron.id(), |neuron| {
            neuron.set_controller(PrincipalId::new_user_test_id(2));
        })
        .unwrap();

    // Step 3: verifies that the neuron can be looked up by the neuron controller but not the old one.
    let neuron_ids_found_by_new_controller = with_stable_neuron_indexes(|indexes| {
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(2))
    });
    assert_eq!(neuron_ids_found_by_new_controller, hashset! {neuron.id()});
    let neuron_ids_found_by_old_controller = with_stable_neuron_indexes(|indexes| {
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1))
    });
    assert_eq!(neuron_ids_found_by_old_controller, hashset! {});
}

#[test]
fn test_heap_range_with_begin_and_limit() {
    let neuron_1 = simple_neuron_builder(1).build();
    let neuron_3 = simple_neuron_builder(3).build();
    let neuron_7 = simple_neuron_builder(7).build();
    let neuron_12 = simple_neuron_builder(12).build();

    let neuron_store = NeuronStore::new(btreemap! {
        1 => neuron_1,
        3 => neuron_3.clone(),
        7 => neuron_7.clone(),
        12 => neuron_12,
    });

    let observed_neurons: Vec<_> = neuron_store
        .range_heap_neurons(NeuronId { id: 3 }..)
        .take(2)
        .collect();

    assert_eq!(observed_neurons, vec![neuron_3, neuron_7],);
}

#[test]
fn test_add_inactive_neuron() {
    // Step 1.1: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 1.1: set up 1 active neuron and 1 inactive neuron.
    let now = neuron_store.now();
    let active_neuron = active_neuron_builder(1, now).build();
    let inactive_neuron = inactive_neuron_builder(2).build();

    // Step 2: add both neurons into neuron store.
    neuron_store.add_neuron(active_neuron.clone()).unwrap();
    neuron_store.add_neuron(inactive_neuron.clone()).unwrap();

    // Step 3.1: verify that the active neuron is not in the stable neuron store.
    let active_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(active_neuron.id())
    });
    match active_neuron_read_result {
        Ok(_) => panic!("Active neuron appeared in stable neuron store"),
        Err(error) => match error {
            NeuronStoreError::NeuronNotFound { neuron_id } => {
                assert_eq!(neuron_id, active_neuron.id());
            }
            _ => panic!("read returns error other than not found: {:?}", error),
        },
    }

    // Step 3.2: verify that inactive neuron can be read from stable neuron store and it's equal to
    // the one we added.
    let inactive_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(inactive_neuron.id())
    });
    assert_eq!(inactive_neuron_read_result, Ok(inactive_neuron.clone()));

    // Step 3.3: verify that the inactive neuron can also be read from neuron store.
    let inactive_neuron_in_neuron_store =
        neuron_store.with_neuron(&inactive_neuron.id(), |neuron| neuron.clone());
    assert_eq!(inactive_neuron_in_neuron_store, Ok(inactive_neuron.clone()));
}

#[test]
fn test_remove_inactive_neuron() {
    // Step 1.1: set up 1 active neuron and 1 inactive neuron.
    let inactive_neuron = inactive_neuron_builder(1).build();

    // Step 1.2: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 1.3: add the inactive neuron into neuron store and verifies it's in the stable neuron store.
    neuron_store.add_neuron(inactive_neuron.clone()).unwrap();
    let inactive_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(inactive_neuron.id())
    });
    assert_eq!(inactive_neuron_read_result, Ok(inactive_neuron.clone()));

    // Step 2: remove the neuron from neuron store.
    neuron_store.remove_neuron(&inactive_neuron.id());

    // Step 3: verify that inactive neuron cannot be read from stable neuron store anymore.
    let inactive_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(inactive_neuron.id())
    });
    match inactive_neuron_read_result {
        Ok(_) => panic!("Inactive neuron failed to be removed from stable neuron store"),
        Err(error) => match error {
            NeuronStoreError::NeuronNotFound { neuron_id } => {
                assert_eq!(neuron_id, inactive_neuron.id());
            }
            _ => panic!("read returns error other than not found: {:?}", error),
        },
    }
}

#[test]
fn test_neuron_store_new_then_restore() {
    // Step 1: create a NeuronStore for the first time with 10 neurons with following.
    let neurons: BTreeMap<_, _> = (0..10)
        .map(|i| {
            let neuron = simple_neuron_builder(i)
                .with_followees(hashmap! {
                    Topic::Governance as i32 => Followees {
                        followees: vec![NeuronId { id: 10 }],
                    }
                })
                .build();
            (i, neuron)
        })
        .collect();
    let neuron_store = NeuronStore::new(neurons.clone());

    // Step 2: verify the neurons and followee index are in the neuron store.
    for neuron in neurons.values() {
        assert_eq!(
            neuron_store
                .with_neuron(&neuron.id(), |neuron| neuron.clone())
                .unwrap(),
            neuron.clone()
        );
    }
    assert_eq!(
        neuron_store
            .get_followers_by_followee_and_topic(NeuronId { id: 10 }, Topic::Governance)
            .len(),
        10
    );

    // Step 3: take its state and restore from it.
    let (heap_neurons, heap_topic_followee_index) = neuron_store.take();
    let restored_neuron_store =
        NeuronStore::new_restored((heap_neurons, heap_topic_followee_index));

    // Step 4: verify again the neurons and followee index are in the restored neuron store.
    for neuron in neurons.values() {
        assert_eq!(
            restored_neuron_store
                .with_neuron(&neuron.id(), |neuron| neuron.clone())
                .unwrap(),
            neuron.clone()
        );
    }
    assert_eq!(
        restored_neuron_store
            .get_followers_by_followee_and_topic(NeuronId { id: 10 }, Topic::Governance)
            .len(),
        10
    );
}

#[test]
fn test_batch_validate_neurons_in_stable_store_are_inactive() {
    // Create a neuron store with 80 neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    for i in 1..=80 {
        // The dissolve state timestamp is chosen so that it meets the inactive neuron criteria.
        neuron_store
            .add_neuron(inactive_neuron_builder(i).build())
            .unwrap();
    }

    // Validate 8 batches with 10 each batch.
    let mut next_neuron_id = NeuronId::min_value();
    for _ in 0..8 {
        let (invalid_neuron_ids, neuron_id_for_next_batch) =
            neuron_store.batch_validate_neurons_in_stable_store_are_inactive(next_neuron_id, 10);

        // No invalid neuron ids should be found.
        assert_eq!(invalid_neuron_ids, vec![]);

        // There should always be the next neuron id.
        next_neuron_id = neuron_id_for_next_batch.unwrap();
    }

    // Validate one more time and there shouldn't be any validation done for this round.
    let (invalid_neuron_ids, neuron_id_for_next_batch) =
        neuron_store.batch_validate_neurons_in_stable_store_are_inactive(next_neuron_id, 10);
    assert_eq!(invalid_neuron_ids, vec![]);
    assert_eq!(neuron_id_for_next_batch, None);
}

#[test]
fn test_batch_validate_neurons_in_stable_store_are_inactive_invalid() {
    // Step 1.1: set up 1 inactive neuron.
    let neuron = inactive_neuron_builder(1).build();

    // Step 1.2: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 1.3: add the inactive neuron into neuron store.
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.4: modify the inactive in stable neuron store to make it actually active.
    let mut neuron_made_active = neuron.clone();
    neuron_made_active.cached_neuron_stake_e8s = 1;

    with_stable_neuron_store_mut(|stable_neuron_store| {
        stable_neuron_store
            .update(&neuron, neuron_made_active)
            .unwrap()
    });

    // Step 2: calls `batch_validate_neurons_in_stable_store_are_inactive` to validate.
    let (invalid_neuron_ids, _) =
        neuron_store.batch_validate_neurons_in_stable_store_are_inactive(NeuronId::min_value(), 10);

    // Step 3: verifies the results - the active neuron in stable storage should be found as invalid.
    assert_eq!(invalid_neuron_ids, vec![neuron.id()]);
}

// Below are tests related to how the neurons are stored, which look at the internals of the neuron
// store. They should probably be cleaned up after the inactive neuron migration since it's better
// to test through its public API.

fn active_neuron_builder(id: u64, now: u64) -> NeuronBuilder {
    simple_neuron_builder(id)
        .with_cached_neuron_stake_e8s(0)
        .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now,
        })
}

fn inactive_neuron_builder(id: u64) -> NeuronBuilder {
    simple_neuron_builder(id)
        .with_cached_neuron_stake_e8s(0)
        .with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 1,
        })
}

fn warp_time_to_make_neuron_inactive(neuron_store: &mut NeuronStore) {
    // Set enough time warp to make sure the active neuron becomes inactive.
    neuron_store.set_time_warp(TimeWarp {
        delta_s: 15 * SECONDS_PER_DAY as i64,
    });
}

fn is_neuron_in_heap(neuron_store: &NeuronStore, neuron_id: NeuronId) -> bool {
    neuron_store.heap_neurons.contains_key(&neuron_id.id)
}

fn is_neuron_in_stable(neuron_id: NeuronId) -> bool {
    with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.contains(neuron_id))
}

fn assert_neuron_in_neuron_store_eq(neuron_store: &NeuronStore, neuron: &Neuron) {
    assert_eq!(
        neuron_store
            .with_neuron(&neuron.id(), |neuron| neuron.clone())
            .unwrap(),
        *neuron
    );
}

#[test]
fn test_from_active_to_active() {
    // Step 1.1: set up an empty neuron store with an active neuron.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = active_neuron_builder(1, neuron_store.now()).build();
    let neuron_id = neuron.id();
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.2: verifies that the neuron is only in heap
    assert_neuron_in_neuron_store_eq(&neuron_store, &neuron);
    assert!(is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(!is_neuron_in_stable(neuron_id));

    // Step 2: modifies the neuron to be still active.
    let mut modified_neuron = neuron.clone();
    modified_neuron.cached_neuron_stake_e8s = 2;
    neuron_store
        .with_neuron_mut(&neuron_id, |neuron| *neuron = modified_neuron.clone())
        .unwrap();

    // Step 3: verifies that the neuron is still only in heap.
    assert_neuron_in_neuron_store_eq(&neuron_store, &modified_neuron);
    assert!(is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(!is_neuron_in_stable(neuron_id));
}

#[test]
fn test_from_active_to_inactive() {
    // Step 1.1: set up an empty neuron store with an active neuron which would be inactive if there
    // is no fund.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let mut neuron = inactive_neuron_builder(1).build();
    neuron.cached_neuron_stake_e8s = 1;
    let neuron_id = neuron.id();
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.2: verifies that the neuron is only in heap
    assert_neuron_in_neuron_store_eq(&neuron_store, &neuron);
    assert!(is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(!is_neuron_in_stable(neuron_id));

    // Step 2: modifies the neuron to be inactive by removing its stake
    let mut modified_neuron = neuron.clone();
    modified_neuron.cached_neuron_stake_e8s = 0;
    neuron_store
        .with_neuron_mut(&neuron_id, |neuron| *neuron = modified_neuron.clone())
        .unwrap();

    // Step 3: verifies that the neuron is only in stable.
    assert_neuron_in_neuron_store_eq(&neuron_store, &modified_neuron);
    assert!(!is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(is_neuron_in_stable(neuron_id));
}

#[test]
fn test_from_inactive_to_active() {
    // Step 1.1: set up an empty neuron store with an inactive neuron.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = inactive_neuron_builder(1).build();
    let neuron_id = neuron.id();
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.2: verifies that the neuron is in both stable and heap.
    assert_neuron_in_neuron_store_eq(&neuron_store, &neuron);
    // Whether the inactive neuron can be found in heap depends on whether we want to store inactive neurons
    // only in stable memory.
    assert!(!is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(is_neuron_in_stable(neuron_id));

    // Step 2: modifies the neuron to be active by funding it.
    let mut modified_neuron = neuron.clone();
    modified_neuron.cached_neuron_stake_e8s = 1;
    neuron_store
        .with_neuron_mut(&neuron_id, |neuron| *neuron = modified_neuron.clone())
        .unwrap();

    // Step 3: verifies that the neuron is only in heap.
    assert_neuron_in_neuron_store_eq(&neuron_store, &modified_neuron);
    assert!(is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(!is_neuron_in_stable(neuron_id));
}

#[test]
fn test_from_inactive_to_inactive() {
    // Step 1.1: set up an empty neuron store with an inactive neuron.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = inactive_neuron_builder(1).build();
    let neuron_id = neuron.id();
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.2: verifies that the neuron is in both stable and heap.
    assert_neuron_in_neuron_store_eq(&neuron_store, &neuron);
    // Whether the inactive neuron can be found in heap depends on whether we want to store inactive neurons
    // only in stable memory.
    assert!(!is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(is_neuron_in_stable(neuron_id));

    // Step 2: modifies the neuron to be still inactive.
    let mut modified_neuron = neuron.clone();
    modified_neuron.auto_stake_maturity = Some(true);
    neuron_store
        .with_neuron_mut(&neuron_id, |neuron| *neuron = modified_neuron.clone())
        .unwrap();

    // Step 3: verifies that the neuron is modified and is only in stable.
    assert_neuron_in_neuron_store_eq(&neuron_store, &modified_neuron);
    assert!(!is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(is_neuron_in_stable(neuron_id));
}

#[test]
fn test_from_stale_inactive_to_inactive() {
    // Step 1.1: set up an empty neuron store with an active neuron.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = active_neuron_builder(1, neuron_store.now()).build();
    let neuron_id = neuron.id();
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.2: verifies that the neuron is only in heap.
    assert_neuron_in_neuron_store_eq(&neuron_store, &neuron);
    assert!(is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(!is_neuron_in_stable(neuron_id));

    // Step 1.3: warp time so that the neuron becomes inactive without modification.
    warp_time_to_make_neuron_inactive(&mut neuron_store);

    // Step 2: call with_neuron_mut without modification.
    neuron_store.with_neuron_mut(&neuron_id, |_| {}).unwrap();

    // Step 3: verifies that the neuron is not modified but now only in stable.
    assert_neuron_in_neuron_store_eq(&neuron_store, &neuron);
    assert!(!is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(is_neuron_in_stable(neuron_id));
}

#[test]
fn test_from_stale_inactive_to_active() {
    // Step 1.1: set up an empty neuron store with an active neuron.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    let neuron = active_neuron_builder(1, neuron_store.now()).build();
    let neuron_id = neuron.id();
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.2: verifies that the neuron is only in heap.
    assert_neuron_in_neuron_store_eq(&neuron_store, &neuron);
    assert!(is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(!is_neuron_in_stable(neuron_id));

    // Step 1.3: warp time so that the neuron becomes inactive without modification.
    warp_time_to_make_neuron_inactive(&mut neuron_store);

    // Step 2: modify the neuron to be active again
    let mut modified_neuron = neuron.clone();
    modified_neuron.cached_neuron_stake_e8s = 1;
    neuron_store
        .with_neuron_mut(&neuron_id, |neuron| *neuron = modified_neuron.clone())
        .unwrap();

    // Step 3: verifies that the neuron is modified and still only on heap.
    assert_neuron_in_neuron_store_eq(&neuron_store, &modified_neuron);
    assert!(is_neuron_in_heap(&neuron_store, neuron_id));
    assert!(!is_neuron_in_stable(neuron_id));
}

#[test]
fn test_get_followers_by_followee_and_topic() {
    let neuron = simple_neuron_builder(1)
        .with_followees(hashmap! {
            Topic::Unspecified as i32 => Followees {
                followees: vec![NeuronId { id: 2 }, NeuronId { id: 3 }],
            }
        })
        .build();
    let neuron_store = NeuronStore::new(btreemap! {
        1 => neuron,
    });
    assert_eq!(
        neuron_store.get_followers_by_followee_and_topic(NeuronId { id: 2 }, Topic::Unspecified),
        vec![NeuronId { id: 1 }]
    );
    assert_eq!(
        neuron_store.get_followers_by_followee_and_topic(NeuronId { id: 2 }, Topic::Governance),
        vec![]
    );
}

#[test]
fn test_get_neuron_ids_readable_by_caller() {
    let neuron = simple_neuron_builder(1)
        .with_controller(PrincipalId::new_user_test_id(1))
        .with_hot_keys(vec![
            PrincipalId::new_user_test_id(2),
            PrincipalId::new_user_test_id(3),
        ])
        .build();
    let neuron_store = NeuronStore::new(btreemap! {
        1 => neuron,
    });
    for i in 1..=3 {
        assert_eq!(
            neuron_store.get_neuron_ids_readable_by_caller(PrincipalId::new_user_test_id(i)),
            hashset! { NeuronId { id: 1 } }
        );
    }
    assert_eq!(
        neuron_store.get_neuron_ids_readable_by_caller(PrincipalId::new_user_test_id(4)),
        hashset! {}
    );
}
