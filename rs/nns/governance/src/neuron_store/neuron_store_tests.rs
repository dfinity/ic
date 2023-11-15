use super::*;
use crate::{
    governance::{Governance, MockEnvironment},
    pb::v1::{
        neuron::{DissolveState, Followees},
        Governance as GovernanceProto,
    },
    storage::with_stable_neuron_indexes,
};
use ic_nervous_system_common::{cmc::MockCMC, ledger::MockIcpLedger};
use maplit::{btreemap, hashmap, hashset};
use num_traits::bounds::LowerBounded;
use std::time::{SystemTime, UNIX_EPOCH};

fn simple_neuron(id: u64) -> Neuron {
    // Make sure different neurons have different accounts.
    let mut account = vec![0; 32];
    for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }

    Neuron {
        id: Some(NeuronId { id }),
        account,
        controller: Some(PrincipalId::new_user_test_id(id)),
        ..Default::default()
    }
}

#[test]
fn test_add_neuron_update_indexes() {
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
    });

    // Step 3: adds a new neuron into neuron store.
    let neuron_2 = simple_neuron(2);
    neuron_store.add_neuron(neuron_2.clone()).unwrap();

    // Step 3: verifies that the indexes can be looked up for the new neuron.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron_2.subaccount().unwrap())
            .unwrap()
    });
    assert_eq!(neuron_id_found_by_subaccount_index, neuron_2.id.unwrap());
}

#[test]
fn test_remove_neuron_update_indexes() {
    let neuron = simple_neuron(1);
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron.id.unwrap().id => neuron.clone(),
    });

    // Step 3: removes the neuron from neuron store.
    neuron_store.remove_neuron(&neuron.id.unwrap());

    // Step 3: verifies that the neuron has also been removed from the subaccount index.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap())
    });
    assert_eq!(neuron_id_found_by_subaccount_index, None);
}

#[test]
fn test_modify_neuron_update_indexes() {
    let neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(1)),
        ..simple_neuron(1)
    };
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron.id.unwrap().id => neuron.clone(),
    });

    // Step 3: modifies the controller of the neuron.
    neuron_store
        .with_neuron_mut(&neuron.id.unwrap(), |neuron| {
            neuron.controller = Some(PrincipalId::new_user_test_id(2));
        })
        .unwrap();

    // Step 3: verifies that the neuron can be looked up by the neuron controller but not the old one.
    let neuron_ids_found_by_new_controller = with_stable_neuron_indexes(|indexes| {
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(2))
    });
    assert_eq!(
        neuron_ids_found_by_new_controller,
        hashset! {neuron.id.unwrap().id}
    );
    let neuron_ids_found_by_old_controller = with_stable_neuron_indexes(|indexes| {
        indexes
            .principal()
            .get_neuron_ids(PrincipalId::new_user_test_id(1))
    });
    assert_eq!(neuron_ids_found_by_old_controller, hashset! {});
}

#[test]
fn test_heap_range_with_begin_and_limit() {
    let neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
        3 => simple_neuron(3),
        7 => simple_neuron(7),
        12 => simple_neuron(12),
    });

    let observed_neurons: Vec<_> = neuron_store
        .range_heap_neurons(NeuronId { id: 3 }..)
        .take(2)
        .collect();

    assert_eq!(observed_neurons, vec![simple_neuron(3), simple_neuron(7)],);
}

#[test]
fn test_add_inactive_neuron() {
    // Step 1.1: set up 1 active neuron and 1 inactive neuron.
    let active_neuron = Neuron {
        cached_neuron_stake_e8s: 1,
        ..simple_neuron(1)
    };
    let inactive_neuron = Neuron {
        cached_neuron_stake_e8s: 0,
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(1)),
        ..simple_neuron(2)
    };

    // Step 1.2: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 2: add both neurons into neuron store.
    neuron_store.add_neuron(active_neuron.clone()).unwrap();
    neuron_store.add_neuron(inactive_neuron.clone()).unwrap();

    // Step 3.1: verify that the active neuron is not in the stable neuron store.
    let active_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(active_neuron.id.unwrap())
    });
    match active_neuron_read_result {
        Ok(_) => panic!("Active neuron appeared in stable neuron store"),
        Err(error) => {
            let GovernanceError {
                error_type,
                error_message,
            } = &error;

            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:#?}", error);

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable"), "{:#?}", error);
            assert!(error_message.contains("find"), "{:#?}", error);
        }
    }

    // Step 3.2: verify that inactive neuron can be read from stable neuron store and it's equal to
    // the one we added.
    let inactive_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(inactive_neuron.id.unwrap())
    });
    assert_eq!(inactive_neuron_read_result, Ok(inactive_neuron.clone()));

    // Step 3.3: verify that the inactive neuron can also be read from neuron store.
    let inactive_neuron_in_neuron_store =
        neuron_store.with_neuron(&inactive_neuron.id.unwrap(), |neuron| neuron.clone());
    assert_eq!(inactive_neuron_in_neuron_store, Ok(inactive_neuron.clone()));
}

#[test]
fn test_remove_inactive_neuron() {
    // Step 1.1: set up 1 active neuron and 1 inactive neuron.
    let inactive_neuron = Neuron {
        cached_neuron_stake_e8s: 0,
        // We require a neuron to have at least 6 months dissolve delay, in order to be inactive.
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(1)),
        ..simple_neuron(2)
    };

    // Step 1.2: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 1.3: add the inactive neuron into neuron store and verifies it's in the stable neuron store.
    neuron_store.add_neuron(inactive_neuron.clone()).unwrap();
    let inactive_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(inactive_neuron.id.unwrap())
    });
    assert_eq!(inactive_neuron_read_result, Ok(inactive_neuron.clone()));

    // Step 2: remove the neuron from neuron store.
    neuron_store.remove_neuron(&inactive_neuron.id.unwrap());

    // Step 3: verify that inactive neuron cannot be read from stable neuron store anymore.
    let inactive_neuron_read_result = with_stable_neuron_store(|stable_neuron_store| {
        stable_neuron_store.read(inactive_neuron.id.unwrap())
    });
    match inactive_neuron_read_result {
        Ok(_) => panic!("Inactive neuron failed to be removed from stable neuron store"),
        Err(error) => {
            let GovernanceError {
                error_type,
                error_message,
            } = &error;

            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:#?}", error);

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable"), "{:#?}", error);
            assert!(error_message.contains("find"), "{:#?}", error);
        }
    }
}

#[test]
fn test_with_neuron_mut_inactive_neuron() {
    // Step 1: Prepare the world.
    let now = u64::MAX;

    // Step 1.1: The main characters: a couple of Neurons, one active, the other inactive.
    let funded_neuron = Neuron {
        id: Some(NeuronId { id: 42 }),
        cached_neuron_stake_e8s: 1, // Funded. Thus, no stable memory.

        // This is in the "(sufficiently) distant past" to not be ruled out from being "inactive".
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(42)),

        ..Default::default()
    };
    let funded_neuron_id = funded_neuron.id.unwrap();

    let unfunded_neuron = Neuron {
        id: Some(NeuronId { id: 777 }),
        cached_neuron_stake_e8s: 0, // Unfunded. Thus, should be copied to stable memory.

        // This is in the "(sufficiently) distant past" to not be ruled out from being "inactive".
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(42)),

        ..Default::default()
    };
    let unfunded_neuron_id = unfunded_neuron.id.unwrap();

    // Make sure our test data is correct. Here, we use dummy values for proposals and
    // in_flight_commands.
    assert!(unfunded_neuron.is_inactive(now), "{:#?}", unfunded_neuron);
    assert!(!funded_neuron.is_inactive(now), "{:#?}", funded_neuron);

    // Step 1.2: Construct collaborators of Governance, and Governance itself.
    let mut governance = {
        let governance_proto = GovernanceProto {
            neurons: btreemap! {
                funded_neuron_id.id => funded_neuron.clone(),
                unfunded_neuron_id.id => unfunded_neuron.clone(),
            },
            ..Default::default()
        };

        // Governance::new calls environment.now. This just part of "preparing the world", not the
        // code under test itself. Nevertheless, we have to tell the `mockall` crate about this;
        // otherwise it will freak out.
        let mut environment = MockEnvironment::new();
        let now_timestamp_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        environment.expect_now().return_const(now_timestamp_seconds);

        Governance::new(
            governance_proto,
            Box::new(environment),
            Box::new(MockIcpLedger::new()),
            Box::new(MockCMC::new()),
        )
    };

    // Step 2: Call the code under test (twice).
    let results = [funded_neuron_id, unfunded_neuron_id].map(|neuron_id| {
        governance.with_neuron_mut(&neuron_id, |neuron: &mut Neuron| {
            // Modify the neuron a little bit.
            neuron.account = vec![1, 2, 3];

            // Don't just return () so that the return value has something
            // (such as it is) to inspect.
            ("ok", neuron_id)
        })
    });

    // Step 3: Verify result(s).
    assert_eq!(results.len(), 2, "{:#?}", results); // A sanity check.
    for result in results {
        let neuron_id = result.as_ref().map(|(_ok, neuron_id)| *neuron_id).unwrap();
        assert_eq!(result, Ok(("ok", neuron_id)));
    }

    // Step 3.1: The main thing that we want to see is that the unfunded Neuron ends up in stable
    // memory (and has the modification).
    assert_eq!(
        with_stable_neuron_store(|stable_neuron_store| {
            stable_neuron_store.read(unfunded_neuron_id)
        }),
        Ok(Neuron {
            account: vec![1, 2, 3],
            ..unfunded_neuron
        }),
    );

    // Step 3.2: Negative result: funded neuron should not be copied to stable memory. Perhaps, less
    // interesting, but also important is that some neurons (to wit, the funded Neuron) do NOT get
    // copied to stable memory.
    let funded_neuron_read_result =
        with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.read(funded_neuron_id));
    match &funded_neuron_read_result {
        Ok(_ok) => {
            panic!(
                "Seems that the funded neuron was copied to stable memory. Result:\n{:#?}",
                funded_neuron_read_result,
            );
        }

        Err(err) => {
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:#?}", err);

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable"), "{:#?}", err);
            assert!(error_message.contains("find"), "{:#?}", err);
            assert!(
                error_message.contains(&format!("{}", funded_neuron_id.id)),
                "{:#?}",
                err
            );
        }
    }
}

#[test]
fn test_neuron_store_builds_index_unless_provided() {
    let mut neuron3 = simple_neuron(3);
    neuron3.followees = hashmap! {
        2 => Followees {
            followees: vec![NeuronId { id: 1 }],
        },
        3 => Followees {
            followees: vec![NeuronId { id: 2 }],
        }
    };
    let mut neuron1 = simple_neuron(1);
    neuron1.followees = hashmap! {
        2 => Followees {
            followees: vec![NeuronId { id: 1 }],
        },
        3 => Followees {
            followees: vec![NeuronId { id: 2 }],
        }
    };
    let neurons = btreemap! {
        1 => neuron1,
        3 => neuron3,
        7 => simple_neuron(7),
        12 => simple_neuron(12),
    };
    let neuron_store = NeuronStore::new(neurons.clone());
    assert_eq!(neuron_store.topic_followee_index.num_entries(), 4);
    assert_eq!(
        neuron_store
            .get_followers_by_followee_and_topic(NeuronId { id: 2 }, Topic::from_i32(3).unwrap())
            .into_iter()
            .collect::<HashSet<_>>(),
        hashset! {NeuronId { id: 3 }, NeuronId { id: 1 }}
    );

    let empty_topic_followee_index = HeapNeuronFollowingIndex::new(BTreeMap::new());
    let neuron_store = NeuronStore::new_restored(neurons, empty_topic_followee_index);

    assert_eq!(neuron_store.topic_followee_index.num_entries(), 0);
    assert_eq!(
        neuron_store
            .get_followers_by_followee_and_topic(NeuronId { id: 2 }, Topic::from_i32(3).unwrap()),
        vec![]
    );
}

#[test]
fn test_neuron_store_new_then_restore() {
    // Creating a NeuronStore for the first time.
    let neurons: BTreeMap<_, _> = (0..10).map(|i| (i, simple_neuron(i))).collect();
    let mut neuron_store = NeuronStore::new(neurons.clone());

    // Taking its states (simulating how it's called by Governance).
    let heap_neurons = neuron_store.take_heap_neurons();
    let heap_topic_followee_index = neuron_store.take_heap_topic_followee_index();

    // Restoring from those states.
    let restored_neuron_store = NeuronStore::new_restored(heap_neurons, heap_topic_followee_index);

    for neuron in neurons.into_values() {
        assert_eq!(
            restored_neuron_store
                .with_neuron(&neuron.id.unwrap(), |neuron| neuron.clone())
                .unwrap(),
            neuron
        );
    }
}

#[test]
fn test_batch_validate_neurons_in_stable_store_are_inactive() {
    // Create a neuron store with 80 neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());
    for i in 1..=80 {
        // The dissolve state timestamp is chosen so that it meets the inactive neuron criteria.
        neuron_store
            .add_neuron(Neuron {
                cached_neuron_stake_e8s: 0,
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(1)),
                ..simple_neuron(i)
            })
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
    let neuron = Neuron {
        cached_neuron_stake_e8s: 0,
        dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(1)),
        ..simple_neuron(1)
    };

    // Step 1.2: create neuron store with no neurons.
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Step 1.3: add the inactive neuron into neuron store.
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 1.4: modify the inactive in stable neuron store to make it actually active.
    with_stable_neuron_store_mut(|stable_neuron_store| {
        stable_neuron_store
            .update(Neuron {
                cached_neuron_stake_e8s: 1,
                ..neuron
            })
            .unwrap()
    });

    // Step 2: calls `batch_validate_neurons_in_stable_store_are_inactive` to validate.
    let (invalid_neuron_ids, _) =
        neuron_store.batch_validate_neurons_in_stable_store_are_inactive(NeuronId::min_value(), 10);

    // Step 3: verifies the results - the active neuron in stable storage should be found as invalid.
    assert_eq!(invalid_neuron_ids, vec![neuron.id.unwrap()]);
}
