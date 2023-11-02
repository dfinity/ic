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

// Since the indexes_migration is Succeeded on mainnet, we set it to Succeeded in NeuronStore::new
// by default. However, we still have some tests relying on the state being not Succeeded, which we
// will clean up after switching to the stable storage indexes. For those tests, we use this
// function to test the cases where the migration has a different state than Succeeded. After
// switching to the stable storage indexes, any test calling this function should be deleted.
fn initialize_neuron_store_with_neurons_and_indexes_migration(
    neurons: BTreeMap<u64, Neuron>,
    indexes_migration: Migration,
) -> NeuronStore {
    // Initializes a
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Back up and restore neuron_store, but set the indexes_migration to what we want.
    let heap_neurons = neuron_store.take_heap_neurons();
    let heap_topic_followee_index = neuron_store.take_heap_topic_followee_index();
    let mut neuron_store =
        NeuronStore::new_restored(heap_neurons, heap_topic_followee_index, indexes_migration);

    for neuron in neurons.into_values() {
        neuron_store.add_neuron(neuron).unwrap();
    }

    neuron_store
}

// The following tests are not verifying the content of the stable indexes yet, as it's currently
// impossible to read from the indexes through its pub API. Those should be added when we start to
// allow reading from the stable indexes.
#[test]
fn test_batch_add_heap_neurons_to_stable_indexes_two_batches() {
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        btreemap! {
            1 => simple_neuron(1),
            3 => simple_neuron(3),
            7 => simple_neuron(7),
        },
        Migration::default(),
    );

    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 0 }, 2),
        Ok(Some(NeuronId { id: 3 }))
    );
    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 3 }, 2),
        Ok(None)
    );
}

#[test]
fn test_batch_add_heap_neurons_to_stable_indexes_three_batches_last_empty() {
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        btreemap! {
            1 => simple_neuron(1),
            3 => simple_neuron(3),
            7 => simple_neuron(7),
            12 => simple_neuron(12),
        },
        Migration::default(),
    );

    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 0 }, 2),
        Ok(Some(NeuronId { id: 3 }))
    );
    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 3 }, 2),
        Ok(Some(NeuronId { id: 12 }))
    );
    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 12 }, 2),
        Ok(None)
    );
}

#[test]
fn test_maybe_batch_add_heap_neurons_to_stable_indexes_succeed() {
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        (0..10).map(|i| (i, simple_neuron(i))).collect(),
        Migration::default(),
    );

    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        }
    );
}

#[test]
fn test_maybe_batch_add_heap_neurons_to_stable_indexes_already_succeeded() {
    // Step 1: initializes a neuron store with 10 neurons before indexes migration.
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        (0..10).map(|i| (i, simple_neuron(i))).collect(),
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        },
    );

    // Step 2: Tries to run the migration and asserts that the indexes migration status has not changed.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        }
    );
}

#[test]
fn test_maybe_batch_add_heap_neurons_to_stable_indexes_already_failed() {
    // Step 1: initializes a neuron store with 10 neurons before indexes migration.
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        (0..10).map(|i| (i, simple_neuron(i))).collect(),
        Migration {
            status: Some(MigrationStatus::Failed as i32),
            failure_reason: None,
            progress: None,
        },
    );

    // Step 2: Tries to run the migration and asserts that the indexes migration status has not changed.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::Failed as i32),
            failure_reason: None,
            progress: None,
        }
    );
}

#[test]
fn test_add_neuron_after_indexes_migration() {
    // Step 1: initializes a neuron store with one neurons before indexes migration.
    let mut neuron_store = NeuronStore::new(btreemap! {1 => simple_neuron(1)});

    // Step 2: adds a new neuron into neuron store.
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
fn test_add_neuron_during_indexes_migration_smaller_id() {
    // Step 1: prepare a neuron store with more than 1 batch of neurons with even number ids.
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        (1..=(NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 + 1))
            .map(|i| (i * 2, simple_neuron(i * 2)))
            .collect(),
        Migration::default(),
    );

    // Step 2: run one batch of migration and assert its result.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::InProgress as i32),
            failure_reason: None,
            progress: Some(Progress::LastNeuronId(NeuronId {
                id: NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 * 2
            })),
        }
    );

    // Step 3: insert a neuron whose id has been passed by the migration progress.
    let neuron = simple_neuron(3);
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 4: assert that the neuron can be looked up by subaccount index.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap())
            .unwrap()
    });
    assert_eq!(neuron_id_found_by_subaccount_index, neuron.id.unwrap());
}

#[test]
fn test_remove_neuron_after_indexes_migration() {
    let neuron = simple_neuron(1);
    // Step 1.1: initializes a neuron store with one neurons before indexes migration.
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => neuron.clone(),
    });

    // Step 1.2: restores the neuron store to a similar state where the migration has already succeeded.
    let heap_neurons = neuron_store.take_heap_neurons();
    let heap_topic_followee_index = neuron_store.take_heap_topic_followee_index();
    let mut neuron_store = NeuronStore::new_restored(
        heap_neurons,
        heap_topic_followee_index,
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        },
    );

    // Step 2: removes the neuron from neuron store.
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
fn test_modify_neuron_after_indexes_migration() {
    // Step 1.1: initializes the neuron store with one neuron.
    let neuron = Neuron {
        controller: Some(PrincipalId::new_user_test_id(1)),
        ..simple_neuron(1)
    };
    let mut neuron_store = NeuronStore::new(btreemap! {
        neuron.id.unwrap().id => neuron.clone(),
    });

    // Step 1.2: restores the neuron store to a similar state where the migration has already succeeded.
    let heap_neurons = neuron_store.take_heap_neurons();
    let heap_topic_followee_index = neuron_store.take_heap_topic_followee_index();
    let mut neuron_store = NeuronStore::new_restored(
        heap_neurons,
        heap_topic_followee_index,
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        },
    );

    // Step 2: modifies the controller of the neuron.
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
fn test_add_neuron_during_indexes_migration() {
    // Step 1: prepare a neuron store with more than 1 batch of neurons.
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        (1..=(NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 + 1))
            .map(|i| (i, simple_neuron(i)))
            .collect(),
        Migration::default(),
    );

    // Step 2: run one batch and assert that the migration isn't done yet.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::InProgress as i32),
            failure_reason: None,
            progress: Some(Progress::LastNeuronId(NeuronId {
                id: NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64
            })),
        }
    );

    // Step 3: insert a neuron beyond the migration progress.
    let neuron = simple_neuron(NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 + 2);
    neuron_store.add_neuron(neuron.clone()).unwrap();

    // Step 4: assert that the subaccount index has not picked up the neuron.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap())
    });
    assert_eq!(neuron_id_found_by_subaccount_index, None);

    // Step 5: let migration proceed and assert it succeeds.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        }
    );

    // Step 6: assert that the subaccount index has now picked up the neuron.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap())
    });
    assert_eq!(neuron_id_found_by_subaccount_index, neuron.id);
}

#[test]
fn test_remove_neuron_during_indexes_migration() {
    // Step 1: prepare a neuron store with more than 1 batch of neurons.
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        (1..=(NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 + 1))
            .map(|i| (i, simple_neuron(i)))
            .collect(),
        Migration::default(),
    );

    // Step 2: run one batch and assert that the migration isn't done yet.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::InProgress as i32),
            failure_reason: None,
            progress: Some(Progress::LastNeuronId(NeuronId {
                id: NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64
            })),
        }
    );

    // Step 3: remove a neuron beyond the migration progress.
    let neuron = simple_neuron(NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 + 1);
    neuron_store.remove_neuron(&neuron.id.unwrap());

    // Step 4: assert that the subaccount index does not have the removed neuron.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap())
    });
    assert_eq!(neuron_id_found_by_subaccount_index, None);

    // Step 5: let migration proceed and assert it succeeds.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        }
    );

    // Step 6: assert that the subaccount index still does not have the removed neuron.
    let neuron_id_found_by_subaccount_index = with_stable_neuron_indexes(|indexes| {
        indexes
            .subaccount()
            .get_neuron_id_by_subaccount(&neuron.subaccount().unwrap())
    });
    assert_eq!(neuron_id_found_by_subaccount_index, None);
}

#[test]
fn test_modify_neuron_during_indexes_migration() {
    // Step 1: prepare a neuron store with more than 1 batch of neurons.
    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        (1..=(NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 + 1))
            .map(|i| (i, simple_neuron(i)))
            .collect(),
        Migration::default(),
    );

    // Step 2: run one batch and assert that the migration isn't done yet.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::InProgress as i32),
            failure_reason: None,
            progress: Some(Progress::LastNeuronId(NeuronId {
                id: NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64
            })),
        }
    );

    // Step 3: modify a neuron beyond the migration progress.
    let neuron_id = NeuronId {
        id: NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 + 1,
    };
    let new_principal_id =
        PrincipalId::new_user_test_id(NEURON_INDEXES_MIGRATION_BATCH_SIZE as u64 * 2);
    neuron_store
        .with_neuron_mut(&neuron_id, |neuron| {
            neuron.controller = Some(new_principal_id);
        })
        .unwrap();

    // Step 4: assert that the principal index has not picked up the neuron.
    let neuron_id_found_by_principal_index =
        with_stable_neuron_indexes(|indexes| indexes.principal().get_neuron_ids(new_principal_id));
    assert_eq!(neuron_id_found_by_principal_index, hashset! {});

    // Step 5: let migration proceed and assert it succeeds.
    assert_eq!(
        neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes(),
        Migration {
            status: Some(MigrationStatus::Succeeded as i32),
            failure_reason: None,
            progress: None,
        }
    );

    // Step 6: assert that the principal index has now picked up the neuron.
    let neuron_id_found_by_principal_index =
        with_stable_neuron_indexes(|indexes| indexes.principal().get_neuron_ids(new_principal_id));
    assert_eq!(neuron_id_found_by_principal_index, hashset! {neuron_id.id});
}

#[test]
fn test_maybe_batch_add_heap_neurons_to_stable_indexes_failure() {
    let neuron_1 = simple_neuron(1);
    let neuron_2 = Neuron {
        account: neuron_1.account.clone(),
        ..simple_neuron(2)
    };

    let mut neuron_store = initialize_neuron_store_with_neurons_and_indexes_migration(
        btreemap! {
            1 => neuron_1,
            2 => neuron_2,
        },
        Migration::default(),
    );

    let migration = neuron_store.maybe_batch_add_heap_neurons_to_stable_indexes();
    assert_eq!(migration.status, Some(MigrationStatus::Failed as i32));
    let failure_reason = migration.failure_reason.unwrap();
    assert!(failure_reason.contains("Neuron indexes are corrupted"));
    assert!(failure_reason.contains("Subaccount"));
}

#[test]
fn test_batch_add_inactive_neurons_to_stable_memory() {
    // Step 1: Prepare the world.

    // Each element is (Neuron, is inactive).
    let batch = vec![
        (simple_neuron(1), false),
        (simple_neuron(3), true),
        (simple_neuron(7), false),
        (simple_neuron(12), true),
    ];

    // This isn't actually used, but we do this for realism.
    let id_to_neuron = BTreeMap::from_iter(batch.iter().map(|(neuron, _is_active)| {
        let neuron = neuron.clone();
        let id = neuron.id.as_ref().unwrap().id;

        (id, neuron)
    }));

    // No need to clear stable_neuron_store, because each #[test] is run in its own thread.

    // Step 2: Call the code under test.
    let mut neuron_store = NeuronStore::new(id_to_neuron);
    let batch_result = neuron_store.batch_add_inactive_neurons_to_stable_memory(batch);

    // Step 3: Verify.

    let last_neuron_id = NeuronId { id: 12 };
    assert_eq!(batch_result, Ok(Some(last_neuron_id)));

    fn read(neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
        with_stable_neuron_store(|stable_neuron_store| stable_neuron_store.read(neuron_id))
    }

    // Step 3.1: Assert that neurons 3 and 12 were copied, since they are inactive.
    for neuron_id in [3, 12] {
        let neuron_id = NeuronId { id: neuron_id };

        let read_result = read(neuron_id);

        match &read_result {
            Ok(ok) => assert_eq!(ok, &simple_neuron(neuron_id.id)),
            _ => panic!("{:?}", read_result),
        }
    }

    // Step 3.2: Assert that other neurons were NOT copied, since they are active.
    for neuron_id in 1..10 {
        // Skip inactive neuron IDs.
        if [3, 12].contains(&neuron_id) {
            continue;
        }

        let neuron_id = NeuronId { id: neuron_id };

        let read_result = read(neuron_id);

        match &read_result {
            Err(err) => {
                let GovernanceError {
                    error_type,
                    error_message,
                } = err;

                assert_eq!(
                    ErrorType::from_i32(*error_type),
                    Some(ErrorType::NotFound),
                    "{:?}",
                    err
                );

                let error_message = error_message.to_lowercase();
                assert!(error_message.contains("unable"), "{:?}", err);
                assert!(
                    error_message.contains(&format!("{}", neuron_id.id)),
                    "{:?}",
                    err
                );
            }

            _ => panic!("{:#?}", read_result),
        }
    }
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

    let principal_to_neuron_ids_index = HeapNeuronFollowingIndex::new(BTreeMap::new());

    let neuron_store =
        NeuronStore::new_restored(neurons, principal_to_neuron_ids_index, Migration::default());

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

    // Taking its migration state. Governance would have its most recent version because every time
    // it changes within NeuronStore it gets reported back to Governance, but we take it here. TODO:
    // this will be cleaned up very soon since we don't need this migration state after it's
    // finished.
    let indexes_migration = neuron_store.indexes_migration;

    // Restoring from those states.
    let restored_neuron_store =
        NeuronStore::new_restored(heap_neurons, heap_topic_followee_index, indexes_migration);

    for neuron in neurons.into_values() {
        assert_eq!(
            restored_neuron_store
                .with_neuron(&neuron.id.unwrap(), |neuron| neuron.clone())
                .unwrap(),
            neuron
        );
    }
}
