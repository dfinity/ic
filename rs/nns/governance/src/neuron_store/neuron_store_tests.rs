use super::*;

use maplit::btreemap;

fn simple_neuron(id: u64) -> Neuron {
    // Make sure different neurons have different accounts.
    let mut account = vec![0; 32];
    for (destination, data) in account.iter_mut().zip(id.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }

    Neuron {
        id: Some(NeuronId { id }),
        account,
        ..Default::default()
    }
}

// The following tests are not verifying the content of the stable indexes yet, as it's currently
// impossible to read from the indexes through its pub API. Those should be added when we start to
// allow reading from the stable indexes.
#[test]
fn test_batch_add_heap_neurons_to_stable_indexes_two_batches() {
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
        3 => simple_neuron(3),
        7 => simple_neuron(7),
    });

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
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
        3 => simple_neuron(3),
        7 => simple_neuron(7),
        12 => simple_neuron(12),
    });

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
fn test_batch_add_heap_neurons_to_stable_indexes_failure() {
    let mut neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
    });

    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 0 }, 2),
        Ok(None)
    );

    // Calling it again ignoring the progress would cause a failure.
    let result = neuron_store.batch_add_heap_neurons_to_stable_indexes(NeuronId { id: 0 }, 2);
    assert!(result.is_err(), "{:?}", result);
    let error = result.err().unwrap();
    assert!(error.contains("Subaccount"), "{}", error);
    assert!(error.contains("already exists in the index"), "{}", error);
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

    // No need to clear STABLE_NEURON_STORE, because each #[test] is run in its
    // own thread.

    // Step 2: Call the code under test.
    let mut neuron_store = NeuronStore::new(id_to_neuron);
    let batch_result = neuron_store.batch_add_inactive_neurons_to_stable_memory(batch);

    // Step 3: Verify.

    let last_neuron_id = NeuronId { id: 12 };
    assert_eq!(batch_result, Ok(Some(last_neuron_id)));

    fn read(neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
        STABLE_NEURON_STORE.with(|s| s.borrow().read(neuron_id))
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

    let observed_neurons =
        neuron_store.heap_neurons_range_with_begin_and_limit(NeuronId { id: 3 }, 2);

    assert_eq!(observed_neurons, vec![simple_neuron(3), simple_neuron(7)],);
}
