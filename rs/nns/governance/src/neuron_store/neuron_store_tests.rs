use super::*;

use maplit::btreemap;

fn simple_neuron(id: u8) -> Neuron {
    Neuron {
        id: Some(NeuronId { id: id as u64 }),
        account: [id; 32].to_vec(),
        ..Default::default()
    }
}

// The following tests are not verifying the content of the stable indexes yet, as it's currently
// impossible to read from the indexes through its pub API. Those should be added when we start to
// allow reading from the stable indexes.
#[test]
fn batch_add_heap_neurons_to_stable_indexes_two_batches() {
    let neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
        3 => simple_neuron(2),
        7 => simple_neuron(7),
    });

    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(0, 2),
        Ok(Some(3))
    );
    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(3, 2),
        Ok(None)
    );
}

#[test]
fn batch_add_heap_neurons_to_stable_indexes_three_batches_last_empty() {
    let neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
        3 => simple_neuron(3),
        7 => simple_neuron(7),
        12 => simple_neuron(12),
    });

    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(0, 2),
        Ok(Some(3))
    );
    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(3, 2),
        Ok(Some(12))
    );
    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(12, 2),
        Ok(None)
    );
}

#[test]
fn batch_add_heap_neurons_to_stable_indexes_failure() {
    let neuron_store = NeuronStore::new(btreemap! {
        1 => simple_neuron(1),
    });

    assert_eq!(
        neuron_store.batch_add_heap_neurons_to_stable_indexes(0, 2),
        Ok(None)
    );

    // Calling it again ignoring the progress would cause a failure.
    let result = neuron_store.batch_add_heap_neurons_to_stable_indexes(0, 2);
    assert!(result.is_err(), "{:?}", result);
    let error = result.err().unwrap();
    assert!(error.contains("Subaccount"), "{}", error);
    assert!(error.contains("already exists in the index"), "{}", error);
}
