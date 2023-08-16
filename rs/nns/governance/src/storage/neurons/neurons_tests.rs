use super::*;

/// Summary:
///
///   1. create
///   2. bad create
///   3. read to verify create
///   4. bad read
///
///   5. update
///   6. read to verify the update
///   7. bad update
///   8. read to verify bad update
///
///   9. delete
///   10. bad delete: repeat
///   11. read to verify.
#[test]
fn test_store_simplest_nontrivial_case() {
    let mut store = new_heap_based();

    // 1. Create a Neuron.
    assert_eq!(
        store.create(Neuron {
            id: Some(NeuronId { id: 42 }),
            cached_neuron_stake_e8s: 0xCAFE, // Yummy.
            ..Default::default()
        }),
        Ok(())
    );

    // 2. Bad create: use an existing NeuronId. This should result in an
    // InvalidCommand Err.
    let bad_create_result = store.create(Neuron {
        id: Some(NeuronId { id: 42 }),
        cached_neuron_stake_e8s: 0xDEAD_BEEF,
        ..Default::default()
    });
    match &bad_create_result {
        Err(err) => {
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            assert_eq!(
                ErrorType::from_i32(*error_type),
                Some(ErrorType::PreconditionFailed),
                "{:?}",
                err,
            );

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("already in use"), "{:?}", err);
            assert!(error_message.contains("42"), "{:?}", err);
        }

        _ => panic!(
            "create(evil_twin_neuron) did not result in an Err: {:?}",
            bad_create_result
        ),
    }

    // 3. Read back the first neuron (the second one should have no effect).
    assert_eq!(
        store.read(NeuronId { id: 42 }),
        Ok(Neuron {
            id: Some(NeuronId { id: 42 }),
            cached_neuron_stake_e8s: 0xCAFE,
            ..Default::default()
        }),
    );

    // 4. Bad read: Unknown NeuronId. This should result in a NotFound Err.
    let bad_read_result = store.read(NeuronId { id: 0xDEAD_BEEF });
    match &bad_read_result {
        Err(err) => {
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            assert_eq!(
                ErrorType::from_i32(*error_type),
                Some(ErrorType::NotFound),
                "{:?}",
                err,
            );

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable to find"), "{:?}", err);
            assert!(error_message.contains("3735928559"), "{:?}", err); // 0xDEAD_BEEF
        }

        _ => panic!(
            "read(0xDEAD) did not result in an Err: {:?}",
            bad_read_result
        ),
    }

    // 5. Update existing neuron.
    let update_result = store.update(Neuron {
        id: Some(NeuronId { id: 42 }),
        cached_neuron_stake_e8s: 0xFEED, // After drink, we eat.
        ..Default::default()
    });
    assert_eq!(update_result, Ok(()));

    // 6. Read to verify update.
    assert_eq!(
        store.read(NeuronId { id: 42 }),
        Ok(Neuron {
            id: Some(NeuronId { id: 42 }),
            // The most important part: entry actually changed.
            cached_neuron_stake_e8s: 0xFEED,
            ..Default::default()
        }),
    );

    // 7. Bad update: Neuron not found (unknown ID).
    let update_result = store.update(Neuron {
        id: Some(NeuronId { id: 0xDEAD_BEEF }),
        cached_neuron_stake_e8s: 0xBAD_F00D,
        ..Default::default()
    });
    match &update_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("update"), "{:?}", err);
            assert!(error_message.contains("existing"), "{:?}", err);
            assert!(error_message.contains("neuron"), "{:?}", err);
            assert!(error_message.contains("there was none"), "{:?}", err);

            assert!(error_message.contains("id"), "{:?}", err);
            assert!(error_message.contains("3735928559"), "{:?}", err); // 0xDEAD_BEEF

            assert!(
                error_message.contains("cached_neuron_stake_e8s"),
                "{:?}",
                err,
            );
            assert!(error_message.contains("195948557"), "{:?}", err); // 0xBAD_F00D
        }

        // Any other result is bad.
        _ => panic!("{:#?}", update_result),
    }

    // 8. Read to verify bad update.
    let read_result = store.read(NeuronId { id: 0xDEAD_BEEF });
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable to find"), "{:?}", err);
            assert!(error_message.contains("3735928559"), "{:?}", err); // 0xDEAD_BEEF
        }

        _ => panic!("read did not return Err: {:?}", read_result),
    }

    // 9. Delete.
    assert_eq!(store.delete(NeuronId { id: 42 }), Ok(()));

    // 10. Bad delete: repeat.
    let delete_result = store.delete(NeuronId { id: 42 });
    match &delete_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("not found"), "{:?}", err);
            assert!(error_message.contains("42"), "{:?}", err);
        }

        _ => panic!("second delete did not return Err: {:?}", delete_result),
    }

    // 11. Read to verify delete.
    let read_result = store.read(NeuronId { id: 42 });
    match &read_result {
        // This is what we expected.
        Err(err) => {
            // Take a closer look at err.
            let GovernanceError {
                error_type,
                error_message,
            } = err;

            // Inspect type.
            let error_type = ErrorType::from_i32(*error_type);
            assert_eq!(error_type, Some(ErrorType::NotFound), "{:?}", err);

            // Next, turn to error_message.
            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("unable to find"), "{:?}", err);
            assert!(error_message.contains("42"), "{:?}", err);
        }

        _ => panic!("read did not return Err: {:?}", read_result),
    }
}

/// Summary:
///
///   1. upsert (effectively, an insert)
///   2. read to verify
///   3. upsert same ID (effectively, an update)
///   4. read to verify
#[test]
fn test_store_upsert() {
    let mut store = new_heap_based();

    let neuron = Neuron {
        id: Some(NeuronId { id: 0xF00D }),
        cached_neuron_stake_e8s: 0xBEEF,
        ..Default::default()
    };

    // 1. upsert (entry not already present)
    assert_eq!(store.upsert(neuron.clone()), Ok(()));

    // 2. read to verify
    assert_eq!(store.read(NeuronId { id: 0xF00D }), Ok(neuron.clone()));

    // Modify neuron.
    let neuron = Neuron {
        cached_neuron_stake_e8s: 0xCAFE,
        ..neuron
    };

    // 3. upsert (change an existing entry)
    assert_eq!(store.upsert(neuron.clone()), Ok(()));

    // 4. read to verify
    assert_eq!(store.read(NeuronId { id: 0xF00D }), Ok(neuron));
}
