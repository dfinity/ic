use super::*;

// create followed by read.
#[test]
fn test_store_simplest_nontrivial_case() {
    let mut store = new_heap_based();

    // create a Neuron.
    assert_eq!(
        store.create(Neuron {
            id: Some(NeuronId { id: 42 }),
            cached_neuron_stake_e8s: 0xDEAD_BEEF,
            ..Default::default()
        }),
        Ok(())
    );

    // read it back.
    assert_eq!(
        store.read(NeuronId { id: 42 }),
        Ok(Neuron {
            id: Some(NeuronId { id: 42 }),
            cached_neuron_stake_e8s: 0xDEAD_BEEF,
            ..Default::default()
        }),
    );

    // Bad read: Unknown NeuronId. This should result in Err.
    let bad_read_result = store.read(NeuronId { id: 123 });
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
            assert!(error_message.contains("unable to find"), "{:?}", err,);
            assert!(error_message.contains("123"), "{:?}", err,);
        }

        _ => panic!(
            "read(0xDEAD) did not result in an Err: {:?}",
            bad_read_result
        ),
    }

    // Bad create: use an existing NeuronId.
    let bad_create_result = store.create(Neuron {
        id: Some(NeuronId { id: 42 }),
        cached_neuron_stake_e8s: 1,
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
            assert!(error_message.contains("already in use"), "{:?}", err,);
            assert!(error_message.contains("42"), "{:?}", err,);
        }

        _ => panic!(
            "create(evil_twin_neuron) did not result in an Err: {:?}",
            bad_create_result
        ),
    }
}
