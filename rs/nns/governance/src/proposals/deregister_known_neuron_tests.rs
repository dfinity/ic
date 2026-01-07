use crate::proposals::self_describing::LocallyDescribableProposalAction;
use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    neuron_store::NeuronStore,
    pb::v1::{DeregisterKnownNeuron, KnownNeuronData, governance_error::ErrorType},
};
use assert_matches::assert_matches;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::SelfDescribingValue;
use maplit::hashmap;
use std::collections::BTreeMap;

fn create_test_neuron_store() -> NeuronStore {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Create a known neuron (ID: 1)
    let known_neuron = NeuronBuilder::new_for_test(
        1,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 86400,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_cached_neuron_stake_e8s(1_000_000_000)
    .with_known_neuron_data(Some(KnownNeuronData {
        name: "Test Known Neuron".to_string(),
        description: Some("A test known neuron for deregistration".to_string()),
        links: vec!["http://example.com".to_string()],
        committed_topics: vec![],
    }))
    .build();

    neuron_store.add_neuron(known_neuron).unwrap();

    // Create a regular neuron without known neuron data (ID: 2)
    let regular_neuron = NeuronBuilder::new_for_test(
        2,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 86400,
            aging_since_timestamp_seconds: 0,
        },
    )
    .build();

    neuron_store.add_neuron(regular_neuron).unwrap();

    neuron_store
}

#[test]
fn test_validate_success_with_known_neuron() {
    let neuron_store = create_test_neuron_store();
    let request = DeregisterKnownNeuron {
        id: Some(NeuronId { id: 1 }),
    };

    let result = request.validate(&neuron_store);
    assert!(
        result.is_ok(),
        "Expected validation to succeed for known neuron"
    );
}

#[test]
fn test_validate_missing_neuron_id() {
    let neuron_store = create_test_neuron_store();
    let request = DeregisterKnownNeuron { id: None };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("No neuron ID specified")
    );
}

#[test]
fn test_validate_nonexistent_neuron() {
    let neuron_store = create_test_neuron_store();
    let request = DeregisterKnownNeuron {
        id: Some(NeuronId { id: 999 }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::NotFound as i32
            && error.error_message.contains("Neuron not found")
            && error.error_message.contains("999")
    );
}

#[test]
fn test_validate_regular_neuron_not_known() {
    let neuron_store = create_test_neuron_store();
    let request = DeregisterKnownNeuron {
        id: Some(NeuronId { id: 2 }), // Regular neuron without known data
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("is not a known neuron")
            && error.error_message.contains("2")
    );
}

#[test]
fn test_execute_success() {
    let mut neuron_store = create_test_neuron_store();
    let neuron_id = NeuronId { id: 1 };
    let request = DeregisterKnownNeuron {
        id: Some(neuron_id),
    };

    // Verify the neuron has known neuron data before execution
    let has_known_data_before = neuron_store
        .with_neuron(&neuron_id, |neuron| neuron.known_neuron_data().is_some())
        .expect("Neuron should exist");
    assert!(
        has_known_data_before,
        "Neuron should have known data before deregistration"
    );

    // Also verify the actual data
    let known_data_before = neuron_store
        .with_neuron(&neuron_id, |neuron| neuron.known_neuron_data().cloned())
        .expect("Neuron should exist");
    assert!(
        known_data_before.is_some(),
        "Known data should exist before deregistration"
    );
    let data = known_data_before.unwrap();
    assert_eq!(data.name, "Test Known Neuron");
    assert_eq!(
        data.description,
        Some("A test known neuron for deregistration".to_string())
    );

    // Execute the deregistration
    let result = request.execute(&mut neuron_store);
    assert!(result.is_ok(), "Execute should succeed: {result:?}");

    // Verify the known neuron data has been removed
    let has_known_data_after = neuron_store
        .with_neuron(&neuron_id, |neuron| neuron.known_neuron_data().is_some())
        .expect("Neuron should still exist after deregistration");
    assert!(
        !has_known_data_after,
        "Neuron should not have known data after deregistration"
    );

    // Verify the neuron itself still exists with other data intact
    let neuron_exists = neuron_store.contains(neuron_id);
    assert!(
        neuron_exists,
        "Neuron should still exist after deregistration"
    );

    let stake = neuron_store
        .with_neuron(&neuron_id, |neuron| neuron.cached_neuron_stake_e8s)
        .expect("Neuron should exist");
    assert_eq!(stake, 1_000_000_000, "Neuron stake should remain unchanged");
}

#[test]
fn test_execute_missing_neuron_id() {
    let mut neuron_store = create_test_neuron_store();
    let request = DeregisterKnownNeuron { id: None };

    let result = request.execute(&mut neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("No neuron ID specified")
    );
}

#[test]
fn test_execute_nonexistent_neuron() {
    let mut neuron_store = create_test_neuron_store();
    let request = DeregisterKnownNeuron {
        id: Some(NeuronId { id: 999 }),
    };

    let result = request.execute(&mut neuron_store);
    assert_matches!(result, Err(_), "Execute should fail for nonexistent neuron");
}

#[test]
fn test_deregister_known_neuron_to_self_describing() {
    let deregister = DeregisterKnownNeuron {
        id: Some(NeuronId { id: 456 }),
    };

    let action = deregister.to_self_describing_action();
    let value = SelfDescribingValue::from(action.value.unwrap());

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "neuron_id".to_string() => SelfDescribingValue::Nat(candid::Nat::from(456u64)),
        })
    );
}
