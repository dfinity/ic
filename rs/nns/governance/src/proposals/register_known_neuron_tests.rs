use super::*;

use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    neuron_store::NeuronStore,
    pb::v1::{KnownNeuron, KnownNeuronData, governance_error::ErrorType},
    proposals::register_known_neuron::{
        KNOWN_NEURON_DESCRIPTION_MAX_LEN, KNOWN_NEURON_NAME_MAX_LEN,
    },
};
use assert_matches::assert_matches;
use ic_nns_common::pb::v1::NeuronId;
use std::collections::BTreeMap;

fn create_test_neuron_store() -> NeuronStore {
    let mut neuron_store = NeuronStore::new(BTreeMap::new());

    // Create a regular neuron (ID: 1) - not yet a known neuron
    let regular_neuron = NeuronBuilder::new_for_test(
        1,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 86400,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_cached_neuron_stake_e8s(1_000_000_000)
    .build();

    neuron_store.add_neuron(regular_neuron).unwrap();

    // Create a neuron that's already a known neuron (ID: 2)
    let already_known_neuron = NeuronBuilder::new_for_test(
        2,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 86400,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_cached_neuron_stake_e8s(1_000_000_000)
    .with_known_neuron_data(Some(KnownNeuronData {
        name: "Existing Known Neuron".to_string(),
        description: Some("Already registered".to_string()),
        links: vec!["https://existing.com".to_string()],
    }))
    .build();

    neuron_store.add_neuron(already_known_neuron).unwrap();

    neuron_store
}

#[test]
fn test_validate_success() {
    let neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron for registration".to_string()),
            links: vec!["https://example.com".to_string()],
        }),
    };

    assert_eq!(request.validate(&neuron_store), Ok(()));
}

#[test]
fn test_validate_missing_neuron_id() {
    let neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: None,
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: vec![],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("No neuron ID specified")
    );
}

#[test]
fn test_validate_missing_known_neuron_data() {
    let neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: None,
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("No known neuron data specified")
    );
}

#[test]
fn test_validate_nonexistent_neuron() {
    let neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: Some(NeuronId { id: 999 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: vec![],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::NotFound as i32
            && error.error_message.contains("Neuron 999 not found")
    );
}

#[test]
fn test_validate_name_empty() {
    let neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "".to_string(),
            description: Some("A test known neuron".to_string()),
            links: vec![],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("The neuron's name is empty.")
    );
}

#[test]
fn test_validate_name_too_long() {
    let neuron_store = create_test_neuron_store();
    let long_name = "a".repeat(KNOWN_NEURON_NAME_MAX_LEN + 1);
    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: long_name,
            description: Some("A test known neuron".to_string()),
            links: vec![],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("maximum number of bytes for a neuron's name")
            && error.error_message.contains(&format!("{}", KNOWN_NEURON_NAME_MAX_LEN))
    );
}

#[test]
fn test_validate_description_too_long() {
    let neuron_store = create_test_neuron_store();
    let long_description = "a".repeat(KNOWN_NEURON_DESCRIPTION_MAX_LEN + 1);
    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some(long_description),
            links: vec![],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("maximum number of bytes for a neuron's description")
            && error.error_message.contains(&format!("{}", KNOWN_NEURON_DESCRIPTION_MAX_LEN))
    );
}

#[test]
fn test_validate_too_many_links() {
    let neuron_store = create_test_neuron_store();
    let too_many_links: Vec<String> = (0..11)
        .map(|i| format!("https://example{}.com", i))
        .collect();

    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: too_many_links,
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("The maximum number of links")
            && error.error_message.contains(&format!("{}", MAX_KNOWN_NEURON_LINKS))
    );
}

#[test]
fn test_validate_link_too_long() {
    let neuron_store = create_test_neuron_store();
    let long_link = format!("https://{}.com", "a".repeat(89)); // 101 characters total

    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: vec![long_link],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("Link at index 0 is not valid")
            && error.error_message.contains("100 characters long")
            && error.error_message.contains("but it is 101 characters long")
    );
}

#[test]
fn test_validate_link_invalid() {
    let neuron_store = create_test_neuron_store();
    let invalid_link = "http://not-secure.com".to_string();

    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: vec![invalid_link],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("Link at index 0 is not valid")
            && error.error_message.contains("https://")
    );
}

#[test]
fn test_validate_name_already_exists() {
    let neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Existing Known Neuron".to_string(), // Same as neuron ID 2
            description: Some("A test known neuron".to_string()),
            links: vec![],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("already belongs to a different known neuron with ID 2")
            && error.error_message.contains("Existing Known Neuron")
    );
}

#[test]
fn test_validate_maximum_valid_links() {
    let neuron_store = create_test_neuron_store();
    let max_links: Vec<String> = (0..10)
        .map(|i| format!("https://example{}.com", i))
        .collect();

    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: max_links,
        }),
    };

    let result = request.validate(&neuron_store);
    assert_eq!(
        result,
        Ok(()),
        "Expected validation to succeed with 10 links"
    );
}

#[test]
fn test_validate_maximum_valid_link_size() {
    let neuron_store = create_test_neuron_store();
    let max_size_link = format!("https://{}.com", "a".repeat(88)); // Exactly 100 bytes

    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: vec![max_size_link],
        }),
    };

    let result = request.validate(&neuron_store);
    assert_eq!(
        result,
        Ok(()),
        "Expected validation to succeed with 100-byte link"
    );
}

#[test]
fn test_execute_success() {
    let mut neuron_store = create_test_neuron_store();
    let neuron_id = NeuronId { id: 1 };
    let known_neuron_data = KnownNeuronData {
        name: "Test Known Neuron".to_string(),
        description: Some("A test known neuron for registration".to_string()),
        links: vec![
            "https://example.com".to_string(),
            "https://test.com".to_string(),
        ],
    };
    let request = KnownNeuron {
        id: Some(neuron_id),
        known_neuron_data: Some(known_neuron_data.clone()),
    };

    // Verify the neuron doesn't have known neuron data before execution
    let has_known_data_before = neuron_store
        .with_neuron(&neuron_id, |neuron| neuron.known_neuron_data().is_some())
        .expect("Neuron should exist");
    assert!(
        !has_known_data_before,
        "Neuron should not have known data before registration"
    );

    // Execute the registration
    assert_eq!(request.execute(&mut neuron_store), Ok(()));

    // Verify the known neuron data has been added
    let known_data_after = neuron_store
        .with_neuron(&neuron_id, |neuron| neuron.known_neuron_data().cloned())
        .expect("Neuron should exist");
    assert_eq!(known_data_after, Some(known_neuron_data));

    // Verify the neuron itself still exists with other data intact
    assert!(neuron_store.contains(neuron_id),);

    let stake = neuron_store
        .with_neuron(&neuron_id, |neuron| neuron.cached_neuron_stake_e8s)
        .expect("Neuron should exist");
    assert_eq!(stake, 1_000_000_000, "Neuron stake should remain unchanged");
}

// Tests for validation failures occuring in the `execute()` method. Not all validation failures are
// tested here, since the `validate()` method is tested in the previous section, and technically not
// all validations need to be performed in `execute()`.

#[test]
fn test_execute_validation_failure() {
    let mut neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: Some(NeuronId { id: 999 }), // Non-existent neuron
        known_neuron_data: Some(KnownNeuronData {
            name: "Test Known Neuron".to_string(),
            description: Some("A test known neuron".to_string()),
            links: vec![],
        }),
    };

    let result = request.execute(&mut neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::NotFound as i32
            && error.error_message.contains("Neuron 999 not found")
    );
}

#[test]
fn test_execute_name_conflict() {
    let mut neuron_store = create_test_neuron_store();
    let request = KnownNeuron {
        id: Some(NeuronId { id: 1 }),
        known_neuron_data: Some(KnownNeuronData {
            name: "Existing Known Neuron".to_string(), // Same as neuron ID 2
            description: Some("A test known neuron".to_string()),
            links: vec![],
        }),
    };

    let result = request.execute(&mut neuron_store);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("already belongs to a different known neuron with ID 2")
    );
}

#[test]
fn test_clobbering_same_neuron_allowed() {
    let mut neuron_store = create_test_neuron_store();
    // Try to register neuron ID 2 with its existing name "Existing Known Neuron"
    // This should succeed (clobbering is allowed when same name and same ID)
    let updated_data = KnownNeuronData {
        name: "Existing Known Neuron".to_string(), // Same name as neuron ID 2 already has
        description: Some("Updated description".to_string()),
        links: vec!["https://updated.com".to_string()],
    };
    let request = KnownNeuron {
        id: Some(NeuronId { id: 2 }),
        known_neuron_data: Some(updated_data.clone()),
    };

    // Execute the registration - should succeed
    let result = request.execute(&mut neuron_store);
    assert_eq!(
        result,
        Ok(()),
        "Should allow clobbering when same neuron ID and name"
    );

    // Verify the known neuron data has been updated
    let known_data_after = neuron_store
        .with_neuron(&NeuronId { id: 2 }, |neuron| {
            neuron.known_neuron_data().cloned()
        })
        .expect("Neuron should exist");
    assert_eq!(
        known_data_after,
        Some(updated_data),
        "Known neuron data should be updated"
    );
}
