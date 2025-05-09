use super::*;
use crate::pb::v1::{high_capacity_registry_mutation, registry_mutation, Precondition};

#[test]
fn test_convert_to_high_capacity_registry_atomic_mutate_request() {
    let preconditions = vec![
        Precondition {
            key: b"precondition 1".to_vec(),
            expected_version: 42,
        },
        Precondition {
            key: b"some other key".to_vec(),
            expected_version: 57,
        },
    ];

    let original_mutation = RegistryAtomicMutateRequest {
        mutations: vec![
            RegistryMutation {
                key: b"name".to_vec(),
                mutation_type: registry_mutation::Type::Upsert as i32,
                value: b"Daniel".to_vec(),
            },
            RegistryMutation {
                key: b"job".to_vec(),
                mutation_type: registry_mutation::Type::Insert as i32,
                value: b"Software Engineer".to_vec(),
            },
        ],
        preconditions: preconditions.clone(),
    };

    let upgraded_mutation = HighCapacityRegistryAtomicMutateRequest::from(original_mutation);

    assert_eq!(
        upgraded_mutation,
        HighCapacityRegistryAtomicMutateRequest {
            mutations: vec![
                HighCapacityRegistryMutation {
                    key: b"name".to_vec(),
                    mutation_type: registry_mutation::Type::Upsert as i32,
                    content: Some(high_capacity_registry_mutation::Content::Value(
                        b"Daniel".to_vec()
                    )),
                },
                HighCapacityRegistryMutation {
                    key: b"job".to_vec(),
                    mutation_type: registry_mutation::Type::Insert as i32,
                    content: Some(high_capacity_registry_mutation::Content::Value(
                        b"Software Engineer".to_vec()
                    )),
                },
            ],
            preconditions,
            timestamp_seconds: 0,
        }
    );
}
