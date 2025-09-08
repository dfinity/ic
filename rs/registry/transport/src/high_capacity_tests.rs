use super::*;
use crate::pb::v1::{Precondition, high_capacity_registry_mutation, registry_mutation};
use lazy_static::lazy_static;
use pretty_assertions::assert_eq;

lazy_static! {
    static ref RECONSTITUTED_MONOLITHIC_BLOB: Vec<u8> = b"ABCXYZ".to_vec();
    static ref CHUNK_KEY_TO_CONTENT: Vec<(Vec<u8>, Vec<u8>)> = [b"ABC".to_vec(), b"XYZ".to_vec(),]
        .into_iter()
        .map(|chunk_content| {
            let key = Sha256::hash(&chunk_content).to_vec();
            (key, chunk_content)
        })
        .collect();
    static ref LARGE_VALUE_CHUNK_KEYS: LargeValueChunkKeys = LargeValueChunkKeys {
        chunk_content_sha256s: CHUNK_KEY_TO_CONTENT
            .clone()
            .into_iter()
            .map(|(key, _content)| key)
            .collect(),
    };
}

// We do not define a GET_CHUNK in lazy_static! because that never gets dropped,
// and therefore, we would not detect when expected calls get "left hanging"
// (i.e. end up never occurring). Whereas, by providing this function (instead
// of GET_CHUNK), tests drop the MockGetChunk at the end, and it is then
// verified that there are no expected calls that didn't end up occurring.
fn new_get_chunk() -> MockGetChunk {
    let mut result = MockGetChunk::new();

    // Populate result. I.e. set expected calls. I.e. all chunks are
    // requested (via the get_chunk_without_validation method).
    for (key, content) in CHUNK_KEY_TO_CONTENT.clone() {
        result
            .expect_get_chunk_without_validation()
            .with(mockall::predicate::eq(key))
            .times(1)
            .returning(move |_key| Ok(content.clone()));
    }

    result
}

#[tokio::test]
async fn test_dechunkify_get_value_content() {
    // Step 1: Prepare the world. Actually, this is done in the lazy_static +
    // new_get_chunk fixture, so our job here is trivial.

    // Step 2: Run the code under test.
    let dechunkified = dechunkify_get_value_response_content(
        high_capacity_registry_get_value_response::Content::LargeValueChunkKeys(
            LARGE_VALUE_CHUNK_KEYS.clone(),
        ),
        &new_get_chunk(),
    )
    .await;

    // Step 3: Verify result(s).
    assert_eq!(dechunkified, Ok(RECONSTITUTED_MONOLITHIC_BLOB.clone()));
}

#[tokio::test]
async fn test_dechunkify_mutation_value() {
    // Step 1: Prepare the world. Actually, this is done in the lazy_static +
    // new_get_chunk fixture, so our job here is trivial.

    // Step 2: Run the code under test.

    // Step 2.1: The interesting case. To wit, LargeValueChunkKeys.
    let large_mutation = HighCapacityRegistryMutation {
        mutation_type: registry_mutation::Type::Upsert as i32,
        key: b"this does not matter to the test".to_vec(),
        content: Some(
            high_capacity_registry_mutation::Content::LargeValueChunkKeys(
                LARGE_VALUE_CHUNK_KEYS.clone(),
            ),
        ),
    };
    let large_value: Option<Vec<u8>> = dechunkify_mutation_value(large_mutation, &new_get_chunk())
        .await
        .unwrap();

    // Step 2.2 and 2.3: These cases are "boring", but nevertheless need to be tested

    let small_mutation = HighCapacityRegistryMutation {
        mutation_type: registry_mutation::Type::Insert as i32,
        key: b"lil".to_vec(),
        content: Some(high_capacity_registry_mutation::Content::Value(
            b"Hello, world!".to_vec(),
        )),
    };
    let small_value = dechunkify_mutation_value(small_mutation, &MockGetChunk::new())
        .await
        .unwrap();

    let delete_mutation = HighCapacityRegistryMutation {
        mutation_type: registry_mutation::Type::Delete as i32,
        key: b"del".to_vec(),
        content: None,
    };
    let delete_value = dechunkify_mutation_value(delete_mutation, &MockGetChunk::new())
        .await
        .unwrap();

    // Step 3: Verify result(s).

    assert_eq!(large_value, Some(RECONSTITUTED_MONOLITHIC_BLOB.clone()));
    assert_eq!(small_value, Some(b"Hello, world!".to_vec()));
    assert_eq!(delete_value, None);
}

#[tokio::test]
async fn test_dechunkify_delta() {
    // Step 1: Prepare the world. Actually, this is done in the lazy_static +
    // new_get_chunk fixture, so our job here is trivial.

    // Step 2: Run the code under test.

    let high_capacity_delta = HighCapacityRegistryDelta {
        key: b"not actually important to this test".to_vec(),
        values: vec![
            HighCapacityRegistryValue {
                version: 7,
                content: Some(high_capacity_registry_value::Content::Value(
                    b"inline".to_vec(),
                )),
                timestamp_nanoseconds: 0,
            },
            HighCapacityRegistryValue {
                version: 8,
                content: Some(high_capacity_registry_value::Content::LargeValueChunkKeys(
                    LARGE_VALUE_CHUNK_KEYS.clone(),
                )),
                timestamp_nanoseconds: 0,
            },
            HighCapacityRegistryValue {
                version: 9,
                content: Some(high_capacity_registry_value::Content::DeletionMarker(true)),
                timestamp_nanoseconds: 0,
            },
        ],
    };
    let inlined_delta: RegistryDelta = dechunkify_delta(high_capacity_delta, &new_get_chunk())
        .await
        .unwrap();

    // Step 3: Verify result(s).

    assert_eq!(
        inlined_delta,
        RegistryDelta {
            key: b"not actually important to this test".to_vec(),
            values: vec![
                RegistryValue {
                    version: 7,
                    value: b"inline".to_vec(),
                    deletion_marker: false,
                    timestamp_nanoseconds: 0,
                },
                // This is the most interesting element; nevertheless, the other
                // cases are included in this test, because ofc, even though a
                // behavior is "boring", we still need to verify it.
                RegistryValue {
                    version: 8,
                    value: RECONSTITUTED_MONOLITHIC_BLOB.clone(),
                    deletion_marker: false,
                    timestamp_nanoseconds: 0,
                },
                RegistryValue {
                    version: 9,
                    value: vec![],
                    deletion_marker: true,
                    timestamp_nanoseconds: 0,
                },
            ],
        },
    );
}

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
            timestamp_nanoseconds: 0,
        }
    );
}
