use super::*;
use ic_registry_transport::pb::v1::{registry_mutation, Precondition};
use std::{cell::RefCell, rc::Rc};

#[test]
fn test_chunkify_composite_mutation() {
    // Step 1: Prepare the world.

    // Step 1.1: Construct input mutation.
    let divisor = u8::MAX as u64 + 1;

    let original_monolithic_blob = (0..5_000_000)
        .map(|i| {
            let b = (31 * i + 42) % divisor;
            b as u8
        })
        .collect::<Vec<u8>>();

    let original_mutation = RegistryAtomicMutateRequest {
        mutations: vec![
            RegistryMutation {
                key: b"whale".to_vec(),
                mutation_type: registry_mutation::Type::Upsert as i32,
                value: original_monolithic_blob.clone(),
            },
            RegistryMutation {
                key: b"small".to_vec(),
                mutation_type: registry_mutation::Type::Update as i32,
                value: b"Hello, world!".to_vec(),
            },
        ],
        preconditions: vec![
            Precondition {
                key: b"precondition".to_vec(),
                expected_version: 42,
            },
            Precondition {
                key: b"some other key".to_vec(),
                expected_version: 57,
            },
        ],
    };

    // Step 1.2: monolithic blob will be stored here.
    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let mut chunks = Chunks::init(memory);

    // Step 2: Run code under test.
    let upgraded_mutation = chunkify_composite_mutation(original_mutation.clone(), &mut chunks);

    // Step 3: Verify results.

    let first_prime_mutation = upgraded_mutation.mutations.first().unwrap();

    // Assert that the first prime mutation within the result was chunkified/de-inlined.
    let chunk_content_sha256s = match first_prime_mutation.content.as_ref().unwrap() {
        high_capacity_registry_mutation::Content::LargeValueChunkKeys(LargeValueChunkKeys {
            chunk_content_sha256s,
        }) => chunk_content_sha256s.clone(),

        _ => panic!("{:?}", upgraded_mutation),
    };

    // Assert that Chunks was populated, and we can reconstruct the original
    // monolithic blob.
    let mut reconstructed_monolithic_blob = vec![];
    for key in &chunk_content_sha256s {
        reconstructed_monolithic_blob.append(&mut chunks.get_chunk(key).unwrap())
    }
    assert_eq!(reconstructed_monolithic_blob, original_monolithic_blob);

    // The expected return value is mostly the same as the "transcription" of
    // the input, except that the first prime/component mutation was chunkified.
    let mut expected_mutation = HighCapacityRegistryAtomicMutateRequest::from(original_mutation);
    *expected_mutation.mutations.get_mut(0).unwrap() = HighCapacityRegistryMutation {
        key: b"whale".to_vec(),
        mutation_type: registry_mutation::Type::Upsert as i32,
        content: Some(
            high_capacity_registry_mutation::Content::LargeValueChunkKeys(LargeValueChunkKeys {
                chunk_content_sha256s,
            }),
        ),
    };

    assert_eq!(upgraded_mutation, expected_mutation);
}
