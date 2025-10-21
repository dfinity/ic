use super::*;
use crate::flags::temporarily_enable_chunkifying_large_values;
use ic_registry_transport::pb::v1::{
    LargeValueChunkKeys, Precondition, RegistryMutation, high_capacity_registry_mutation,
    registry_mutation,
};
use lazy_static::lazy_static;

lazy_static! {
    static ref PRECONDITION: Precondition = Precondition {
        key: b"precondition".to_vec(),
        expected_version: 42,
    };
}

fn new_monolithic_blob(size: u64) -> Vec<u8> {
    const DIVISOR: u64 = u8::MAX as u64 + 1;

    (0..size).map(|i| (i % DIVISOR) as u8).collect::<Vec<u8>>()
}

#[test]
fn test_no_chunkify_small_mutation() {
    // Step 1: Prepare the world.
    let _restore_on_drop = temporarily_enable_chunkifying_large_values();

    let original_mutation = RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            key: b"name".to_vec(),
            mutation_type: registry_mutation::Type::Insert as i32,
            value: b"Daniel Wong".to_vec(),
        }],
        preconditions: vec![PRECONDITION.clone()],
    };

    // Step 2: Call the code under test.
    let result = chunkify_composite_mutation_if_too_large(original_mutation.clone());

    // Step 3: Verify results. Since the input is small, the output is simply a
    // transcription of the input. In particular, there is no chunking.
    assert_eq!(
        result,
        HighCapacityRegistryAtomicMutateRequest::from(original_mutation)
    );
}

#[test]
fn test_chunkify_reasonably_large_mutation() {
    // Step 1: Prepare the world.
    let _restore_on_drop = temporarily_enable_chunkifying_large_values();

    let original_monolithic_blob = new_monolithic_blob(3_000_000);

    let original_mutation = RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            key: b"whale".to_vec(),
            mutation_type: registry_mutation::Type::Insert as i32,
            value: original_monolithic_blob.clone(),
        }],
        preconditions: vec![PRECONDITION.clone()],
    };

    // Step 2: Call the code under test.
    let result = chunkify_composite_mutation_if_too_large(original_mutation);

    // Step 3: Verify results.

    // Step 3.1: Assert that value has been replaced with LargeValueChunkKeys.
    let first_prime_mutation = result.mutations.first().unwrap().content.as_ref().unwrap();
    let high_capacity_registry_mutation::Content::LargeValueChunkKeys(LargeValueChunkKeys {
        chunk_content_sha256s,
    }) = first_prime_mutation
    else {
        panic!("{result:?}");
    };

    // Step 3.2: Assert that reassembled blob is equal to the original.
    let reassembled_monolitich_blob = with_chunks(|chunks| {
        let mut result = vec![];
        for key in chunk_content_sha256s {
            result.append(&mut chunks.get_chunk(key).unwrap());
        }
        result
    });
    assert_eq!(reassembled_monolitich_blob, original_monolithic_blob);

    // Step 3.3: Finally, check other fields of result.
    let expected_mutation = HighCapacityRegistryAtomicMutateRequest {
        mutations: vec![result.mutations.first().unwrap().clone()],
        preconditions: vec![PRECONDITION.clone()],
        timestamp_nanoseconds: 0,
    };
    assert_eq!(result, expected_mutation);
}

#[test]
#[should_panic = "Mutation too large."]
fn test_panic_on_hyper_large_mutation() {
    // Step 1: Prepare the world.
    let _restore_on_drop = temporarily_enable_chunkifying_large_values();

    let monolithic_blob = new_monolithic_blob(100_000_000);

    let original_mutation = RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            key: b"absurd".to_vec(),
            mutation_type: registry_mutation::Type::Insert as i32,
            value: monolithic_blob.clone(),
        }],
        preconditions: vec![PRECONDITION.clone()],
    };

    // Step 2: Call the code under test.
    let _explode = chunkify_composite_mutation_if_too_large(original_mutation);

    // Step 3: Verify results. The previous line is supposed to panic (and this
    // is verified at the top via should_panic).
}
