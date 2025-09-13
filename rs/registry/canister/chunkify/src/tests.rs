use super::*;
use ic_nervous_system_chunks::test_data::MEGA_BLOB;
use ic_registry_transport::pb::v1::{
    HighCapacityRegistryValue, Precondition, high_capacity_registry_mutation,
    high_capacity_registry_value,
    registry_mutation::{self, Type as MutationType},
};
use prost::Message;
use std::{
    cell::{RefCell, RefMut},
    rc::Rc,
};

type MemoryImpl = Rc<RefCell<Vec<u8>>>;

thread_local! {
    static MEMORY: RefCell<MemoryImpl> = RefCell::new(Rc::new(RefCell::new(Vec::<u8>::new())));
    static CHUNKS: RefCell<Chunks<MemoryImpl>> = MEMORY.with(|memory: &RefCell<MemoryImpl>| {
        let memory: RefMut<MemoryImpl> = memory.borrow_mut();
        RefCell::new(Chunks::init(memory.clone()))
    });
}

#[test]
fn test_dechunkify_registry_value_inline() {
    let value = high_capacity_registry_value::Content::Value(vec![42, 43, 44]);

    CHUNKS.with(|chunks| {
        assert_eq!(
            dechunkify_registry_value(value, &*chunks.borrow()),
            Some(vec![42, 43, 44]),
        );
    });
}

#[test]
fn test_dechunkify_registry_value_delete() {
    let value = high_capacity_registry_value::Content::DeletionMarker(true);
    CHUNKS.with(|chunks| {
        assert_eq!(dechunkify_registry_value(value, &*chunks.borrow()), None,);
    });

    // This is a value that we would not expect to see in practice, but rustc
    // does not prevent it, so we handle it anyway by treating it like
    // Value(vec![]).
    let value = high_capacity_registry_value::Content::DeletionMarker(false);
    CHUNKS.with(|chunks| {
        assert_eq!(
            dechunkify_registry_value(value, &*chunks.borrow()),
            Some(vec![]),
        );
    });
}

#[test]
fn test_dechunkify_registry_value_chunks() {
    let chunk_content_sha256s = CHUNKS.with(|chunks: &RefCell<Chunks<MemoryImpl>>| {
        let mut chunks: RefMut<Chunks<MemoryImpl>> = chunks.borrow_mut();
        chunks.upsert_monolithic_blob(MEGA_BLOB.clone())
    });

    let value = high_capacity_registry_value::Content::LargeValueChunkKeys(LargeValueChunkKeys {
        chunk_content_sha256s,
    });

    CHUNKS.with(|chunks| {
        assert_eq!(
            dechunkify_registry_value(value, &*chunks.borrow()),
            Some(MEGA_BLOB.clone()),
        );
    });
}

#[test]
fn test_dechunkify_mutation_delete() {
    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let chunks = Chunks::init(memory);

    let mutation = HighCapacityRegistryMutation {
        mutation_type: MutationType::Delete as i32,
        key: b"this is key".to_vec(),
        content: None,
    };

    let result = dechunkify_prime_mutation_value(mutation, &chunks);

    assert_eq!(result, None);
}

#[test]
fn test_dechunkify_mutation_inline() {
    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let chunks = Chunks::init(memory);

    let mutation = HighCapacityRegistryMutation {
        mutation_type: MutationType::Insert as i32,
        key: b"this is key".to_vec(),
        content: Some(high_capacity_registry_mutation::Content::Value(
            b"Hello, world!".to_vec(),
        )),
    };

    let result = dechunkify_prime_mutation_value(mutation, &chunks);

    assert_eq!(result, Some(b"Hello, world!".to_vec()));
}

#[test]
fn test_dechunkify_mutation_chunked() {
    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let mut chunks = Chunks::init(memory);

    let chunk_content_sha256s = chunks.upsert_monolithic_blob(b"blobity blob".to_vec());
    assert_eq!(chunk_content_sha256s.len(), 1, "{chunk_content_sha256s:?}");

    let mutation = HighCapacityRegistryMutation {
        mutation_type: MutationType::Update as i32,
        key: b"this is key".to_vec(),
        content: Some(
            high_capacity_registry_mutation::Content::LargeValueChunkKeys(LargeValueChunkKeys {
                chunk_content_sha256s,
            }),
        ),
    };

    let result = dechunkify_prime_mutation_value(mutation, &chunks);

    assert_eq!(result, Some(b"blobity blob".to_vec()));
}

#[test]
fn test_dechunkify_mutation_no_content() {
    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let chunks = Chunks::init(memory);

    let mutation = HighCapacityRegistryMutation {
        mutation_type: MutationType::Upsert as i32,
        key: b"this is key".to_vec(),
        content: None,
    };

    let result = dechunkify_prime_mutation_value(mutation, &chunks);

    assert_eq!(result, Some(vec![]));
}

// This also indirectly tests dechunkify, because decode_high_capacity_registry_value calls that.
#[test]
fn test_decode_high_capacity_registry_value() {
    let small_value = Precondition {
        key: b"this is key".to_vec(),
        expected_version: 42,
    };
    let small_value_content = Some(high_capacity_registry_value::Content::Value(
        small_value.encode_to_vec(),
    ));

    let key = std::iter::repeat_n(b"hello ", 500_000)
        .flatten()
        .cloned()
        .collect::<Vec<u8>>();
    assert_eq!(key.len(), 3_000_000);

    let big_value = Precondition {
        key,
        expected_version: 43,
    };

    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let mut chunks = Chunks::init(memory);

    let chunk_content_sha256s: Vec<Vec<u8>> =
        chunks.upsert_monolithic_blob(big_value.encode_to_vec());
    let lens = chunk_content_sha256s
        .iter()
        .map(|hash| hash.len())
        .collect::<Vec<usize>>();
    assert_eq!(lens, vec![32, 32]);

    let big_value_content = Some(high_capacity_registry_value::Content::LargeValueChunkKeys(
        LargeValueChunkKeys {
            chunk_content_sha256s,
        },
    ));

    let mut version = 42_000; // This has no effect on the result, but is needed anyway.
    let empty_decoded_value = Some(Precondition::decode(&[][..]).unwrap());
    for (content, expected_output) in [
        (
            Some(high_capacity_registry_value::Content::DeletionMarker(true)),
            None,
        ),
        (small_value_content, Some(small_value)),
        (big_value_content, Some(big_value)),
        // These are degenerate cases, and are treated like empty value.
        (None, empty_decoded_value.clone()),
        (
            Some(high_capacity_registry_value::Content::DeletionMarker(false)),
            empty_decoded_value,
        ),
    ] {
        version += 1;
        let timestamp_nanoseconds = version + 123_000_000;

        let input = HighCapacityRegistryValue {
            version,
            content,
            timestamp_nanoseconds,
        };

        let observed_output: Option<Precondition> =
            decode_high_capacity_registry_value(&input, &chunks);

        assert_eq!(observed_output, expected_output);
    }
}

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

        _ => panic!("{upgraded_mutation:?}"),
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
