use canister_test::CanisterInstallMode;
use ic_base_types::PrincipalId;
use ic_nervous_system_chunks::{
    test_data::{MEGA_BLOB, MEGA_BLOB_CHUNK_KEYS},
    Chunks,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_handler_root::now_nanoseconds;
use ic_nns_test_utils::{
    common::{build_test_registry_wasm, NnsInitPayloadsBuilder},
    state_test_helpers::{
        registry_get_chunk, registry_get_value, registry_high_capacity_get_changes_since,
        registry_latest_version, registry_mutate_test_high_capacity_records, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use ic_registry_canister_api::{mutate_test_high_capacity_records, Chunk};
use ic_registry_transport::pb::v1::{
    high_capacity_registry_get_value_response, high_capacity_registry_value, registry_error,
    HighCapacityRegistryDelta, HighCapacityRegistryGetChangesSinceResponse,
    HighCapacityRegistryGetValueResponse, HighCapacityRegistryValue, LargeValueChunkKeys,
    RegistryError,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use pretty_assertions::assert_eq;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{cell::RefCell, rc::Rc};

#[test]
fn test_large_records() {
    let test_beginning_timestamp = now_nanoseconds();
    // Step 1: Prepare the world.
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let original_version = registry_latest_version(&state_machine).unwrap();

    // Step 2: Run the code that is under test.

    let new_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: 42,
            operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
        },
    );

    // Step 3: Verify result(s).

    // Step 3.1: Version has advanced by 1. (This is not as interesting as the next thing(s).)
    assert_eq!(new_version, original_version + 1);

    // Step 3.2: Inspect value associated with "daniel_wong_42".
    let get_value_response = registry_get_value(&state_machine, b"daniel_wong_42");
    let after_mutation_timestamp = now_nanoseconds();
    assert_eq!(
        get_value_response,
        HighCapacityRegistryGetValueResponse {
            content: Some(
                high_capacity_registry_get_value_response::Content::LargeValueChunkKeys(
                    LargeValueChunkKeys {
                        chunk_content_sha256s: MEGA_BLOB_CHUNK_KEYS.clone(),
                    }
                )
            ),
            version: new_version,
            // Since the assertion expects the exact equality we are
            // unable to test timestamps here.
            timestamp_seconds: get_value_response.timestamp_seconds,
            error: None,
        },
    );
    // Testing that timestamps are in expected range.
    assert!(
        test_beginning_timestamp <= get_value_response.timestamp_seconds
            && get_value_response.timestamp_seconds <= after_mutation_timestamp,
        "Expected the timestamp of the mutation {} to be in range: [{}, {}]",
        get_value_response.timestamp_seconds,
        test_beginning_timestamp,
        after_mutation_timestamp
    );

    // Step 3.3: Reconstituted blob, and inspect it.
    let chunk_content_sha256s = match &get_value_response.content {
        Some(high_capacity_registry_get_value_response::Content::LargeValueChunkKeys(
            LargeValueChunkKeys {
                chunk_content_sha256s,
            },
        )) => chunk_content_sha256s,
        // Because of the assert_eq directly before, this is unreachable (but
        // rustc doesn't know that).
        _ => panic!("{:#?}", get_value_response),
    };
    let reconstructed_big_monolithic_blob = chunk_content_sha256s
        .iter()
        .flat_map(|chunk_key| -> Vec<u8> {
            let Chunk { content } = registry_get_chunk(&state_machine, chunk_key).unwrap();
            content.unwrap()
        })
        .collect::<Vec<u8>>();
    // assert_eq is not used here, because it would be very spammy.
    assert!(
        reconstructed_big_monolithic_blob == *MEGA_BLOB,
        "len = {} vs. {}",
        reconstructed_big_monolithic_blob.len(),
        MEGA_BLOB.len(),
    );
}

#[test]
fn test_mutate_test_high_capacity_records() {
    // Step 1: Prepare the world.
    let test_begining_timestamp = now_nanoseconds();
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    let after_initialization_timestamp = now_nanoseconds();

    let original_version = registry_latest_version(&state_machine).unwrap();

    // Step 2: Run the code that is under test. Similar to previous test, but we
    // do two more mutations: UpsertSmall, and Delete.

    const RED_HERRING_ID: u64 = 999;

    let prior_small_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: 42,
            operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
        },
    );
    let prior_small_response = registry_get_value(&state_machine, b"daniel_wong_42");

    let small_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: 42,
            operation: mutate_test_high_capacity_records::Operation::UpsertSmall,
        },
    );
    let prior_red_herring_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: RED_HERRING_ID,
            operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
        },
    );
    let prior_red_herring_get_value_response =
        registry_get_value(&state_machine, b"daniel_wong_999");

    let small_get_value_response = registry_get_value(&state_machine, b"daniel_wong_42");

    let final_red_herring_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: RED_HERRING_ID,
            operation: mutate_test_high_capacity_records::Operation::UpsertSmall,
        },
    );
    let delete_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: 42,
            operation: mutate_test_high_capacity_records::Operation::Delete,
        },
    );
    let last_version = delete_version;

    let delete_get_value_response = registry_get_value(&state_machine, b"daniel_wong_42");

    // Step 3: Inspect result(s).

    assert_eq!(small_version, original_version + 2);
    assert_eq!(delete_version, original_version + 5);

    assert_eq!(
        small_get_value_response,
        HighCapacityRegistryGetValueResponse {
            content: Some(high_capacity_registry_get_value_response::Content::Value(
                b"small value".to_vec()
            )),
            version: small_version,
            // Will be checked later.
            timestamp_seconds: small_get_value_response.timestamp_seconds,
            error: None,
        },
    );
    // Testing that the timestamp is within the expected range.
    assert!(
        test_begining_timestamp <= small_get_value_response.timestamp_seconds
            && small_get_value_response.timestamp_seconds <= after_initialization_timestamp,
        "Expected small timestamp {} to be within the range: [{}, {}]",
        small_get_value_response.timestamp_seconds,
        test_begining_timestamp,
        after_initialization_timestamp
    );

    assert_eq!(
        delete_get_value_response,
        HighCapacityRegistryGetValueResponse {
            error: Some(RegistryError {
                code: registry_error::Code::KeyNotPresent as i32,
                reason: "".to_string(),
                key: b"daniel_wong_42".to_vec(),
            }),
            content: None,
            version: delete_version,
            timestamp_seconds: 0,
        },
    );

    let red_herring_get_value_response = registry_get_value(&state_machine, b"daniel_wong_999");
    assert_eq!(
        red_herring_get_value_response,
        HighCapacityRegistryGetValueResponse {
            content: Some(high_capacity_registry_get_value_response::Content::Value(
                b"small value".to_vec()
            )),
            version: final_red_herring_version,
            // Will be checked later.
            timestamp_seconds: red_herring_get_value_response.timestamp_seconds,
            error: None,
        },
    );
    // Testing that the timestamp is within the expected range.
    assert!(
        test_begining_timestamp <= red_herring_get_value_response.timestamp_seconds
            && red_herring_get_value_response.timestamp_seconds <= after_initialization_timestamp,
        "Expected red herring timestamp {} to be within the range: [{}, {}]",
        red_herring_get_value_response.timestamp_seconds,
        test_begining_timestamp,
        after_initialization_timestamp
    );

    // Step 3.2: Verify get_change_since.

    let changes = registry_high_capacity_get_changes_since(
        &state_machine,
        PrincipalId::new_user_test_id(42),
        original_version, // version
    );
    assert_eq!(
        changes,
        HighCapacityRegistryGetChangesSinceResponse {
            deltas: vec![
                HighCapacityRegistryDelta {
                    key: b"daniel_wong_42".to_vec(),
                    values: vec![
                        HighCapacityRegistryValue {
                            version: delete_version,
                            content: Some(high_capacity_registry_value::Content::DeletionMarker(
                                true
                            )),
                            // Will be tested later.
                            timestamp_seconds: changes.deltas[0].values[0].timestamp_seconds,
                        },
                        HighCapacityRegistryValue {
                            version: small_version,
                            content: Some(high_capacity_registry_value::Content::Value(
                                b"small value".to_vec(),
                            )),
                            // Will be tested later.
                            timestamp_seconds: small_get_value_response.timestamp_seconds,
                        },
                        HighCapacityRegistryValue {
                            version: prior_small_version,
                            content: Some(
                                high_capacity_registry_value::Content::LargeValueChunkKeys(
                                    LargeValueChunkKeys {
                                        chunk_content_sha256s: MEGA_BLOB_CHUNK_KEYS.clone(),
                                    }
                                )
                            ),
                            // Will be tested later.
                            timestamp_seconds: prior_small_response.timestamp_seconds,
                        },
                    ],
                },
                HighCapacityRegistryDelta {
                    key: b"daniel_wong_999".to_vec(),
                    values: vec![
                        HighCapacityRegistryValue {
                            version: final_red_herring_version,
                            content: Some(high_capacity_registry_value::Content::Value(
                                b"small value".to_vec(),
                            )),
                            // Will be tested later.
                            timestamp_seconds: red_herring_get_value_response.timestamp_seconds,
                        },
                        HighCapacityRegistryValue {
                            version: prior_red_herring_version,
                            content: Some(
                                high_capacity_registry_value::Content::LargeValueChunkKeys(
                                    LargeValueChunkKeys {
                                        chunk_content_sha256s: MEGA_BLOB_CHUNK_KEYS.clone(),
                                    }
                                )
                            ),
                            // Will be tested later.
                            timestamp_seconds: prior_red_herring_get_value_response
                                .timestamp_seconds,
                        },
                    ],
                },
            ],
            version: last_version,
            error: None,
        },
    );

    for delta in changes.deltas {
        for (i, value) in delta.values.into_iter().enumerate() {
            assert!(
                test_begining_timestamp <= value.timestamp_seconds
                    && value.timestamp_seconds <= after_initialization_timestamp,
                "Expected {}. value in delta belonging to the key {}\\
                to be within range: [{}, {}], but was {}",
                i,
                std::str::from_utf8(&delta.key).unwrap(),
                test_begining_timestamp,
                after_initialization_timestamp,
                value.timestamp_seconds
            );
        }
    }
}

#[test]
fn test_get_chunk() {
    // Step 1: Prepare the world.
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let stable_memory = Rc::new(RefCell::new(vec![]));
    let memory_manager = MemoryManager::init(Rc::clone(&stable_memory));
    let chunks_memory = memory_manager.get(MemoryId::new(1));
    let mut chunks = Chunks::init(chunks_memory);

    let mut chunk_keys = chunks.upsert_monolithic_blob(b"Hello, world!".to_vec());
    let small_chunk_key = chunk_keys.pop().unwrap();
    // Because the monolithic blob is small.
    assert_eq!(chunk_keys, Vec::<Vec<u8>>::new());

    let big_len = 5_123_456;
    let big_monolithic_blob = StdRng::seed_from_u64(42)
        .sample_iter(rand::distributions::Standard)
        .take(big_len)
        .collect::<Vec<u8>>();
    let original_big_monolithic_blob = big_monolithic_blob.clone();
    let big_chunk_keys = chunks.upsert_monolithic_blob(big_monolithic_blob);
    assert_eq!(big_chunk_keys.len(), 3, "{:?}", big_chunk_keys);

    // It should be possible to avoid clone, but I cannot figure out how to
    // convert stable_memory to its inner Vec.
    let stable_memory = <RefCell<std::vec::Vec<u8>> as Clone>::clone(&stable_memory).into_inner();
    state_machine.set_stable_memory(REGISTRY_CANISTER_ID, &stable_memory);
    state_machine
        .install_wasm_in_mode(
            REGISTRY_CANISTER_ID,
            CanisterInstallMode::Upgrade,
            build_test_registry_wasm().bytes(),
            vec![],
        )
        .unwrap();

    // Step 2: Call code under test (i.e. get_chunk).
    let small_response = registry_get_chunk(&state_machine, &small_chunk_key);

    let big_responses = big_chunk_keys
        .iter()
        .map(|big_chunk_key| registry_get_chunk(&state_machine, big_chunk_key))
        .collect::<Vec<_>>();

    let garbage_response = registry_get_chunk(&state_machine, b"garbage".as_ref());

    // Step 3: Verify result(s).
    assert_eq!(
        small_response,
        Ok(Chunk {
            content: Some(b"Hello, world!".to_vec())
        })
    );

    assert_eq!(big_responses.len(), 3, "{:?}", big_responses);
    let reconstructed_big_monolithic_blob = big_responses
        .into_iter()
        .flat_map(|big_response| -> Vec<u8> {
            let Chunk { content } = big_response.unwrap();
            content.unwrap()
        })
        .collect::<Vec<u8>>();
    assert_eq!(
        reconstructed_big_monolithic_blob[0..25],
        original_big_monolithic_blob[0..25]
    );
    assert_eq!(
        reconstructed_big_monolithic_blob[big_len - 25..big_len],
        original_big_monolithic_blob[big_len - 25..big_len]
    );
    assert_eq!(reconstructed_big_monolithic_blob.len(), big_len);
    // assert_eq is not used here, because we do not want 5 MB of spam to be
    // dumped into the terminal.
    assert!(reconstructed_big_monolithic_blob == original_big_monolithic_blob);

    let err: String = match garbage_response {
        Err(ok) => ok,
        _ => panic!("{:#?}", garbage_response),
    };
    for key_word in ["no chunk", "sha256"] {
        assert!(err.to_lowercase().contains(key_word), "{:?}", err);
    }
}
