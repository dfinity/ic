use canister_test::CanisterInstallMode;
use ic_base_types::PrincipalId;
use ic_nervous_system_chunks::{
    Chunks,
    test_data::{MEGA_BLOB, MEGA_BLOB_CHUNK_KEYS},
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_test_utils::{
    common::{NnsInitPayloadsBuilder, build_test_registry_wasm},
    state_test_helpers::{
        registry_get_chunk, registry_get_value, registry_high_capacity_get_changes_since,
        registry_latest_version, registry_mutate_test_high_capacity_records, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use ic_registry_canister_api::{Chunk, mutate_test_high_capacity_records};
use ic_registry_transport::pb::v1::{
    HighCapacityRegistryDelta, HighCapacityRegistryGetChangesSinceResponse,
    HighCapacityRegistryGetValueResponse, HighCapacityRegistryValue, LargeValueChunkKeys,
    RegistryError, high_capacity_registry_get_value_response, high_capacity_registry_value,
    registry_error,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_state_machine_tests::StateMachine;
use pretty_assertions::assert_eq;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::{cell::RefCell, rc::Rc, time::SystemTime};

fn get_state_machine_time_nanoseconds(machine: &StateMachine) -> u64 {
    machine
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
}

macro_rules! assert_timestamp {
    ($lower:expr_2021, $timestamp:expr_2021, $upper:expr_2021) => {
        if !($lower <= $timestamp && $timestamp <= $upper) {
            panic!(
                "Timestamp assertion doesn't hold. Expected {} to be within range: [{}, {}]",
                stringify!($timestamp),
                stringify!($lower),
                stringify!($upper)
            );
        }
    };
}

#[test]
fn test_large_records() {
    // Step 1: Prepare the world.
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let original_version = registry_latest_version(&state_machine).unwrap();

    // Step 2: Run the code that is under test.

    let before_new_version = get_state_machine_time_nanoseconds(&state_machine);
    let new_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: 42,
            operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
        },
    );
    let after_new_version = get_state_machine_time_nanoseconds(&state_machine);

    // Step 3: Verify result(s).

    // Step 3.1: Version has advanced by 1. (This is not as interesting as the next thing(s).)
    assert_eq!(new_version, original_version + 1);

    // Step 3.2: Inspect value associated with "daniel_wong_42".
    let get_value_response = registry_get_value(&state_machine, b"daniel_wong_42");
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
            timestamp_nanoseconds: get_value_response.timestamp_nanoseconds,
            error: None,
        },
    );
    assert_timestamp!(
        before_new_version,
        get_value_response.timestamp_nanoseconds,
        after_new_version
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
        _ => panic!("{get_value_response:#?}"),
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
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let original_version = registry_latest_version(&state_machine).unwrap();

    // Step 2: Run the code that is under test. Similar to previous test, but we
    // do two more mutations: UpsertSmall, and Delete.

    const RED_HERRING_ID: u64 = 999;

    let before_prior_small_version = get_state_machine_time_nanoseconds(&state_machine);
    let prior_small_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: 42,
            operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
        },
    );
    let after_prior_small_version = get_state_machine_time_nanoseconds(&state_machine);
    let prior_small_response = registry_get_value(&state_machine, b"daniel_wong_42");
    assert_timestamp!(
        before_prior_small_version,
        prior_small_response.timestamp_nanoseconds,
        after_prior_small_version
    );

    let before_small_version = get_state_machine_time_nanoseconds(&state_machine);
    let small_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: 42,
            operation: mutate_test_high_capacity_records::Operation::UpsertSmall,
        },
    );
    let after_small_version = get_state_machine_time_nanoseconds(&state_machine);

    let before_prior_red_herring_version = get_state_machine_time_nanoseconds(&state_machine);
    let prior_red_herring_version = registry_mutate_test_high_capacity_records(
        &state_machine,
        mutate_test_high_capacity_records::Request {
            id: RED_HERRING_ID,
            operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
        },
    );
    let after_prior_red_herring_version = get_state_machine_time_nanoseconds(&state_machine);
    let prior_red_herring_get_value_response =
        registry_get_value(&state_machine, b"daniel_wong_999");

    assert_timestamp!(
        before_prior_red_herring_version,
        prior_red_herring_get_value_response.timestamp_nanoseconds,
        after_prior_red_herring_version
    );

    let small_get_value_response = registry_get_value(&state_machine, b"daniel_wong_42");
    assert_timestamp!(
        before_small_version,
        small_get_value_response.timestamp_nanoseconds,
        after_small_version
    );

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
            timestamp_nanoseconds: small_get_value_response.timestamp_nanoseconds,
            error: None,
        },
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
            timestamp_nanoseconds: 0,
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
            timestamp_nanoseconds: red_herring_get_value_response.timestamp_nanoseconds,
            error: None,
        },
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
                            timestamp_nanoseconds: changes.deltas[0].values[0]
                                .timestamp_nanoseconds,
                        },
                        HighCapacityRegistryValue {
                            version: small_version,
                            content: Some(high_capacity_registry_value::Content::Value(
                                b"small value".to_vec(),
                            )),
                            // Will be tested later.
                            timestamp_nanoseconds: small_get_value_response.timestamp_nanoseconds,
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
                            timestamp_nanoseconds: prior_small_response.timestamp_nanoseconds,
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
                            timestamp_nanoseconds: red_herring_get_value_response
                                .timestamp_nanoseconds,
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
                            timestamp_nanoseconds: prior_red_herring_get_value_response
                                .timestamp_nanoseconds,
                        },
                    ],
                },
            ],
            version: last_version,
            error: None,
        },
    );
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
        _ => panic!("{garbage_response:#?}"),
    };
    for key_word in ["no chunk", "sha256"] {
        assert!(err.to_lowercase().contains(key_word), "{err:?}");
    }
}
