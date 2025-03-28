use ic_nervous_system_chunks::Chunks;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        registry_get_chunk, setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};
use ic_registry_canister_api::Chunk;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{cell::RefCell, rc::Rc};

#[test]
fn test_get_chunk() {
    // Step 1: Prepare the world.
    let state_machine = state_machine_builder_for_nns_tests().build();

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // TODO(NNS1-3682): Populate chunks via mutation, not by directly
    // manipulating stable memory.
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
