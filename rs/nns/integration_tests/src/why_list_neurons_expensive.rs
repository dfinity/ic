use candid::{Decode, Encode};
use flate2::read::GzDecoder;
use ic_base_types::PrincipalId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::ListNeurons;
use ic_nns_test_utils::state_test_helpers::{list_neurons, unwrap_wasm_result, get_profiling};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use std::io::Read; // For flate2.

fn decompress_gz(buffer: &[u8]) -> Vec<u8> {
    let mut result = vec![];
    let mut decoder = GzDecoder::new(buffer);
    decoder.read_to_end(&mut result).unwrap();
    result
}

#[test]
fn test_why_list_neurons_expensive() {
    // Step 1: Prepare the world

    // Step 1.1: Load golden nns state into a StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Step 1.2: Custom governance WASMs

    // Step 1.2.1: Allocate stable memory for ic-wasm profiling. This happens during post_upgrade.
    println!("\nAllocating stable memory for profiling...\n");
    let governance_wasm_gz: Vec<u8> = canister_test::Project::cargo_bin_maybe_from_env(
        "governance-canister",
        /* features = */ &[],
    )
    .bytes();
    state_machine.upgrade_canister(
        GOVERNANCE_CANISTER_ID,
        governance_wasm_gz.clone(),
        vec![], // args
    )
    .unwrap();
    let (start_address, page_limit) = Decode!(
        &unwrap_wasm_result(
            state_machine.query(
                GOVERNANCE_CANISTER_ID,
                "where_ic_wasm_instrument_memory",
                Encode!().unwrap(),
            )
        ),
        u64,
        u64
    )
    .unwrap();
    println!("");
    println!("Result from ic_wasm_instrument_memory:");
    println!("  start_address = {}", start_address);
    println!("  page_limit = {}", page_limit);
    println!("");

    // Step 1.2.2: Enable ic-wasm profiling.
    let mut instrumented_governance_wasm = walrus::Module::from_buffer(&decompress_gz(&governance_wasm_gz))
        .expect("walrus cannot cope with our WASM.");
    ic_wasm::instrumentation::instrument(
        &mut instrumented_governance_wasm,
        ic_wasm::instrumentation::Config {
            trace_only_funcs: vec![],
            start_address: Some(i64::try_from(start_address).unwrap()),
            page_limit: Some(i32::try_from(page_limit).unwrap()),
        },
    )
    .unwrap();
    let instrumented_governance_wasm = instrumented_governance_wasm.emit_wasm();
    println!("\nInstalling instrumented governance WASM...\n");
    state_machine.upgrade_canister(
        GOVERNANCE_CANISTER_ID,
        instrumented_governance_wasm,
        vec![], // args
    )
    .unwrap();
    println!("\nDone installing instrumented governance WASM. Ready for fine-grained performance measurement 👍\n");

    // Step 2: Run the code under test.

    let caller = PrincipalId::new_user_test_id(42); // DO NOT MERGE
    list_neurons(
        &state_machine,
        caller,
        ListNeurons {
            include_neurons_readable_by_caller: true,
            include_public_neurons_in_full_neurons: Some(false),
            include_empty_neurons_readable_by_caller: Some(false),
            neuron_ids: vec![],
        },
    );

    // Step 3: Inspect results. In particular, generate flame graph.

    let profiling = get_profiling(&state_machine, GOVERNANCE_CANISTER_ID);
    println!("\n\nprofiling:\n{:#?}", profiling);

    panic!("\n\nHELLO WHY list_neurons EXPENSIVE\n\n");
}
