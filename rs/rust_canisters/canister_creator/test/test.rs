use canister_test::*;
use ic_state_machine_tests::StateMachine;

// This constant has been obtained empirically by running the tests.
// The old value of the const was 1_820_000.
// Since, we updated the default stack size for Wasm from 1MiB to 3MiB
// The new memory usage is 1_820_000 - 1_048_576 + 3_145_728 = 3_991_081
// After increasing the size of a canister history entry by 32B,
// and having a total of 1_001 canister creation entries and
// 1 canister code deployment entry (for the creator canister),
// the memory usage grew by extra 1_002 x 32 = 32_064B
// to 3_991_081 + 32_064 = 4_023_145.
const CANISTER_CREATOR_CANISTER_MEMORY_USAGE_BYTES: u64 = 4_023_145;

const HELLO_WORLD_WAT: &str = r#"
(module
    (func $hi)
    (memory $memory 32768)
    (export "memory" (memory $memory))
    (export "canister_query hi" (func $hi))
)"#;

fn install_canister_creator_canister(env: &StateMachine) -> CanisterId {
    let features = [];
    let wasm = Project::cargo_bin_maybe_from_env("canister_creator_canister", &features);
    env.install_canister_with_cycles(wasm.bytes(), vec![], None, Cycles::from(u128::MAX))
        .expect("Failed to install canister")
}

fn bytes_to_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

#[test]
fn creating_canisters_works() {
    let env = StateMachine::new();
    // Assert no canisters are running and the memory usage is zero.
    assert_eq!(env.num_running_canisters(), 0);
    assert_eq!(env.canister_memory_usage_bytes(), 0);

    // Install the canister creator canister, assert only one canister is running.
    let canister_creator_canister_id = install_canister_creator_canister(&env);
    assert_eq!(env.num_running_canisters(), 1);

    // Create canisters.
    let number_of_canisters: usize = 1_000;
    let result = env
        .execute_ingress(
            canister_creator_canister_id,
            "create_canisters",
            format!(r#"{number_of_canisters}"#).as_bytes().to_vec(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply("null".as_bytes().to_vec()));

    // Assert the number of running canisters is equal to the number of created canisters.
    assert_eq!(env.num_running_canisters(), 1_001);
    assert!(
        env.canister_memory_usage_bytes() <= CANISTER_CREATOR_CANISTER_MEMORY_USAGE_BYTES,
        "Actual: {} bytes",
        env.canister_memory_usage_bytes()
    );
}

#[test]
fn install_code_works() {
    let env = StateMachine::new();
    let canister_creator_canister_id = install_canister_creator_canister(&env);

    // Create canisters.
    let number_of_canisters: usize = 1_000;
    let result = env
        .execute_ingress(
            canister_creator_canister_id,
            "create_canisters",
            format!(r#"{number_of_canisters}"#).as_bytes().to_vec(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply("null".as_bytes().to_vec()));
    assert_eq!(env.num_running_canisters(), 1_001);
    assert!(
        env.canister_memory_usage_bytes() <= CANISTER_CREATOR_CANISTER_MEMORY_USAGE_BYTES,
        "Actual: {} bytes",
        env.canister_memory_usage_bytes()
    );

    // Install code.
    let wasm_module = wat::parse_str(HELLO_WORLD_WAT).expect("Failed to parse WAT into bytecode");
    let arg: Vec<u8> = vec![0u8; 10];
    let result = env
        .execute_ingress(
            canister_creator_canister_id,
            "install_code",
            format!(
                r#"[[{}],[{}]]"#,
                bytes_to_str(&wasm_module),
                bytes_to_str(&arg)
            )
            .as_bytes()
            .to_vec(),
        )
        .expect("Failed to execute ingress");
    assert_eq!(result, WasmResult::Reply("null".as_bytes().to_vec()));

    // Assert there are 1_001 canisters running with the memory usage below the
    // subnet storage capacity, which is currently 2 TiB
    assert_eq!(env.num_running_canisters(), 1_001);
    assert!(
        env.canister_memory_usage_bytes() < 2 * 1024 * 1024 * 1024 * 1024,
        "Actual: {} bytes",
        env.canister_memory_usage_bytes()
    );
}
