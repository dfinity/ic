use ic_management_canister_types_private::CanisterInstallMode;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, UserError, WasmResult};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_types::{CanisterId, Cycles};

const REPLICATED_EXECUTION: [u8; 4] = [1, 0, 0, 0];
const NON_REPLICATED_EXECUTION: [u8; 4] = [0, 0, 0, 0];

fn setup() -> (StateMachine, CanisterId) {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_checkpoints_enabled(false)
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::from(301_000_000_000_u128), None);
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
    )
    .unwrap();

    (env, canister_id)
}

pub fn expect_reply(result: Result<WasmResult, UserError>) -> Vec<u8> {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(bytes) => bytes,
            WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
        },
        Err(err) => panic!("Unexpected error: {err}"),
    }
}

#[test]
fn test_in_replicated_execution_for_update_returns_1() {
    // Arrange.
    let (env, canister_id) = setup();
    // Act.
    let result = env.execute_ingress(
        canister_id,
        "update",
        wasm().in_replicated_execution().reply_int().build(),
    );
    // Assert.
    assert_eq!(expect_reply(result), REPLICATED_EXECUTION);
}

#[test]
fn test_in_replicated_execution_for_replicated_query_returns_1() {
    // Arrange.
    let (env, canister_id) = setup();
    // Act.
    let result = env.execute_ingress(
        canister_id,
        "query",
        wasm().in_replicated_execution().reply_int().build(),
    );
    // Assert.
    assert_eq!(expect_reply(result), REPLICATED_EXECUTION);
}

#[test]
fn test_in_replicated_execution_for_query_returns_0() {
    // Arrange.
    let (env, canister_id) = setup();
    // Act.
    let result = env.query(
        canister_id,
        "query",
        wasm().in_replicated_execution().reply_int().build(),
    );
    // Assert.
    assert_eq!(expect_reply(result), NON_REPLICATED_EXECUTION);
}

#[test]
fn test_in_replicated_execution_for_composite_query_returns_0() {
    // Arrange.
    let (env, canister_id) = setup();
    // Act.
    let result = env.query(
        canister_id,
        "composite_query",
        wasm().in_replicated_execution().reply_int().build(),
    );
    // Assert.
    assert_eq!(expect_reply(result), NON_REPLICATED_EXECUTION);
}
