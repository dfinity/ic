use ic_base_types::PrincipalId;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_management_canister_types::{
    self as ic00, BoundedAllowedViewers, CanisterIdRecord, CanisterInstallMode, CanisterLogRecord,
    CanisterSettingsArgs, CanisterSettingsArgsBuilder, DataSize, EmptyBlob,
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    ErrorCode, StateMachine, StateMachineBuilder, StateMachineConfig, SubmitIngressError, UserError,
};
use ic_test_utilities::universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use ic_test_utilities_execution_environment::{get_reply, wat_canister, wat_fn};
use ic_test_utilities_metrics::{fetch_histogram_stats, fetch_histogram_vec_stats, labels};
use ic_types::{
    ingress::WasmResult, CanisterId, Cycles, NumBytes, NumInstructions,
    MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE,
};
use more_asserts::{assert_gt, assert_le, assert_lt};
use proptest::{prelude::ProptestConfig, prop_assume};
use std::time::{Duration, SystemTime};

// Change limits in order not to duplicate prod values.
const B: u64 = 1_000_000_000;
const MAX_INSTRUCTIONS_PER_ROUND: NumInstructions = NumInstructions::new(5 * B);
const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(20 * B);
const MAX_INSTRUCTIONS_PER_SLICE: NumInstructions = NumInstructions::new(B);

const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;
const TIB: u64 = GIB * 1024;
const SUBNET_MEMORY_THRESHOLD: u64 = 10_253 * MIB;
const SUBNET_MEMORY_CAPACITY: u64 = 20 * GIB;

fn setup(subnet_memory_threshold: u64, subnet_memory_capacity: u64) -> (StateMachine, CanisterId) {
    let subnet_type = SubnetType::Application;
    let mut execution_config = ExecutionConfig::default();
    execution_config.subnet_memory_threshold = NumBytes::new(subnet_memory_threshold);
    execution_config.subnet_memory_capacity = NumBytes::new(subnet_memory_capacity);
    let config = StateMachineConfig::new(SubnetConfig::new(subnet_type), execution_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
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

/*
$ ./ci/container/container-run.sh

$ bazel test //rs/execution_environment:execution_environment_misc_integration_tests/storage_reservation \
    --test_output=streamed \
    --test_arg=--nocapture \
    --test_arg=test_storage_reservation
*/
#[test]
fn test_storage_reservation_not_triggered() {
    let (env, canister_id) = setup(SUBNET_MEMORY_THRESHOLD, SUBNET_MEMORY_CAPACITY);
    let initial_balance = env.cycle_balance(canister_id);
    let initial_reserved_balance = env.reserved_balance(canister_id);

    let _ = env.execute_ingress(canister_id, "update", wasm().build());

    assert_lt!(env.cycle_balance(canister_id), initial_balance);
    assert_eq!(initial_reserved_balance, 0);
    assert_eq!(env.reserved_balance(canister_id), 0);
}

#[test]
fn test_storage_reservation_triggered_in_update() {
    let (env, canister_id) = setup(SUBNET_MEMORY_THRESHOLD, SUBNET_MEMORY_CAPACITY);
    let initial_balance = env.cycle_balance(canister_id);
    let initial_reserved_balance = env.reserved_balance(canister_id);

    let _ = env.execute_ingress(canister_id, "update", wasm().stable_grow(100).build());

    assert_lt!(env.cycle_balance(canister_id), initial_balance);
    assert_eq!(initial_reserved_balance, 0);
    assert_gt!(env.reserved_balance(canister_id), 0);
}

#[test]
fn test_storage_reservation_triggered_in_response() {
    let (env, canister_id) = setup(SUBNET_MEMORY_THRESHOLD, SUBNET_MEMORY_CAPACITY);
    let initial_balance = env.cycle_balance(canister_id);
    let initial_reserved_balance = env.reserved_balance(canister_id);

    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .call_with_cycles(
                ic00::IC_00,
                ic00::Method::RawRand,
                call_args()
                    .other_side(EmptyBlob.encode())
                    .on_reply(wasm().stable_grow(100)),
                Cycles::new(0),
            )
            .build(),
    );

    assert_lt!(env.cycle_balance(canister_id), initial_balance);
    assert_eq!(initial_reserved_balance, 0);
    assert_gt!(env.reserved_balance(canister_id), 0);
}

#[test]
fn test_storage_reservation_triggered_in_cleanup() {
    let (env, canister_id) = setup(SUBNET_MEMORY_THRESHOLD, SUBNET_MEMORY_CAPACITY);
    let initial_balance = env.cycle_balance(canister_id);
    let initial_reserved_balance = env.reserved_balance(canister_id);

    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .call_with_cycles(
                ic00::IC_00,
                ic00::Method::RawRand,
                call_args()
                    .other_side(EmptyBlob.encode())
                    .on_reply(wasm().trap_with_blob(b"on_reply trap"))
                    .on_cleanup(wasm().stable_grow(100)),
                Cycles::new(0),
            )
            .build(),
    );

    assert_lt!(env.cycle_balance(canister_id), initial_balance);
    assert_eq!(initial_reserved_balance, 0);
    assert_gt!(env.reserved_balance(canister_id), 0);
}
