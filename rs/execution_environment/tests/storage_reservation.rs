use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_management_canister_types::{self as ic00, CanisterInstallMode, EmptyBlob, Payload};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use ic_types::{CanisterId, Cycles, NumBytes};
use more_asserts::{assert_gt, assert_lt};

const T: u128 = 1_000_000_000_000;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;
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
    let canister_id = env.create_canister_with_cycles(None, Cycles::from(100 * T), None);

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
    assert_eq!(env.reserved_balance(canister_id), 0);
    let initial_balance = env.cycle_balance(canister_id);

    let _ = env.execute_ingress(canister_id, "update", wasm().build());

    assert_lt!(env.cycle_balance(canister_id), initial_balance);
    assert_eq!(env.reserved_balance(canister_id), 0);
}

#[test]
fn test_storage_reservation_triggered_in_update() {
    let (env, canister_id) = setup(SUBNET_MEMORY_THRESHOLD, SUBNET_MEMORY_CAPACITY);
    assert_eq!(env.reserved_balance(canister_id), 0);

    let _ = env.execute_ingress(canister_id, "update", wasm().stable_grow(100).build());

    assert_gt!(env.reserved_balance(canister_id), 0);
}

#[test]
fn test_storage_reservation_triggered_in_response() {
    let (env, canister_id) = setup(SUBNET_MEMORY_THRESHOLD, SUBNET_MEMORY_CAPACITY);
    assert_eq!(env.reserved_balance(canister_id), 0);

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

    assert_gt!(env.reserved_balance(canister_id), 0);
}

#[test]
fn test_storage_reservation_triggered_in_cleanup() {
    let (env, canister_id) = setup(SUBNET_MEMORY_THRESHOLD, SUBNET_MEMORY_CAPACITY);
    assert_eq!(env.reserved_balance(canister_id), 0);

    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .call_with_cycles(
                ic00::IC_00,
                ic00::Method::RawRand,
                call_args()
                    .other_side(EmptyBlob.encode())
                    .on_reply(wasm().trap())
                    .on_cleanup(wasm().stable_grow(100)),
                Cycles::new(0),
            )
            .build(),
    );

    assert_gt!(env.reserved_balance(canister_id), 0);
}
