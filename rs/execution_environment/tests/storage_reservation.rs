use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::TakeCanisterSnapshotArgs;
use ic_management_canister_types_private::{self as ic00, CanisterInstallMode, EmptyBlob, Payload};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use ic_types::{CanisterId, Cycles, NumBytes};
use more_asserts::{assert_gt, assert_lt};

const T: u128 = 1_000_000_000_000;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;
const SUBNET_MEMORY_CAPACITY: u64 = 20 * GIB;

const PAGE_SIZE: usize = 64 * KIB as usize;

/// Upper bound for the default total memory usage of the universal canister
/// after deployment.
const UNIVERSAL_CANISTER_DEFAULT_MEMORY_USAGE: u64 = 10 * MIB;

#[test]
fn test_universal_canister_default_memory_usage() {
    let env = StateMachine::new();
    let canister_id = env.create_canister(None);
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
    )
    .unwrap();

    let actual_memory_usage = env
        .canister_status(canister_id)
        .unwrap()
        .unwrap()
        .memory_size();
    assert_lt!(
        actual_memory_usage.get(),
        UNIVERSAL_CANISTER_DEFAULT_MEMORY_USAGE
    );
}

fn setup(subnet_memory_capacity: u64, initial_cycles: Option<u128>) -> (StateMachine, CanisterId) {
    let subnet_type = SubnetType::Application;
    let subnet_config = SubnetConfig::new(subnet_type);
    let mut execution_config = ExecutionConfig {
        subnet_memory_capacity: NumBytes::new(subnet_memory_capacity),
        ..Default::default()
    };
    // We want storage reservation to trigger upon every large enough memory allocation
    // performed after deploying the universal canister.
    // Because a division by `scheduler_cores` is performed in
    // `SchedulerImpl::execute_canisters_in_inner_round` and
    // `subnet_memory_reservation` is subtracted in
    // `ExecutionEnvironment::subnet_available_memory`,
    // we need to set the subnet memory threshold as follows:
    let subnet_memory_threshold = execution_config.subnet_memory_reservation
        + NumBytes::new(UNIVERSAL_CANISTER_DEFAULT_MEMORY_USAGE)
            * subnet_config
                .scheduler_config
                .scheduler_cores
                .try_into()
                .unwrap();
    execution_config.subnet_memory_threshold = subnet_memory_threshold;
    let config = StateMachineConfig::new(subnet_config, execution_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .with_checkpoints_enabled(false)
        .build();
    let canister_id = env.create_canister_with_cycles(
        None,
        Cycles::from(initial_cycles.unwrap_or(100 * T)),
        None,
    );

    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
    )
    .unwrap();

    (env, canister_id)
}

fn reserved_balance(env: &StateMachine, canister_id: CanisterId) -> u128 {
    env.canister_status(canister_id)
        .unwrap()
        .unwrap()
        .reserved_cycles()
}

#[test]
fn test_storage_reservation_not_triggered() {
    // Baseline test: ensures that calling an update method alone does not trigger storage reservation.
    // This test is used as a reference for other tests that involve additional operations
    // causing storage reservation.
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);
    let initial_balance = env.cycle_balance(canister_id);

    let _ = env.execute_ingress(canister_id, "update", wasm().build());

    assert_lt!(env.cycle_balance(canister_id), initial_balance);
    assert_eq!(reserved_balance(&env, canister_id), 0); // No storage reservation.
}

#[test]
fn test_storage_reservation_triggered_in_update_by_stable_grow() {
    // Verifies that growing stable memory within the update method triggers storage reservation.
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);

    let _ = env.execute_ingress(canister_id, "update", wasm().stable_grow(1000).build());

    assert_gt!(reserved_balance(&env, canister_id), 0); // Storage reservation is triggered.
}

#[test]
fn test_storage_reservation_triggered_in_update_by_growing_wasm_memory() {
    // Verifies that growing Wasm memory within the update method triggers storage reservation.
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);

    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(&[0; 100 * PAGE_SIZE]).build(),
    );

    assert_gt!(reserved_balance(&env, canister_id), 0); // Storage reservation is triggered.
}

#[test]
fn test_storage_reservation_triggered_in_response() {
    // Verifies that growing stable memory during the response callback triggers storage reservation.
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);

    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .call_with_cycles(
                ic00::IC_00,
                ic00::Method::RawRand,
                call_args()
                    .other_side(EmptyBlob.encode())
                    .on_reply(wasm().stable_grow(1000)),
                Cycles::new(0),
            )
            .build(),
    );

    assert_gt!(reserved_balance(&env, canister_id), 0); // Storage reservation is triggered.
}

#[test]
fn test_storage_reservation_triggered_in_cleanup() {
    // Verifies that growing stable memory during the cleanup callback triggers storage reservation.
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);

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
                    .on_cleanup(wasm().stable_grow(1000)),
                Cycles::new(0),
            )
            .build(),
    );

    assert_gt!(reserved_balance(&env, canister_id), 0); // Storage reservation is triggered.
}

#[test]
fn test_storage_reservation_triggered_in_canister_snapshot_with_enough_cycles_available() {
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);

    // Grow memory in update call, should trigger storage reservation.
    let _ = env.execute_ingress(canister_id, "update", wasm().stable_grow(1000).build());
    let reserved_balance_before_snapshot = reserved_balance(&env, canister_id);
    assert_gt!(reserved_balance_before_snapshot, 0); // Storage reservation is triggered.

    // Take a snapshot to trigger more storage reservation.
    env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .unwrap();
    let reserved_balance_after_snapshot = reserved_balance(&env, canister_id);
    assert_gt!(
        reserved_balance_after_snapshot,
        reserved_balance_before_snapshot
    );
}

#[test]
fn test_storage_reservation_triggered_in_canister_snapshot_without_enough_cycles_available() {
    // This test verifies that a canister cannot take a snapshot if it does not have enough
    // cycles to cover the storage reservation triggered by the snapshot operation. The main
    // point of the test is to verify that the error message is informative and includes the
    // amount of cycles required to cover the storage reservation.
    //
    // The error message is produced by running the test once and checking the output. Calculating
    // the exact amounts is hard to do in advance. Note that any changes to cycles cost or how
    // the reservation mechanism works may require updating the error message in the test.

    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, Some(300_400_000_000));
    assert_eq!(reserved_balance(&env, canister_id), 0);

    // Grow memory in update call, should trigger storage reservation.
    let _ = env.execute_ingress(canister_id, "update", wasm().stable_grow(3000).build());
    let reserved_balance_before_snapshot = reserved_balance(&env, canister_id);
    assert_gt!(reserved_balance_before_snapshot, 0); // Storage reservation is triggered.

    // Take a snapshot to trigger more storage reservation. The canister does not have
    // enough cycles in its balance, so this should fail.
    let err = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .expect_err("Expected an error, but got Ok(_)");
    err.assert_contains(
        ErrorCode::InsufficientCyclesInMemoryGrow,
        "Canister cannot grow memory by",
    );

    // Match on a substring of the error message. Due to a difference in instructions consumed on
    // Mac vs Linux, we cannot match on the exact number of cycles but we only need to verify it's
    // a non-zero amount.
    let regex = regex::Regex::new("At least ([0-9_]+) additional cycles are required.").unwrap();
    let cycles_needed: u128 = regex
        .captures(err.description())
        .expect("Number regex match failed.")
        .get(1)
        .expect("No match for cycles needed.")
        .as_str()
        .replace("_", "")
        .parse()
        .expect("Failed to parse regex match for cycle count.");
    assert!(
        cycles_needed > 0,
        "The amount of cycles needed is {cycles_needed} which is not positive."
    );
}
