use ic_base_types::PrincipalId;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfig;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::TakeCanisterSnapshotArgs;
use ic_management_canister_types_private::{
    self as ic00, CanisterInstallMode, CanisterSettingsArgsBuilder, CanisterSnapshotDataOffset,
    EmptyBlob, LoadCanisterSnapshotArgs, Payload, ReadCanisterSnapshotMetadataArgs,
    UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs,
};
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
        canister_snapshot_download: FlagStatus::Enabled,
        canister_snapshot_upload: FlagStatus::Enabled,
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
fn test_storage_reservation_not_triggered_with_reserved_memory_allocation() {
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);

    // Trigger storage reservation.
    env.execute_ingress(
        canister_id,
        "update",
        wasm().stable_grow(1000).reply().build(),
    )
    .unwrap();

    let initial_reserved_balance = reserved_balance(&env, canister_id);
    assert_gt!(initial_reserved_balance, 0); // Storage reservation is triggered.

    // Set the memory allocation to be equal to the current memory usage.
    let status = env.canister_status(canister_id).unwrap().unwrap();
    let initial_memory_usage = status.memory_size().get();

    let settings = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(initial_memory_usage)
        .build();
    env.update_settings(&canister_id, settings).unwrap();

    // Increase the memory usage by updating controllers which increases the canister history memory usage.
    let settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![PrincipalId::new_anonymous()])
        .build();
    env.update_settings(&canister_id, settings).unwrap();

    // Check that the memory usage increased.
    let status = env.canister_status(canister_id).unwrap().unwrap();
    let memory_usage = status.memory_size().get();
    assert_gt!(memory_usage, initial_memory_usage);

    // Increase the memory usage again by updating controllers which increases the canister history memory usage.
    let settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![PrincipalId::new_anonymous()])
        .build();
    env.update_settings(&canister_id, settings).unwrap();

    // Check that the memory usage increased again.
    let status = env.canister_status(canister_id).unwrap().unwrap();
    let final_memory_usage = status.memory_size().get();
    assert_gt!(final_memory_usage, memory_usage);

    assert_eq!(
        reserved_balance(&env, canister_id),
        initial_reserved_balance
    ); // No extra storage reservation while we have reserved memory allocation.
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
fn test_storage_reservation_triggered_in_take_canister_snapshot_with_enough_cycles_available() {
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
fn test_storage_reservation_triggered_in_take_canister_snapshot_without_enough_cycles_available() {
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

#[test]
fn test_storage_reservation_triggered_in_upload_and_load_canister_snapshot_with_enough_cycles_available(
) {
    let (env, canister_id) = setup(SUBNET_MEMORY_CAPACITY, None);
    assert_eq!(reserved_balance(&env, canister_id), 0);

    // Take a canister snapshot to get valid snapshot metadata to upload later.
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .unwrap()
        .snapshot_id();
    // The canister memory usage is low so far => the snapshot size is also low => no storage reservation is triggered.
    assert_eq!(reserved_balance(&env, canister_id), 0);

    let metadata = env
        .read_canister_snapshot_metadata(&ReadCanisterSnapshotMetadataArgs {
            canister_id: canister_id.get(),
            snapshot_id,
        })
        .unwrap();
    // Only reading data => no storage reservation triggered.
    assert_eq!(reserved_balance(&env, canister_id), 0);

    // Create a new canister snapshot by uploading metadata specifying large canister stable memory.
    let new_snapshot_id = env
        .upload_canister_snapshot_metadata(&UploadCanisterSnapshotMetadataArgs {
            canister_id: canister_id.get(),
            replace_snapshot: None,
            wasm_module_size: metadata.wasm_module_size,
            exported_globals: metadata.exported_globals,
            wasm_memory_size: metadata.wasm_memory_size,
            stable_memory_size: (1000 * PAGE_SIZE) as u64,
            certified_data: metadata.certified_data,
            global_timer: metadata.global_timer,
            on_low_wasm_memory_hook_status: metadata.on_low_wasm_memory_hook_status,
        })
        .unwrap()
        .get_snapshot_id();

    let reserved_balance_after_uploading_snapshot = reserved_balance(&env, canister_id);
    assert_gt!(reserved_balance_after_uploading_snapshot, 0); // Storage reservation is now triggered.

    // We upload the universal canister WASM to get a valid snapshot that can be loaded.
    env.upload_canister_snapshot_data(&UploadCanisterSnapshotDataArgs {
        canister_id: canister_id.get(),
        snapshot_id: new_snapshot_id,
        kind: CanisterSnapshotDataOffset::WasmModule { offset: 0 },
        chunk: UNIVERSAL_CANISTER_WASM.to_vec(),
    })
    .unwrap();
    // Uploading snapshot data does not trigger storage reservation anymore
    // because memory for the snapshot was already reserved when uploading snapshot metadata.
    assert_eq!(
        reserved_balance(&env, canister_id),
        reserved_balance_after_uploading_snapshot
    );

    // Load a snapshot to trigger more storage reservation.
    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id,
        new_snapshot_id,
        None,
    ))
    .unwrap();
    let reserved_balance_after_loading_snapshot = reserved_balance(&env, canister_id);
    assert_gt!(
        reserved_balance_after_loading_snapshot,
        reserved_balance_after_uploading_snapshot,
    );
}

fn instruction_and_reserved_cycles_exceed_canister_balance_setup() -> (StateMachine, CanisterId) {
    // Create application subnet `StateMachine`.
    let subnet_type = SubnetType::Application;
    let subnet_config = SubnetConfig::new(subnet_type);
    let execution_config = ExecutionConfig::default();
    let config = StateMachineConfig::new(subnet_config, execution_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .build();

    // Create multiple universal canisters:
    // - the first few (`fillup_canisters`) are used to trigger storage reservation on the subnet;
    // - the last one (`test_canister`) is used to test the case of instruction and reserved cycles exceeding the canister balance.
    let initial_cycles = 10 * T;
    let settings = CanisterSettingsArgsBuilder::new()
        .with_reserved_cycles_limit(initial_cycles)
        .with_freezing_threshold(0)
        .build();
    let mut fillup_canisters = vec![];
    for _ in 0..2 {
        let canister_id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.to_vec(),
                vec![],
                Some(settings.clone()),
                initial_cycles.into(),
            )
            .unwrap();
        fillup_canisters.push(canister_id);
    }
    let test_canister = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(settings),
            initial_cycles.into(),
        )
        .unwrap();

    // Keep growing stable memory of the fillup canisters by 10 GiB (`10 << 14` WASM pages) at a time until cycles start getting reserved.
    let mut iterations = 0;
    loop {
        for canister_id in &fillup_canisters {
            env.execute_ingress(
                *canister_id,
                "update",
                wasm().stable64_grow(10 << 14).reply().build(),
            )
            .unwrap();
        }
        if fillup_canisters
            .iter()
            .any(|canister_id| reserved_balance(&env, *canister_id) != 0)
        {
            break;
        }
        iterations += 1;
        if iterations > 100 {
            panic!("Could not trigger storage reservation after 100 steps - maybe the storage reservation threshold increased and more fillup canisters are needed?");
        }
    }

    // Grow stable memory of the test canister by 10 GiB so that taking its snapshot grows memory usage significantly
    // and many cycles are reserved (but still much less cycles are reserved than taking a snapshot of a fillup canister).
    env.execute_ingress(
        test_canister,
        "update",
        wasm().stable64_grow(10 << 14).reply().build(),
    )
    .unwrap();

    (env, test_canister)
}

/// The amount of reserved cycles for storage when taking a snapshot in the test `instruction_and_reserved_cycles_exceed_canister_balance`.
/// This value should be much more than 40B (instruction cycles prepayment as the prepayment amount can't be burned
/// and we burn cycles to reach the target cycles balance).
fn reserved_cycles_for_snapshot() -> u128 {
    let (env, canister_id) = instruction_and_reserved_cycles_exceed_canister_balance_setup();

    let before = reserved_balance(&env, canister_id);
    env.take_canister_snapshot(TakeCanisterSnapshotArgs {
        canister_id: canister_id.get(),
        replace_snapshot: None,
    })
    .unwrap();
    let after = reserved_balance(&env, canister_id);

    let reserved_by_snapshot = after - before;
    assert!(reserved_by_snapshot >= 40_000_000_000);
    reserved_by_snapshot
}

#[test]
fn instruction_and_reserved_cycles_exceed_canister_balance() {
    let (env, canister_id) = instruction_and_reserved_cycles_exceed_canister_balance_setup();

    // Burn cycles of the canister so that only
    // `reserved_cycles_for_snapshot()` + 1B (slack; less than the base fee for a snapshot) are remaining.
    let status = env.canister_status(canister_id).unwrap().unwrap();
    let balance = status.cycles();
    let to_burn = balance
        .checked_sub(reserved_cycles_for_snapshot() + 1_000_000_000)
        .unwrap();
    env.execute_ingress(
        canister_id,
        "update",
        wasm().cycles_burn128(to_burn).reply().build(),
    )
    .unwrap();

    let err = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs {
            canister_id: canister_id.get(),
            replace_snapshot: None,
        })
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}
