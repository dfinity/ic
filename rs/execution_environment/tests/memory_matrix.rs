use ic_base_types::{CanisterId, NumBytes};
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    CanisterSettingsArgsBuilder, CanisterSnapshotResponse, LoadCanisterSnapshotArgs, Method,
    Payload, TakeCanisterSnapshotArgs,
};
use ic_replicated_state::canister_state::execution_state::WasmExecutionMode;
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder, get_reply};
use ic_types::Cycles;
use num_traits::ops::saturating::SaturatingSub;

const T: u128 = 1_000_000_000_000;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

const DEFAULT_INITIAL_CYCLES: u128 = 100_000 * T;
const FREEZING_THRESHOLD_DAYS: u64 = 365 * 10;
const FREEZING_THRESHOLD_SECS: u64 = FREEZING_THRESHOLD_DAYS * 24 * 3600;
const SUBNET_EXECUTION_MEMORY: u64 = 200 * GIB;
const SUBNET_MEMORY_THRESHOLD: u64 = 100 * GIB;

#[derive(Clone)]
struct RunbookParams {
    op_cycles_prepayment: bool,
    subnet_message: bool,
    ignore_canister_history_memory_usage: bool,
    early_prepayment_refund: bool,
}

struct Runbook<F, G> {
    initial_cycles: Cycles,
    memory_allocation: Option<u64>,
    setup: F,
    op: G,
    subnet_memory_target_before_op: NumBytes,
    expected_allocated_bytes: Option<NumBytes>,
    reserved_cycles_increased_after_op: bool,
    memory_allocation_exceeded_before_op: bool,
    memory_allocation_exceeded_after_op: bool,
    params: RunbookParams,
}

struct RunResult {
    err: Option<UserError>,
    unused_cycles_prepayment: Cycles,
    allocated_bytes: NumBytes,
    cycles_used: Cycles,
    idle_cycles_burned_per_day: Cycles,
}

#[must_use]
fn run<F, G, H>(runbook: &Runbook<F, G>) -> RunResult
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError>,
{
    let scaling = 4;
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory((scaling * SUBNET_EXECUTION_MEMORY) as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold((scaling * SUBNET_MEMORY_THRESHOLD) as i64)
        .with_resource_saturation_scaling(scaling as usize)
        .build();

    let initial_subnet_available_memory = test.subnet_available_memory();

    let initial_cycles = runbook.initial_cycles;
    let canister_id = test.create_canister(initial_cycles);
    let res = (runbook.setup)(&mut test, canister_id);
    let settings = CanisterSettingsArgsBuilder::new()
        .with_maybe_memory_allocation(runbook.memory_allocation)
        .with_reserved_cycles_limit(DEFAULT_INITIAL_CYCLES)
        .with_freezing_threshold(FREEZING_THRESHOLD_SECS)
        .build();
    test.update_settings(canister_id, settings).unwrap();
    let memory_allocated_bytes_after_setup =
        test.canister_state(canister_id).memory_allocated_bytes();

    // Dummy canister that fills the memory capacity up to the desired subnet memory target before executing `op`.
    let dummy_canister_initial_cycles: Cycles = DEFAULT_INITIAL_CYCLES.into();
    let subnet_memory_target = runbook.subnet_memory_target_before_op;
    assert!(memory_allocated_bytes_after_setup <= subnet_memory_target);
    let dummy_canister_memory_allocation =
        subnet_memory_target - memory_allocated_bytes_after_setup;
    let dummy_canister_settings = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(dummy_canister_memory_allocation.get())
        .with_reserved_cycles_limit(dummy_canister_initial_cycles.get())
        .build();
    let dummy_canister_id = test
        .create_canister_with_settings(dummy_canister_initial_cycles, dummy_canister_settings)
        .unwrap();

    let memory_allocation_exceeded = |test: &ExecutionTest| {
        test.canister_state(canister_id).memory_usage()
            > test.canister_state(canister_id).memory_allocation().bytes()
    };

    assert_eq!(
        memory_allocation_exceeded(&test),
        runbook.memory_allocation_exceeded_before_op
    );
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .reserved_balance(),
        Cycles::zero()
    );
    let expected_reserved_cycles =
        runbook
            .expected_allocated_bytes
            .map(|expected_allocated_bytes| {
                test.expected_storage_reservation_cycles(expected_allocated_bytes)
            });
    let initial_history_memory_usage = test
        .canister_state(canister_id)
        .canister_history_memory_usage();
    let initial_allocated_bytes = test.canister_state(canister_id).memory_allocated_bytes();
    let initial_executed_instructions = test.canister_executed_instructions(canister_id);
    let err = (runbook.op)(&mut test, canister_id, res);
    let final_executed_instructions = test.canister_executed_instructions(canister_id);
    let unused_cycles_prepayment = if runbook.params.op_cycles_prepayment {
        let used_instructions = final_executed_instructions - initial_executed_instructions;
        let limit = if runbook.params.subnet_message {
            test.install_code_instructions_limit()
        } else {
            test.max_instructions_per_message()
        };
        let unused_instructions = limit - used_instructions;
        test.convert_instructions_to_cycles(unused_instructions, WasmExecutionMode::Wasm32)
    } else {
        Cycles::zero()
    };
    let final_memory_usage = if runbook.params.ignore_canister_history_memory_usage {
        test.canister_state(canister_id).memory_usage()
            - test
                .canister_state(canister_id)
                .canister_history_memory_usage()
            + initial_history_memory_usage
    } else {
        test.canister_state(canister_id).memory_usage()
    };
    let final_allocated_bytes = test
        .canister_state(canister_id)
        .memory_allocation()
        .allocated_bytes(final_memory_usage);
    let allocated_bytes = final_allocated_bytes.saturating_sub(&initial_allocated_bytes);
    let reserved_cycles = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();
    if err.is_none() {
        if let Some(expected_reserved_cycles) = expected_reserved_cycles {
            assert_eq!(reserved_cycles, expected_reserved_cycles);
        }
        assert_eq!(
            reserved_cycles > Cycles::zero(),
            runbook.reserved_cycles_increased_after_op
        );
        assert_eq!(
            memory_allocation_exceeded(&test),
            runbook.memory_allocation_exceeded_after_op
        );
        if let Some(expected_allocated_bytes) = runbook.expected_allocated_bytes {
            assert_eq!(allocated_bytes, expected_allocated_bytes);
        }
    } else {
        assert_eq!(reserved_cycles, Cycles::zero());
        assert_eq!(allocated_bytes, NumBytes::from(0));
    }

    let canister_memory_usage = test
        .canister_state(canister_id)
        .memory_allocated_bytes()
        .get();
    let dummy_canister_memory_usage = test
        .canister_state(dummy_canister_id)
        .memory_allocated_bytes()
        .get();
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory(),
        test.subnet_available_memory().get_execution_memory()
            + canister_memory_usage as i64
            + dummy_canister_memory_usage as i64
    );

    let cycles_balance = test.canister_state(canister_id).system_state.balance()
        + test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();
    let idle_cycles_burned_per_day =
        test.idle_cycles_burned_per_day_for_memory_usage(canister_id, final_memory_usage);

    RunResult {
        err,
        unused_cycles_prepayment,
        allocated_bytes,
        cycles_used: runbook.initial_cycles - cycles_balance,
        idle_cycles_burned_per_day,
    }
}

fn test_memory_allocation<F, G, H>(mut runbook: Runbook<F, G>)
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError>,
{
    let res = run(&runbook);
    let allocated_bytes = res.allocated_bytes;
    let minimum_initial_cycles = res.cycles_used
        + res.idle_cycles_burned_per_day * FREEZING_THRESHOLD_DAYS
        + res.unused_cycles_prepayment;
    let unused_cycles_prepayment = res.unused_cycles_prepayment;
    let maximum_subnet_memory_target_before_op =
        NumBytes::from(SUBNET_EXECUTION_MEMORY) - allocated_bytes;

    runbook.expected_allocated_bytes = Some(allocated_bytes);
    runbook.initial_cycles = minimum_initial_cycles;
    runbook.subnet_memory_target_before_op = maximum_subnet_memory_target_before_op;
    let res = run(&runbook);
    assert!(res.err.is_none());

    if allocated_bytes > NumBytes::from(0) {
        runbook.subnet_memory_target_before_op =
            maximum_subnet_memory_target_before_op + NumBytes::from(1);
        let res = run(&runbook);
        let err = res.err.unwrap();
        match err.code() {
            ErrorCode::CanisterOutOfMemory | ErrorCode::SubnetOversubscribed => (),
            ErrorCode::CanisterCalledTrap => {
                assert!(err.description().contains("ic0.stable64_grow failed"));
            }
            _ => panic!("Unexpected error: {:?}", err),
        };
        runbook.subnet_memory_target_before_op = maximum_subnet_memory_target_before_op;

        runbook.initial_cycles = minimum_initial_cycles - Cycles::from(1_u128);
        if runbook.params.early_prepayment_refund {
            runbook.initial_cycles -= unused_cycles_prepayment;
        }
        let res = run(&runbook);
        let err = res.err.unwrap();
        assert!(
            err.code() == ErrorCode::InsufficientCyclesInMemoryGrow
                || err.code() == ErrorCode::CanisterOutOfCycles
        );
        runbook.initial_cycles = minimum_initial_cycles;
    }
}

fn test_memory_allocation_suite<F, G, H>(setup: F, op: G, params: RunbookParams)
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H + Copy,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError> + Copy,
{
    // very low memory allocation (exceeded already before executing `op`)
    let runbook = Runbook {
        memory_allocation: Some(0),
        setup,
        op,
        subnet_memory_target_before_op: SUBNET_MEMORY_THRESHOLD.into(),
        reserved_cycles_increased_after_op: true,
        expected_allocated_bytes: None,
        initial_cycles: DEFAULT_INITIAL_CYCLES.into(),
        memory_allocation_exceeded_before_op: true,
        memory_allocation_exceeded_after_op: true,
        params: params.clone(),
    };
    test_memory_allocation(runbook);

    // large memory allocation (not exceeded even after executing `op`)
    let runbook = Runbook {
        memory_allocation: Some(100 * GIB),
        setup,
        op,
        subnet_memory_target_before_op: SUBNET_MEMORY_THRESHOLD.into(),
        reserved_cycles_increased_after_op: false,
        expected_allocated_bytes: None,
        initial_cycles: DEFAULT_INITIAL_CYCLES.into(),
        memory_allocation_exceeded_before_op: false,
        memory_allocation_exceeded_after_op: false,
        params: params.clone(),
    };
    test_memory_allocation(runbook);
}

fn memory_grow_payload(heap_pages: u64, stable_pages: u64, reply: bool) -> Vec<u8> {
    let mut payload = wasm()
        .wasm_memory_grow(heap_pages.try_into().unwrap())
        .stable64_grow(stable_pages)
        .int64_to_blob()
        .trap_if_eq(u64::MAX.to_le_bytes(), "ic0.stable64_grow failed");
    if reply {
        payload = payload.reply();
    }
    payload.build()
}

fn setup_universal_canister(test: &mut ExecutionTest, canister_id: CanisterId) {
    let payload = memory_grow_payload((60 * MIB) >> 16, (60 * MIB) >> 16, false);
    test.install_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
        .unwrap();
}

#[test]
fn test_memory_allocation_suite_grow_wasm_memory() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload(GIB >> 16, 0, true);
        test.ingress(canister_id, "update", payload).err()
    };
    let params = RunbookParams {
        op_cycles_prepayment: true,
        subnet_message: false,
        ignore_canister_history_memory_usage: false,
        early_prepayment_refund: false,
    };
    test_memory_allocation_suite(setup_universal_canister, op, params);
}

#[test]
fn test_memory_allocation_suite_grow_stable_memory() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload(0, GIB >> 16, true);
        test.ingress(canister_id, "update", payload).err()
    };
    let params = RunbookParams {
        op_cycles_prepayment: true,
        subnet_message: false,
        ignore_canister_history_memory_usage: false,
        early_prepayment_refund: false,
    };
    test_memory_allocation_suite(setup_universal_canister, op, params);
}

#[test]
fn test_memory_allocation_suite_take_snapshot() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let take_canister_snapshot_args = TakeCanisterSnapshotArgs::new(canister_id, None);
        test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = RunbookParams {
        op_cycles_prepayment: false,
        subnet_message: true,
        ignore_canister_history_memory_usage: false,
        early_prepayment_refund: false,
    };
    test_memory_allocation_suite(setup_universal_canister, op, params);
}

#[test]
fn test_memory_allocation_suite_load_snapshot() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let take_canister_snapshot_args = TakeCanisterSnapshotArgs::new(canister_id, None);
        let res = test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        );
        let snapshot_id = CanisterSnapshotResponse::decode(&get_reply(res))
            .unwrap()
            .id;
        test.uninstall_code(canister_id).unwrap();
        snapshot_id
    };
    let op = |test: &mut ExecutionTest, canister_id, snapshot_id| {
        let load_canister_snapshot_args =
            LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
        test.subnet_message(
            Method::LoadCanisterSnapshot,
            load_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = RunbookParams {
        op_cycles_prepayment: false,
        subnet_message: true,
        ignore_canister_history_memory_usage: true,
        early_prepayment_refund: false,
    };
    test_memory_allocation_suite(setup, op, params);
}

#[test]
fn test_memory_allocation_suite_install_code() {
    let setup = |_test: &mut ExecutionTest, _canister_id: CanisterId| {};
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload((60 * MIB) >> 16, (60 * MIB) >> 16, false);
        test.install_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
            .err()
    };
    let params = RunbookParams {
        op_cycles_prepayment: true,
        subnet_message: true,
        ignore_canister_history_memory_usage: false,
        early_prepayment_refund: true,
    };
    test_memory_allocation_suite(setup, op, params);
}

#[test]
fn test_memory_allocation_suite_upgrade_code() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let pre_upgrade_grow_payload = memory_grow_payload(GIB >> 16, (120 * MIB) >> 16, false);
        test.ingress(
            canister_id,
            "update",
            wasm()
                .set_pre_upgrade(pre_upgrade_grow_payload)
                .reply()
                .build(),
        )
        .unwrap();
    };
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload((120 * MIB) >> 16, (120 * MIB) >> 16, false);
        test.upgrade_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
            .err()
    };
    let params = RunbookParams {
        op_cycles_prepayment: true,
        subnet_message: true,
        ignore_canister_history_memory_usage: false,
        early_prepayment_refund: true,
    };
    test_memory_allocation_suite(setup, op, params);
}

#[test]
fn test_memory_allocation_suite_reinstall_code() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload((120 * MIB) >> 16, (120 * MIB) >> 16, false);
        test.reinstall_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
            .err()
    };
    let params = RunbookParams {
        op_cycles_prepayment: true,
        subnet_message: true,
        ignore_canister_history_memory_usage: false,
        early_prepayment_refund: true,
    };
    test_memory_allocation_suite(setup_universal_canister, op, params);
}
