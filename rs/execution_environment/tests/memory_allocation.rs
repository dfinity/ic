use ic_base_types::{CanisterId, NumBytes};
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    CanisterSettingsArgsBuilder, CanisterSnapshotResponse, LoadCanisterSnapshotArgs, Method,
    Payload, TakeCanisterSnapshotArgs,
};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder, get_reply};
use ic_types::Cycles;
use num_traits::ops::saturating::SaturatingSub;

const B: u128 = 1_000_000_000;
const T: u128 = 1_000_000_000_000;

const GIB: u64 = 1 << 30;

const DEFAULT_INITIAL_CYCLES: u128 = 10_000 * T;
const FREEZING_THRESHOLD_DAYS: u64 = 365 * 10;
const FREEZING_THRESHOLD_SECS: u64 = FREEZING_THRESHOLD_DAYS * 24 * 3600;
const SUBNET_EXECUTION_MEMORY: u64 = 200 * GIB;
const SUBNET_MEMORY_THRESHOLD: u64 = 100 * GIB;

struct Runbook<F, G> {
    initial_cycles: u128,
    memory_allocation: Option<u64>,
    setup: F,
    op: G,
    expected_allocated_bytes: Option<NumBytes>,
    reserved_cycles_increased_after_op: bool,
    memory_allocation_exceeded_before_op: bool,
    memory_allocation_exceeded_after_op: bool,
    op_cycles_prepayment: u128,
}

struct RunResult {
    err: Option<UserError>,
    allocated_bytes: NumBytes,
    cycles_used: u128,
    idle_cycles_burned_per_day: u128,
}

#[must_use]
fn run<F, G, H>(runbook: &Runbook<F, G>) -> RunResult
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError>,
{
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(SUBNET_EXECUTION_MEMORY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(SUBNET_MEMORY_THRESHOLD as i64)
        .build();

    let initial_subnet_available_memory = test.subnet_available_memory();

    let initial_cycles = Cycles::from(runbook.initial_cycles);
    let settings = CanisterSettingsArgsBuilder::new()
        .with_maybe_memory_allocation(runbook.memory_allocation)
        .with_reserved_cycles_limit(initial_cycles.get())
        .with_freezing_threshold(FREEZING_THRESHOLD_SECS)
        .build();
    let canister_id = test
        .create_canister_with_settings(initial_cycles, settings)
        .unwrap();
    test.install_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let res = (runbook.setup)(&mut test, canister_id);
    let memory_allocated_bytes_after_setup =
        test.canister_state(canister_id).memory_allocated_bytes();

    // Dummy canister that fills the memory capacity up to the subnet memory threshold.
    let dummy_canister_id = test
        .create_canister_with_allocation(
            Cycles::from(100 * T),
            None,
            Some(SUBNET_MEMORY_THRESHOLD - memory_allocated_bytes_after_setup.get()),
        )
        .unwrap();

    let memory_allocation_exceeded = |test: &ExecutionTest| {
        test.canister_state(canister_id).memory_usage()
            > test
                .canister_state(canister_id)
                .memory_allocation()
                .pre_allocated_bytes()
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
    let initial_reserved_balance = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();
    let err = (runbook.op)(&mut test, canister_id, res);
    let final_memory_usage = test.canister_state(canister_id).memory_usage()
        - test
            .canister_state(canister_id)
            .canister_history_memory_usage()
        + initial_history_memory_usage;
    let final_allocated_bytes = test
        .canister_state(canister_id)
        .memory_allocation()
        .allocated_bytes(final_memory_usage);
    let final_reserved_balance = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();
    let reserved_cycles = final_reserved_balance - initial_reserved_balance;
    let allocated_bytes = final_allocated_bytes.saturating_sub(&initial_allocated_bytes);
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
        test.subnet_available_memory().get_execution_memory()
            + canister_memory_usage as i64
            + dummy_canister_memory_usage as i64,
        initial_subnet_available_memory.get_execution_memory()
    );

    let cycles_balance = test
        .canister_state(canister_id)
        .system_state
        .balance()
        .get()
        + test
            .canister_state(canister_id)
            .system_state
            .reserved_balance()
            .get();
    let idle_cycles_burned_per_day = test.idle_cycles_burned_per_day(canister_id).get();

    RunResult {
        err,
        allocated_bytes,
        cycles_used: initial_cycles.get() - cycles_balance,
        idle_cycles_burned_per_day,
    }
}

fn test_memory_allocation<F, G, H>(mut runbook: Runbook<F, G>)
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError>,
{
    let res = run(&runbook);
    if runbook.memory_allocation_exceeded_after_op {
        runbook.initial_cycles = res.cycles_used
            + res.idle_cycles_burned_per_day * FREEZING_THRESHOLD_DAYS as u128
            + runbook.op_cycles_prepayment;
        runbook.expected_allocated_bytes = Some(res.allocated_bytes);
        let res = run(&runbook);
        assert!(res.err.is_none());
        runbook.initial_cycles = res.cycles_used
            + res.idle_cycles_burned_per_day * FREEZING_THRESHOLD_DAYS as u128
            + runbook.op_cycles_prepayment
            - 100_000_000;
        let res = run(&runbook);
        let err = res.err.unwrap();
        assert!(
            err.code() == ErrorCode::InsufficientCyclesInMemoryGrow
                || err.code() == ErrorCode::CanisterOutOfCycles
        );
    }
}

fn test_memory_allocation_suite<F, G, H>(setup: F, op: G, op_cycles_prepayment: u128)
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H + Copy,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError> + Copy,
{
    // very low memory allocation (exceeded already before executing `op`)
    let runbook = Runbook {
        memory_allocation: Some(1),
        setup,
        op,
        reserved_cycles_increased_after_op: true,
        expected_allocated_bytes: None,
        initial_cycles: DEFAULT_INITIAL_CYCLES,
        memory_allocation_exceeded_before_op: true,
        memory_allocation_exceeded_after_op: true,
        op_cycles_prepayment,
    };
    test_memory_allocation(runbook);

    // moderate memory allocation (exceeded while executing `op`)
    let runbook = Runbook {
        memory_allocation: Some(100 << 20),
        setup,
        op,
        reserved_cycles_increased_after_op: true,
        expected_allocated_bytes: None,
        initial_cycles: DEFAULT_INITIAL_CYCLES,
        memory_allocation_exceeded_before_op: false,
        memory_allocation_exceeded_after_op: true,
        op_cycles_prepayment,
    };
    test_memory_allocation(runbook);

    // large memory allocation (not exceeded even after executing `op`)
    let runbook = Runbook {
        memory_allocation: Some(100 << 30),
        setup,
        op,
        reserved_cycles_increased_after_op: false,
        expected_allocated_bytes: None,
        initial_cycles: DEFAULT_INITIAL_CYCLES,
        memory_allocation_exceeded_before_op: false,
        memory_allocation_exceeded_after_op: false,
        op_cycles_prepayment,
    };
    test_memory_allocation(runbook);
}

fn noop(_test: &mut ExecutionTest, _canister_id: CanisterId) {}

#[test]
fn test_memory_allocation_suite_grow_wasm_memory() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        test.ingress(
            canister_id,
            "update",
            wasm()
                .push_equal_bytes(42, (1 << 30) + (1 << 29))
                .reply()
                .build(),
        )
        .err()
    };
    test_memory_allocation_suite(noop, op, 38 * B);
}

#[test]
fn test_memory_allocation_suite_grow_stable_memory() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        test.ingress(
            canister_id,
            "update",
            wasm().stable64_grow((1 << 30) >> 16).reply().build(),
        )
        .err()
    };
    test_memory_allocation_suite(noop, op, 40 * B);
}

#[test]
fn test_memory_allocation_suite_take_snapshot() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        test.ingress(
            canister_id,
            "update",
            wasm().stable64_grow((60 << 20) >> 16).reply().build(),
        )
        .unwrap();
        let take_canister_snapshot_args = TakeCanisterSnapshotArgs::new(canister_id, None);
        test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        )
        .err()
    };
    test_memory_allocation_suite(noop, op, 0);
}

#[test]
fn test_memory_allocation_suite_load_snapshot() {
    let setup = |test: &mut ExecutionTest, canister_id| {
        test.ingress(
            canister_id,
            "update",
            wasm().stable64_grow((60 << 20) >> 16).reply().build(),
        )
        .unwrap();
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
    test_memory_allocation_suite(setup, op, 0);
}
