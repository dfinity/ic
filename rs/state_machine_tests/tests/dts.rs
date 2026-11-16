use ic_base_types::PrincipalId;
use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{SchedulerConfig, SubnetConfig},
};
use ic_error_types::ErrorCode;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachineBuilder, StateMachineConfig};
use ic_types_cycles::Cycles;
use std::time::Duration;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

// Canister code with a very slow method.
fn very_slow_wasm(n: u64) -> Vec<u8> {
    let wat = format!(
        r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $inc
            ;; Increment a counter.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 1))))
        (func $run
            ;; create a local variable and initialize it to 0
            (local $i i32)
            (local $j i32)
            (loop $my_loop
                i32.const 0
                local.set $j
                (loop $my_inner_loop
                    ;; add one to $j
                    local.get $j
                    i32.const 1
                    i32.add
                    local.set $j
                    ;; if $j is less than 200000 branch to loop
                    local.get $j
                    i32.const {n}
                    i32.lt_s
                    br_if $my_inner_loop
                )
                ;; add one to $i
                local.get $i
                i32.const 1
                i32.add
                local.set $i
                ;; if $i is less than 200000 branch to loop
                local.get $i
                i32.const {n}
                i32.lt_s
                br_if $my_loop
            )
            (call $msg_reply))
        (memory $memory 1)
        (export "canister_update run" (func $run))
        (export "canister_heartbeat" (func $inc))
    )
"#
    );
    wat::parse_str(wat).unwrap()
}

#[test]
fn test_dts() {
    let config = StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        HypervisorConfig::default(),
    );
    let sm = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_config(Some(config))
        .build();

    // Create a canister.
    let t0 = sm.get_time();
    let can_id = sm.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);
    let t1 = sm.get_time();
    assert_eq!(t1, t0 + Duration::from_nanos(1)); // canister creation should take one round, i.e., 1ns

    // Install the very slow canister wasm file on the canister.
    sm.install_existing_canister(can_id, very_slow_wasm(60_000), vec![])
        .unwrap();

    let t0 = sm.get_time();
    sm.execute_ingress_as(PrincipalId::new_anonymous(), can_id, "run", vec![])
        .unwrap();
    let t1 = sm.get_time();
    assert!(t1 >= t0 + Duration::from_nanos(10)); // DTS takes at least 10 rounds
}

/// A canister whose `run` method burns instructions over many DTS slices
/// until at most 1.5 slice limits are left in the message instruction budget
/// and then calls `stable64_read` with a length exceeding the instructions
/// left by `margin`.
///
/// The length is charged to the instruction counter (one instruction per byte)
/// after the checks that the range lies within the stable memory (hence the
/// initial `stable64_grow`) and that the length is a valid heap address (hence
/// the charge must not exceed `u32::MAX`), but before the destination range is
/// checked against the actual (one page) heap, so the copy never happens.
///
/// The burn proceeds in chunks of a tenth of the slice limit, reading
/// `performance_counter(0)` after each chunk, so that it stops at most one
/// chunk past its target.
fn charge_exceeding_message_budget_wasm() -> Vec<u8> {
    const WASM_PAGE_SIZE: u64 = 65536;
    // Empirically, an iteration of the loop in `$burn_chunk` costs 9 instructions.
    const INSTRUCTIONS_PER_ITERATION: u64 = 9;

    let scheduler_config = SchedulerConfig::application_subnet();
    let message_limit = scheduler_config.max_instructions_per_message.get();
    let slice_limit = scheduler_config.max_instructions_per_slice.get();

    let target_remaining = slice_limit * 3 / 2;
    let chunk_iterations = slice_limit / 10 / INSTRUCTIONS_PER_ITERATION;
    let margin = slice_limit / 10;
    // The charge is at most `target_remaining + margin`.
    let max_charge = target_remaining + margin;
    assert!(max_charge <= u32::MAX as u64);
    let stable_pages = max_charge / WASM_PAGE_SIZE + 1;

    // Before #11956, the test below observed a `SliceOverrun` when the slice
    // containing the charge used at least two slice limits. That slice uses
    // (up to a negligible carry-over from the previous slices) the instructions
    // left in the message budget when the slice starts plus `margin`, so make
    // sure that the limits still align to exercise that failure if they change.
    let executed_before_charge_slice =
        (message_limit - target_remaining) / slice_limit * slice_limit;
    assert!(message_limit - executed_before_charge_slice + margin >= 2 * slice_limit);

    let wat = format!(
        r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
  (import "ic0" "stable64_read" (func $stable64_read (param i64 i64 i64)))
  (import "ic0" "performance_counter" (func $perf_counter (param i32) (result i64)))
  (memory 1)
  (func $burn_chunk (local $i i64)
    (loop $l
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br_if $l (i64.lt_u (local.get $i) (i64.const {chunk_iterations})))))
  ;; Returns the number of instructions left in the message budget.
  (func $remaining (result i64)
    (i64.sub (i64.const {message_limit}) (call $perf_counter (i32.const 0))))
  (func $run
    (drop (call $stable64_grow (i64.const {stable_pages})))
    (block $done
      (loop $l
        (br_if $done (i64.le_s (call $remaining) (i64.const {target_remaining})))
        (call $burn_chunk)
        (br $l)))
    (call $stable64_read
      (i64.const 0)
      (i64.const 0)
      (i64.add (call $remaining) (i64.const {margin})))
    (call $msg_reply))
  (export "canister_update run" (func $run)))
"#
    );
    wat::parse_str(wat).unwrap()
}

/// Regression test for message-budget exhaustion taking precedence over
/// `SliceOverrun` in DTS (#11956).
///
/// Before #11956, the oversized system API charge made the slice appear to use
/// at least two slice limits, producing a `SliceOverrun` even though the message
/// budget was exhausted. `DeterministicTimeSlicing::try_pause` now checks for
/// message-budget exhaustion first and returns `InstructionLimitExceeded`.
/// This error precedence holds even if the cap in `State::newly_executed` is
/// removed; the cap itself is covered by the DTS unit tests.
#[test]
fn charge_exceeding_message_budget_fails_with_message_limit() {
    let scheduler_config = SchedulerConfig::application_subnet();
    let message_limit = scheduler_config.max_instructions_per_message.get();
    let slice_limit = scheduler_config.max_instructions_per_slice.get();

    let sm = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let canister_id = sm.create_canister_with_cycles(None, Cycles::new(1 << 60), None);
    sm.install_existing_canister(canister_id, charge_exceeding_message_budget_wasm(), vec![])
        .unwrap();

    let err = sm.execute_ingress(canister_id, "run", vec![]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);
    let expected = format!(
        "Canister exceeded the limit of {message_limit} instructions for single message execution."
    );
    assert!(
        err.description().contains(&expected),
        "a system API call charging more instructions than are left in the message budget \
         must exhaust the message instruction limit (and not overrun the slice limit {slice_limit}), \
         got: {}",
        err.description()
    );
}
