use std::time::Duration;

use assert_matches::assert_matches;

use ic_base_types::NumSeconds;
use ic_config::subnet_config::SchedulerConfig;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_replicated_state::testing::SystemStateTesting;
use ic_replicated_state::{
    canister_state::{NextExecution, WASM_PAGE_SIZE_IN_BYTES},
    CallOrigin,
};
use ic_state_machine_tests::{Cycles, IngressStatus, WasmResult};
use ic_sys::PAGE_SIZE;
use ic_types::messages::{CallbackId, RequestMetadata};
use ic_types::{NumInstructions, NumOsPages};
use ic_universal_canister::{call_args, wasm};

use ic_test_utilities_execution_environment::{
    check_ingress_status, ExecutionTest, ExecutionTestBuilder,
};

fn wat_writing_to_each_stable_memory_page(memory_amount: u64) -> String {
    format!(
        r#"
        (module
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update go") (local i64)
                (local.set 0 (i64.const 0))
                (drop (call $stable_grow (i64.const 10)))
                (loop $loop
                    (call $stable_write (local.get 0) (i64.const 0) (i64.const 1))
                    (local.set 0 (i64.add (local.get 0) (i64.const 4096))) (;increment by OS page size;)
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#,
        memory_amount
    )
}

fn wat_writing_to_each_stable_memory_page_long_execution(memory_amount: u64) -> String {
    format!(
        r#"
        (module
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_init") (local i64)
                (local.set 0 (i64.const 0))
                (drop (call $stable_grow (i64.const 10)))
                (loop $loop
                    (call $stable_write (local.get 0) (i64.const 0) (i64.const 1))
                    (local.set 0 (i64.add (local.get 0) (i64.const 4096))) (;increment by OS page size;)
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#,
        memory_amount
    )
}

#[test]
fn can_write_to_each_page_in_stable_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(NumOsPages::new(10), NumOsPages::new(10))
        .build();
    let wat = wat_writing_to_each_stable_memory_page(10 * PAGE_SIZE as u64);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let _result = test.ingress(canister_id, "go", vec![]).unwrap();
}

#[test]
fn dts_update_concurrent_cycles_change_succeeds() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `ingress_induction_cycles_debit`).
    // 3. The update method resumes and calls canister B with 1000 cycles.
    // 4. The update method succeeds because there are enough cycles
    //    in the canister balance to cover both the call and 'ingress_induction_cycles_debit'.
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b.clone()),
            transferred_cycles,
        )
        .build();

    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();

    test.ingress_raw(a_id, "update", a);

    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(instruction_limit), test.subnet_size());

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let cycles_debit = Cycles::new(1000);

    // Reset the cycles balance to simplify cycles bookkeeping,
    let initial_cycles = freezing_threshold
        + additional_freezing_threshold
        + max_execution_cost
        + call_charge
        + cycles_debit;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    test.canister_state_mut(a_id)
        .system_state
        .set_balance(initial_cycles);

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles - max_execution_cost,
    );

    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - call_charge
            - (test.canister_execution_cost(a_id) - initial_execution_cost)
            - cycles_debit,
    );
}

#[test]
fn dts_update_concurrent_cycles_change_fails() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `ingress_induction_cycles_debit`).
    // 3. The update method resumes and calls canister B with 1000 cycles.
    // 4. The update method fails because there are not enough cycles
    //    in the canister balance to cover both the call and 'ingress_induction_cycles_debit'.
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b.clone()),
            transferred_cycles,
        )
        .build();

    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(instruction_limit), test.subnet_size());

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    // Reset the cycles balance to simplify cycles bookkeeping,
    let initial_cycles =
        freezing_threshold + additional_freezing_threshold + max_execution_cost + call_charge;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    test.canister_state_mut(a_id)
        .system_state
        .set_balance(initial_cycles);

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles - max_execution_cost,
    );

    let cycles_debit = test.canister_state(a_id).system_state.balance();
    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);

    assert_eq!(
        err.description(),
        format!(
            "Canister {} is out of cycles: \
             please top up the canister with at least {} additional cycles",
            a_id,
            (freezing_threshold + call_charge)
                - (initial_cycles - max_execution_cost - cycles_debit)
        )
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - (test.canister_execution_cost(a_id) - initial_execution_cost)
            - cycles_debit,
    );
}

#[test]
fn dirty_pages_are_free_on_system_subnet() {
    fn instructions_to_write_stable_byte(mut test: ExecutionTest) -> NumInstructions {
        let initial_cycles = Cycles::new(1_000_000_000_000);
        let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
        let a = wasm()
            .stable_grow(1)
            .stable64_fill(0, 0, 1)
            .message_payload()
            .append_and_reply()
            .build();
        let result = test.ingress(a_id, "update", a);
        assert!(result.is_ok());
        test.canister_executed_instructions(a_id)
    }

    let system_test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let system_instructions = instructions_to_write_stable_byte(system_test);
    let app_test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let app_instructions = instructions_to_write_stable_byte(app_test);

    // Can't check for equality because there are other charges that are omitted
    // on system subnets.
    assert!(
        app_instructions
            > system_instructions + SchedulerConfig::application_subnet().dirty_page_overhead
    );
}

#[test]
fn hitting_page_delta_limit_fails_message() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(NumOsPages::from(no_pages), NumOsPages::from(no_pages))
        .build();
    let wat = wat_writing_to_each_stable_memory_page(10 * PAGE_SIZE as u64 + 1);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "go", vec![]).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterMemoryAccessLimitExceeded);
    assert_eq!(
        result.description(),
        format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the number of modified pages in the stable memory in a single execution: limit {} KB for regular messages and {} KB for upgrade messages.",
        no_pages * (PAGE_SIZE as u64 / 1024), no_pages * (PAGE_SIZE as u64 / 1024))
    );
}

#[test]
fn hitting_page_delta_limit_fails_message_system_subnet() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(NumOsPages::from(no_pages), NumOsPages::from(no_pages))
        .with_subnet_type(SubnetType::System)
        .build();
    let wat = wat_writing_to_each_stable_memory_page(10 * PAGE_SIZE as u64 + 1);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "go", vec![]).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterMemoryAccessLimitExceeded);
    assert_eq!(
        result.description(),
        format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the number of modified pages in the stable memory in a single execution: limit {} KB for regular messages and {} KB for upgrade messages.",
        no_pages * (PAGE_SIZE as u64 / 1024), no_pages * (PAGE_SIZE as u64 / 1024))
    );
}

#[test]
fn hitting_page_delta_limit_fails_for_long_message() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(NumOsPages::from(no_pages), NumOsPages::from(no_pages))
        .build();
    let wat = wat_writing_to_each_stable_memory_page_long_execution(10 * PAGE_SIZE as u64 + 1);

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    let result = test.install_canister(canister_id, wat::parse_str(wat).unwrap());

    assert!(result.clone().unwrap_err().code() == ErrorCode::CanisterMemoryAccessLimitExceeded);
    assert_eq!(
        result.unwrap_err().description(),
        format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the number of modified pages in the stable memory in a single execution: limit {} KB for regular messages and {} KB for upgrade messages.",
         no_pages * (PAGE_SIZE as u64 / 1024), no_pages * (PAGE_SIZE as u64 / 1024))
    );
}

#[test]
fn hitting_page_delta_limit_fails_for_long_message_non_native_stable() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(NumOsPages::from(no_pages), NumOsPages::from(no_pages))
        .with_non_native_stable()
        .build();
    let wat = wat_writing_to_each_stable_memory_page_long_execution(10 * PAGE_SIZE as u64 + 1);

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    let result = test.install_canister(canister_id, wat::parse_str(wat).unwrap());

    assert!(result.clone().unwrap_err().code() == ErrorCode::CanisterMemoryAccessLimitExceeded);
    assert_eq!(
        result.unwrap_err().description(),
        format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the \
        number of modified pages in the stable memory in a single message execution: limit: 40 KB.")
    );
}

#[test]
fn hitting_page_delta_limit_fails_message_non_native_stable() {
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(NumOsPages::from(10), NumOsPages::from(10))
        .with_non_native_stable()
        .build();
    let wat = wat_writing_to_each_stable_memory_page(10 * PAGE_SIZE as u64 + 1);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "go", vec![]).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterMemoryAccessLimitExceeded);
    assert_eq!(
        result.description(),
        format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the \
        number of modified pages in the stable memory in a single message execution: limit: 40 KB.")
    );
}

#[test]
fn hitting_page_delta_limit_fails_message_non_native_stable_system_subnet() {
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(NumOsPages::from(10), NumOsPages::from(10))
        .with_non_native_stable()
        .with_subnet_type(SubnetType::System)
        .build();
    let wat = wat_writing_to_each_stable_memory_page(10 * PAGE_SIZE as u64 + 1);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "go", vec![]).unwrap_err();
    assert_eq!(result.code(), ErrorCode::CanisterMemoryAccessLimitExceeded);
    assert_eq!(
        result.description(),
        format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the \
        number of modified pages in the stable memory in a single message execution: limit: 40 KB.")
    );
}

#[test]
fn dts_update_resume_fails_due_to_cycles_change() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we change its cycles balance.
    // 3. The update method resumes, detects the cycles balance mismatch, and
    //    fails.
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();

    let a = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Change the cycles balance of the clean canister.
    let balance = test.canister_state(a_id).system_state.balance();
    test.canister_state_mut(a_id)
        .system_state
        .add_cycles(balance + Cycles::new(1), CyclesUseCase::NonConsumed);

    test.execute_slice(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmEngineError);

    assert_eq!(
        err.description(),
        format!(
            "Error from Canister {}: Canister encountered a Wasm engine error: \
             Failed to apply system changes: Mismatch in cycles \
             balance when resuming an update call",
            a_id
        )
    );
}

#[test]
fn dts_update_resume_fails_due_to_call_context_change() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we change its call context counter.
    // 3. The update method resumes, detects the call context mismatch, and
    //    fails.
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();

    let a = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Change the next call context id of the clean canister.
    let time = test.time();
    test.canister_state_mut(a_id)
        .system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::SystemTask,
            Cycles::new(0),
            time,
            RequestMetadata::for_new_call_tree(time),
        );

    test.execute_slice(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmEngineError);

    assert_eq!(
        err.description(),
        format!(
            "Error from Canister {}: Canister encountered a Wasm engine error: \
             Failed to apply system changes: Mismatch in call \
             context id when resuming an update call",
            a_id
        )
    );
}

#[test]
fn dts_update_does_not_expire_while_executing() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we fast forward the time by 1h.
    // 3. The update resumes and should not fail due to ingress expiration.
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();

    let a = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .push_bytes(&[42])
        .append_and_reply()
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a.clone());

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    test.advance_time(Duration::from_secs(3600));

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let result = check_ingress_status(test.ingress_status(&ingress_id)).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![42]));

    // Now repeat the same steps but also abort the execution after advancing
    // the time.

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    test.advance_time(Duration::from_secs(3600));

    test.abort_all_paused_executions();

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let result = check_ingress_status(test.ingress_status(&ingress_id)).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![42]));
}

#[test]
fn dts_abort_of_call_works() {
    let initial_cycles = 1_000_000_000_000_000;
    // Test steps:
    // 1. Canister A runs an update method that calls canister B.
    // 2. The called update method of canister B runs with DTS.
    // 3. The called update method is aborted.
    // 4. The called update method resumes and succeeds.
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_initial_canister_cycles(initial_cycles)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .accept_cycles(transferred_cycles)
        .push_bytes(&[42])
        .append_and_reply()
        .build();

    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject()),
            transferred_cycles,
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    test.induct_messages();

    test.execute_slice(b_id);

    assert_eq!(
        test.canister_state(b_id).next_execution(),
        NextExecution::ContinueLong,
    );

    test.abort_all_paused_executions();

    test.execute_message(b_id);

    test.induct_messages();

    test.execute_message(a_id);

    let result = check_ingress_status(test.ingress_status(&ingress_id)).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![42]));

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        Cycles::new(initial_cycles)
            - transferred_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&[42])
    );

    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        Cycles::new(initial_cycles) + transferred_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn dts_ingress_induction_cycles_debit_is_applied_on_aborts() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `ingress_induction_cycles_debit`).
    // 3. The update method is aborted and we expected the cycles debit to be
    //    applied.
    let instruction_limit = 100_000_000;
    let initial_canister_cycles = 1_000_000_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_initial_canister_cycles(initial_canister_cycles)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();

    let a = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .push_bytes(&[42])
        .append_and_reply()
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    test.execute_slice(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    let cycles_debit = Cycles::new(1000);
    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    assert!(
        test.canister_state(a_id)
            .system_state
            .ingress_induction_cycles_debit()
            > Cycles::zero()
    );

    test.abort_all_paused_executions();

    assert_eq!(
        test.canister_state(a_id)
            .system_state
            .ingress_induction_cycles_debit(),
        Cycles::zero()
    );

    test.execute_message(a_id);

    let result = check_ingress_status(test.ingress_status(&ingress_id)).unwrap();

    assert_eq!(result, WasmResult::Reply(vec![42]));
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        Cycles::new(initial_canister_cycles) - test.canister_execution_cost(a_id) - cycles_debit
    );
}

#[test]
fn dts_uninstall_with_aborted_update() {
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_manual_execution()
        .build();

    let canister_id = test.universal_canister().unwrap();

    let wasm_payload = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .build();

    let (message_id, _) = test.ingress_raw(canister_id, "update", wasm_payload);

    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong,
    );

    test.abort_all_paused_executions();

    test.uninstall_code(canister_id).unwrap();

    test.execute_message(canister_id);

    let err = check_ingress_status(test.ingress_status(&message_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmModuleNotFound);
    assert_eq!(
        err.description(),
        format!(
            "Error from Canister {}: Attempted to execute a message, but the canister contains no Wasm module.",
            canister_id
        )
    );
}

#[test]
fn stable_grow_updates_subnet_available_memory() {
    let initial_subnet_memory = 11 * WASM_PAGE_SIZE_IN_BYTES as i64;

    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.set_subnet_available_memory(SubnetAvailableMemory::new(
        initial_subnet_memory,
        initial_subnet_memory,
        initial_subnet_memory,
    ));

    // Growing stable memory should reduce the subnet total memory.
    let payload = wasm()
        .stable64_grow(1)
        .int64_to_blob()
        .append_and_reply()
        .build();
    let result = test.ingress(canister_id, "update", payload).unwrap();
    assert_matches!(result, WasmResult::Reply(_));
    assert_eq!(i64::from_le_bytes(result.bytes().try_into().unwrap()), 0);
    // The universal canister needs one wasm page for it's stack in addition to
    // the page we allocated with `stable_grow`.
    assert_eq!(
        initial_subnet_memory - test.subnet_available_memory().get_execution_memory(),
        2 * WASM_PAGE_SIZE_IN_BYTES as i64
    );

    // Growing beyond the total subnet memory should fail (returning -1) and not
    // allocate anything more.
    let payload = wasm()
        .stable64_grow(10)
        .int64_to_blob()
        .append_and_reply()
        .build();
    let result = test.ingress(canister_id, "update", payload).unwrap();
    assert_matches!(result, WasmResult::Reply(_));
    assert_eq!(i64::from_le_bytes(result.bytes().try_into().unwrap()), -1);
    assert_eq!(
        initial_subnet_memory - test.subnet_available_memory().get_execution_memory(),
        2 * WASM_PAGE_SIZE_IN_BYTES as i64
    );
}

#[test]
fn stable_grow_returns_allocated_memory_on_error() {
    const KB: u64 = 1024;
    const GB: u64 = KB * KB * KB;

    // Create a canister which already has stable memory too big for the 32-bit
    // API.
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test
        .universal_canister_with_cycles(Cycles::new(100_000_000_000_000))
        .unwrap();
    let payload = wasm()
        .stable64_grow((4 * GB / WASM_PAGE_SIZE_IN_BYTES as u64) + 1)
        .int64_to_blob()
        .append_and_reply()
        .build();
    let result = test.ingress(canister_id, "update", payload).unwrap();
    assert_matches!(result, WasmResult::Reply(_));
    assert_eq!(i64::from_le_bytes(result.bytes().try_into().unwrap()), 0);

    let initial_subnet_memory = test.subnet_available_memory().get_execution_memory();
    let initial_canister_memory = test.canister_state(canister_id).memory_usage();

    // Calling 32-bit stable grow should trap.
    let payload = wasm().stable_grow(1).reply().build();
    let result = test.ingress(canister_id, "update", payload).unwrap_err();
    assert_eq!(
        result,
        UserError::new(
            ErrorCode::CanisterTrapped,
            format!(
                "Error from Canister {canister_id}: Canister trapped: 32 bit stable memory api used on a memory larger than 4GB"
            )
        )
    );

    // Subnet and canister memory should remain unchanged
    assert_eq!(
        test.subnet_available_memory().get_execution_memory(),
        initial_subnet_memory
    );
    assert_eq!(
        test.canister_state(canister_id).memory_usage(),
        initial_canister_memory
    );
}

#[test]
fn test_call_context_instructions_executed_is_updated_on_ok_update() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    // Create canisters A and B.
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    // Canister A calls canister B.
    let wasm_payload = wasm().inter_update(b_id, call_args()).build();

    // Enqueue ingress message to canister A.
    let ingress_status = test.ingress_raw(a_id, "update", wasm_payload).1;
    assert_matches!(ingress_status, IngressStatus::Unknown);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 1);

    // Execute canister A ingress.
    test.execute_message(a_id);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 2);

    // Make sure the execution was ok.
    let call_context = test.get_call_context(a_id, CallbackId::from(1));

    // Make sure the `instructions_executed` is updated.
    let instructions_executed_a_1 = call_context.instructions_executed();
    assert!(instructions_executed_a_1 > 0.into());
}

#[test]
fn test_call_context_instructions_executed_is_updated_on_err_update() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    // Create canisters A and B.
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    // Canister A calls canister B and then traps.
    let wasm_payload = wasm().inter_update(b_id, call_args()).trap().build();

    // Enqueue ingress message to canister A.
    let ingress_status = test.ingress_raw(a_id, "update", wasm_payload).1;
    assert_matches!(ingress_status, IngressStatus::Unknown);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 1);

    // Execute canister A ingress.
    test.execute_message(a_id);
    assert_eq!(test.canister_state(a_id).system_state.canister_version, 1);

    // Make sure the execution was not ok.
    let call_context_manager = test
        .canister_state(a_id)
        .system_state
        .call_context_manager()
        .unwrap();
    assert!(call_context_manager.call_contexts().is_empty());
}
