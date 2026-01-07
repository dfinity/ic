use std::time::Duration;

use assert_matches::assert_matches;

use ic_base_types::NumSeconds;
use ic_error_types::ErrorCode;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_replicated_state::testing::SystemStateTesting;
use ic_replicated_state::{
    CallOrigin,
    canister_state::{NextExecution, WASM_PAGE_SIZE_IN_BYTES},
};
use ic_state_machine_tests::WasmResult;
use ic_sys::PAGE_SIZE;
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::ingress::IngressState;
use ic_types::messages::{CallbackId, RequestMetadata};
use ic_types::{Cycles, NumInstructions, NumOsPages};
use ic_universal_canister::{call_args, wasm};

use ic_config::embedders::StableMemoryPageLimit;
use ic_test_utilities_execution_environment::{
    ExecutionTest, ExecutionTestBuilder, check_ingress_status,
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
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {memory_amount}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#
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
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {memory_amount}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#
    )
}

fn wat_writing_to_each_stable_memory_page_query(memory_amount: u64) -> String {
    format!(
        r#"
        (module
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (import "ic0" "stable64_read"
                (func $stable_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_query go") (local i64)
                (local.set 0 (i64.const 0))
                (drop (call $stable_grow (i64.const 10)))
                (loop $loop
                    (call $stable_write (local.get 0) (i64.const 0) (i64.const 1))
                    (local.set 0 (i64.add (local.get 0) (i64.const 4096))) (;increment by OS page size;)
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {memory_amount}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (func (export "canister_query read")
                (local i64)
                (local i64)
                (local.set 0 (i64.const 0))
                (local.set 1 (i64.const 0))
                (drop (call $stable_grow (i64.const 10)))
                (loop $loop
                    (call $stable_read (local.get 1) (local.get 0) (i64.const 1))
                    (local.set 0 (i64.add (local.get 0) (i64.const 4096))) (;increment by OS page size;)
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {memory_amount}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#
    )
}

// Helper function to allow testing both update and query methods with the same test.
fn with_update_and_replicated_query<F: Fn(&str)>(test: F) {
    test("update");
    test("query");
}

#[test]
fn can_write_to_each_page_in_stable_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(StableMemoryPageLimit {
            upgrade: NumOsPages::new(10),
            message: NumOsPages::new(10),
            query: NumOsPages::new(10),
        })
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

    let max_execution_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(instruction_limit),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        test.canister_wasm_execution_mode(a_id),
    );

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
fn dts_replicated_query_concurrent_cycles_change_succeeds() {
    // Test steps:
    // 1. Canister A starts running the query method.
    // 2. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `ingress_induction_cycles_debit`).
    // 3. The query method resumes and burns 1000 cycles.
    // 4. The query method succeeds because there are enough cycles
    //    in the canister balance to cover both burning and 'ingress_induction_cycles_debit'.
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit_without_dts(instruction_limit)
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let canister_id = test.universal_canister().unwrap();
    let cycles_to_burn = Cycles::new(1000);

    let payload = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .cycles_burn128(cycles_to_burn)
        .build();

    test.update_freezing_threshold(canister_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(canister_id, Some(1), None)
        .unwrap();

    test.ingress_raw(canister_id, "query", payload);

    let freezing_threshold = test.freezing_threshold(canister_id);

    let max_execution_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(instruction_limit),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        test.canister_wasm_execution_mode(canister_id),
    );

    let cycles_debit = Cycles::new(1000);

    // Reset the cycles balance to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + max_execution_cost + cycles_debit + cycles_to_burn;
    let initial_execution_cost = test.canister_execution_cost(canister_id);
    test.canister_state_mut(canister_id)
        .system_state
        .set_balance(initial_cycles);

    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_cycles - max_execution_cost,
    );

    test.canister_state_mut(canister_id)
        .system_state
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    test.execute_message(canister_id);

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_cycles
            - cycles_to_burn
            - (test.canister_execution_cost(canister_id) - initial_execution_cost)
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

    let max_execution_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(instruction_limit),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        test.canister_wasm_execution_mode(a_id),
    );

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
fn dts_replicated_query_concurrent_cycles_change_fails() {
    // Test steps:
    // 1. Canister A starts running the query method.
    // 2. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `ingress_induction_cycles_debit`).
    // 3. The query method resumes and burns 1000 cycles.
    // 4. The query method fails because there are not enough cycles
    //    in the canister balance to cover both burning and 'ingress_induction_cycles_debit'.
    let instruction_limit = 100_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit_without_dts(instruction_limit)
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let canister_id = test.universal_canister().unwrap();
    let cycles_to_burn = Cycles::new(1000);

    let payload = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .cycles_burn128(cycles_to_burn)
        .build();

    test.update_freezing_threshold(canister_id, NumSeconds::from(1))
        .unwrap();
    test.canister_update_allocations_settings(canister_id, Some(1), None)
        .unwrap();

    let (ingress_id, _) = test.ingress_raw(canister_id, "query", payload);

    let freezing_threshold = test.freezing_threshold(canister_id);

    let max_execution_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(instruction_limit),
        test.subnet_size(),
        CanisterCyclesCostSchedule::Normal,
        test.canister_wasm_execution_mode(canister_id),
    );

    let cycles_debit = Cycles::new(1000);

    // Reset the cycles balance to simplify cycles bookkeeping.
    let initial_cycles = freezing_threshold + max_execution_cost + cycles_debit;
    let initial_execution_cost = test.canister_execution_cost(canister_id);
    test.canister_state_mut(canister_id)
        .system_state
        .set_balance(initial_cycles);

    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_cycles - max_execution_cost,
    );

    test.canister_state_mut(canister_id)
        .system_state
        .add_postponed_charge_to_ingress_induction_cycles_debit(cycles_debit);

    test.execute_message(canister_id);

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);

    assert!(err.description().contains(&format!(
        "Canister {canister_id} is out of cycles: \
             please top up the canister with at least"
    )));

    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_cycles
            - (test.canister_execution_cost(canister_id) - initial_execution_cost)
            - cycles_debit,
    );
}

#[test]
fn dirty_pages_cost_the_same_on_app_and_system_subnets() {
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

    assert_eq!(app_instructions, system_instructions);
}

#[test]
fn hitting_page_delta_limit_fails_message() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(StableMemoryPageLimit {
            upgrade: NumOsPages::new(no_pages),
            message: NumOsPages::new(no_pages),
            query: NumOsPages::new(no_pages),
        })
        .build();
    let wat = wat_writing_to_each_stable_memory_page(no_pages * PAGE_SIZE as u64 + 1);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "go", vec![]).unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        &format!(
            "Error from Canister {canister_id}: Canister exceeded memory access \
        limits: Exceeded the limit for the number of modified pages in the stable \
        memory in a single execution: limit {} KB for regular messages, {} KB for \
        upgrade messages and {} KB for queries.",
            no_pages * (PAGE_SIZE as u64 / 1024),
            no_pages * (PAGE_SIZE as u64 / 1024),
            no_pages * (PAGE_SIZE as u64 / 1024)
        ),
    );
}

#[test]
fn hitting_page_delta_limit_fails_message_system_subnet() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(StableMemoryPageLimit {
            upgrade: NumOsPages::new(no_pages),
            message: NumOsPages::new(no_pages),
            query: NumOsPages::new(no_pages),
        })
        .with_subnet_type(SubnetType::System)
        .build();
    let wat = wat_writing_to_each_stable_memory_page(no_pages * PAGE_SIZE as u64 + 1);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "go", vec![]).unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        &format!(
            "Error from Canister {canister_id}: Canister exceeded memory access \
        limits: Exceeded the limit for the number of modified pages in the stable memory \
        in a single execution: limit {} KB for regular messages, {} KB for upgrade \
        messages and {} KB for queries.",
            no_pages * (PAGE_SIZE as u64 / 1024),
            no_pages * (PAGE_SIZE as u64 / 1024),
            no_pages * (PAGE_SIZE as u64 / 1024)
        ),
    );
}

#[test]
fn hitting_page_delta_limit_fails_for_install_code() {
    let no_pages_upgrade = 10;
    // A large enough limit that will never be triggered.
    let no_pages_other_messages = no_pages_upgrade * 10_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(StableMemoryPageLimit {
            upgrade: NumOsPages::new(no_pages_upgrade),
            message: NumOsPages::new(no_pages_other_messages),
            query: NumOsPages::new(no_pages_other_messages),
        })
        .build();
    let wat = wat_writing_to_each_stable_memory_page_long_execution(
        no_pages_upgrade * PAGE_SIZE as u64 + 1,
    );

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    let result = test
        .install_canister(canister_id, wat::parse_str(wat).unwrap())
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        &format!(
            "Error from Canister {canister_id}: Canister exceeded memory access \
        limits: Exceeded the limit for the number of modified pages in the stable memory \
        in a single execution: limit {} KB for regular messages, {} KB for upgrade \
        messages and {} KB for queries.",
            no_pages_other_messages * (PAGE_SIZE as u64 / 1024),
            no_pages_upgrade * (PAGE_SIZE as u64 / 1024),
            no_pages_other_messages * (PAGE_SIZE as u64 / 1024)
        ),
    );
}

#[test]
fn hitting_page_delta_limit_fails_non_replicated_query() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(StableMemoryPageLimit {
            upgrade: NumOsPages::new(no_pages),
            message: NumOsPages::new(no_pages),
            query: NumOsPages::new(no_pages - 1),
        })
        .build();
    let wat = wat_writing_to_each_stable_memory_page_query(no_pages * PAGE_SIZE as u64);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test
        .non_replicated_query(canister_id, "go", vec![])
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        &format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the \
         number of modified pages in the stable memory in a single execution: limit {} KB for regular messages, {} KB for upgrade messages and \
         {} KB for queries.",
         no_pages * (PAGE_SIZE as u64 / 1024), no_pages * (PAGE_SIZE as u64 / 1024), (no_pages - 1) * (PAGE_SIZE as u64 / 1024))
    );
}

#[test]
fn hitting_page_delta_limit_fails_replicated_query() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_dirty_page_limit(StableMemoryPageLimit {
            upgrade: NumOsPages::new(no_pages),
            message: NumOsPages::new(no_pages),
            query: NumOsPages::new(no_pages - 1),
        })
        .build();
    let wat = wat_writing_to_each_stable_memory_page_query(no_pages * PAGE_SIZE as u64);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "go", vec![]).unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        &format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the \
         number of modified pages in the stable memory in a single execution: limit {} KB for regular messages, {} KB for upgrade messages and \
         {} KB for queries.",
         no_pages * (PAGE_SIZE as u64 / 1024), no_pages * (PAGE_SIZE as u64 / 1024), (no_pages - 1) * (PAGE_SIZE as u64 / 1024))
    );
}

#[test]
fn hitting_access_limit_fails_non_replicated_query() {
    let no_pages = 10;
    let mut test = ExecutionTestBuilder::new()
        .with_stable_memory_access_limit(StableMemoryPageLimit {
            message: NumOsPages::new(no_pages),
            upgrade: NumOsPages::new(no_pages),
            query: NumOsPages::new(no_pages - 1),
        })
        .build();
    let wat = wat_writing_to_each_stable_memory_page_query(no_pages * PAGE_SIZE as u64);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test
        .non_replicated_query(canister_id, "read", vec![])
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        &format!("Error from Canister {canister_id}: Canister exceeded memory access limits: Exceeded the limit for the \
        number of accessed pages in the stable memory in a single message execution: limit {} KB for regular messages and \
         {} KB for queries.",
         no_pages * (PAGE_SIZE as u64 / 1024), (no_pages - 1) * (PAGE_SIZE as u64 / 1024))
    );
}

#[test]
fn dts_replicated_execution_resume_fails_due_to_cycles_change() {
    with_update_and_replicated_query(|method| {
        // Test steps:
        // 1. Canister A starts running the update|query method.
        // 2. While canister A is paused, we change its cycles balance.
        // 3. The update|query method resumes, detects the cycles balance mismatch, and
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

        let (ingress_id, _) = test.ingress_raw(a_id, method, a);

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
        let message = if method == "update" {
            "an update call"
        } else {
            "a replicated query"
        };
        err.assert_contains(
            ErrorCode::CanisterWasmEngineError,
            &format!(
                "Error from Canister {a_id}: Canister encountered a Wasm engine error: \
             Failed to apply system changes: Mismatch in cycles \
             balance when resuming {message}"
            ),
        );
    });
}

#[test]
fn dts_replicated_execution_resume_fails_due_to_call_context_change() {
    with_update_and_replicated_query(|method| {
        // Test steps:
        // 1. Canister A starts running the update|query method.
        // 2. While canister A is paused, we change its call context counter.
        // 3. The update|query method resumes, detects the call context mismatch, and
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

        let (ingress_id, _) = test.ingress_raw(a_id, method, a);

        test.execute_slice(a_id);
        assert_eq!(
            test.canister_state(a_id).next_execution(),
            NextExecution::ContinueLong,
        );

        // Change the next call context id of the clean canister.
        let time = test.time();
        test.canister_state_mut(a_id)
            .system_state
            .new_call_context(
                CallOrigin::SystemTask,
                Cycles::new(0),
                time,
                RequestMetadata::for_new_call_tree(time),
            )
            .unwrap();

        test.execute_slice(a_id);

        assert_eq!(
            test.canister_state(a_id).next_execution(),
            NextExecution::None,
        );

        let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::CanisterWasmEngineError);
        let message = if method == "update" {
            "an update call"
        } else {
            "a replicated query"
        };
        assert_eq!(
            err.description(),
            format!(
                "Error from Canister {a_id}: Canister encountered a Wasm engine error: \
             Failed to apply system changes: Mismatch in call \
             context id when resuming {message}"
            )
        );
    });
}

#[test]
fn dts_replicated_execution_does_not_expire_while_executing() {
    with_update_and_replicated_query(|method| {
        // Test steps:
        // 1. Canister A starts running the update|query method.
        // 2. While canister A is paused, we fast forward the time by 1h.
        // 3. The update|query resumes and should not fail due to ingress expiration.
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

        let (ingress_id, _) = test.ingress_raw(a_id, method, a.clone());

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

        let (ingress_id, _) = test.ingress_raw(a_id, method, a);

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
    });
}

#[test]
fn dts_abort_of_replicated_execution_works() {
    with_update_and_replicated_query(|method| {
        let initial_cycles = 1_000_000_000_000_000;
        // Test steps:
        // 1. Canister A runs an update method that calls canister B.
        // 2. The called update|query method of canister B runs with DTS.
        // 3. The called update|query method is aborted.
        // 4. The called update|query method resumes and succeeds.
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
                method,
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
                - test.call_fee(method, &b)
                - test.reply_fee(&[42])
        );

        assert_eq!(
            test.canister_state(b_id).system_state.balance(),
            Cycles::new(initial_cycles) + transferred_cycles - test.canister_execution_cost(b_id)
        );
    });
}

#[test]
fn dts_ingress_induction_cycles_debit_is_applied_on_replicated_execution_aborts() {
    with_update_and_replicated_query(|method| {
        // Test steps:
        // 1. Canister A starts running the update|query method.
        // 2. While canister A is paused, we emulate a postponed charge
        //    of 1000 cycles (i.e. add 1000 to `ingress_induction_cycles_debit`).
        // 3. The update|query method is aborted and we expected the cycles debit to be
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

        let (ingress_id, _) = test.ingress_raw(a_id, method, a);

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
            Cycles::new(initial_canister_cycles)
                - test.canister_execution_cost(a_id)
                - cycles_debit
        );
    });
}

#[test]
fn dts_uninstall_with_aborted_replicated_execution() {
    with_update_and_replicated_query(|method| {
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

        let (message_id, _) = test.ingress_raw(canister_id, method, wasm_payload);

        test.execute_slice(canister_id);
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueLong,
        );

        test.abort_all_paused_executions();

        test.uninstall_code(canister_id).unwrap();

        test.execute_message(canister_id);

        let err = check_ingress_status(test.ingress_status(&message_id)).unwrap_err();
        err.assert_contains(ErrorCode::CanisterWasmModuleNotFound,
            &format!(
                "Error from Canister {canister_id}: Attempted to execute a message, but the canister contains no Wasm module."
            )
        );
    });
}

#[test]
fn stable_grow_updates_subnet_available_memory() {
    let initial_subnet_memory = 11 * WASM_PAGE_SIZE_IN_BYTES as i64;

    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.set_available_execution_memory(initial_subnet_memory);

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
    result.assert_contains(
            ErrorCode::CanisterTrapped,
            &format!(
                "Error from Canister {canister_id}: Canister trapped: 32 bit stable memory api used on a memory larger than 4GB"
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
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
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
    let msg_id = test.ingress_raw(a_id, "update", wasm_payload).0;
    assert_matches!(test.ingress_state(&msg_id), IngressState::Received);
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
