use std::collections::HashMap;

use crate::execution::test_utilities::{check_ingress_status, ExecutionTest, ExecutionTestBuilder};
use ic_error_types::ErrorCode;
use ic_ic00_types::{EmptyBlob, Payload};
use ic_logger::replica_logger::LogEntryLogger;
use ic_replicated_state::{canister_state::NextExecution, CanisterState};
use ic_state_machine_tests::{IngressState, WasmResult};
use ic_test_utilities::types::ids::user_test_id;
use ic_test_utilities_metrics::fetch_int_counter;
use ic_types::Cycles;
use maplit::btreeset;

////////////////////////////////////////////////////////////////////////
// Constants and templates

/// Slice size used across tests is 1K instructions
const MAX_INSTRUCTIONS_PER_SLICE: u64 = 1_000;
/// Declare local variables for a loop in WAT
const LOOP_LOCALS_WAT: &str = r#"
                (local $i i32)
"#;
/// Declare loop which takes 996 instructions (roughly 1K)
const LOOP_1K_WAT: &str = r#"
                (set_local $i (i32.const 0))
                (loop $loop
                    ;; Each iteration loop takes `9 + 6` instructions,
                    ;; so 110 iterations is 996 instructions.
                    (if (i32.lt_s (get_local $i) (i32.const 110))
                        (then
                            (set_local $i (i32.add (get_local $i) (i32.const 1)))
                            (br $loop)
                        )
                    )
                )
"#;

////////////////////////////////////////////////////////////////////////
// Helpers

/// Function to generate WAT for
#[derive(Debug, Clone, Copy)]
enum Function {
    PreUpgrade,
    Start,
    PostUpgrade,
}

/// WAT successful or failed execution
#[derive(Debug, Clone, Copy)]
enum Execution {
    /// Short successful execution
    Short,
    /// Long successful execution (2 x short execution)
    Long,
    /// Very long successful execution (3 x short execution)
    VeryLong,
    /// Trap after a short execution
    ShortTrap,
    /// Trap after a long execution
    LongTrap,
    /// Execution hits instructions limit (3 x short execution)
    InstructionsLimit,
}

/// Returns `ExecutionTest` with instruction limit set for `max_rounds`
fn execution_test_with_max_rounds(max_rounds: u64) -> ExecutionTest {
    ExecutionTestBuilder::new()
        .with_log(
            LogEntryLogger::new(
                slog::Logger::root(slog::Discard, slog::o!()),
                slog::Level::Trace,
                vec![],
                HashMap::new(),
                vec![],
            )
            .into(),
        )
        .with_deterministic_time_slicing()
        .with_install_code_slice_instruction_limit(MAX_INSTRUCTIONS_PER_SLICE)
        .with_install_code_instruction_limit(MAX_INSTRUCTIONS_PER_SLICE * max_rounds)
        .with_cost_to_compile_wasm_instruction(0)
        .build()
}

/// Asserts canister state after a successful upgrade
fn assert_canister_state_after_ok(state_before: &CanisterState, state_after: &CanisterState) {
    assert_ne!(state_before.system_state, state_after.system_state);
    assert_ne!(state_before.execution_state, state_after.execution_state);
    assert_eq!(state_before.scheduler_state, state_after.scheduler_state);
}

/// Asserts canister state after a failed upgrade
fn assert_canister_state_after_err(state_before: &CanisterState, state_after: &CanisterState) {
    assert_ne!(state_before.system_state, state_after.system_state);
    assert_eq!(state_before.execution_state, state_after.execution_state);
    assert_eq!(state_before.scheduler_state, state_after.scheduler_state);
}

/// Returns a WAT module
fn module<D: std::fmt::Display>(functions: D) -> String {
    format!(
        r#"
        (module
            {functions}
        )"#
    )
}

/// Returns a WAT for a specified `function` and `execution`.
///
/// The function could be one of: `PreUpgrade`, `Start`, `PostUpgrade`.
///
/// The execution could be either a successful one (with a specified complexity),
/// or a failed one (with a specified failure).
fn func(function: Function, execution: Execution) -> String {
    let func = match function {
        Function::PreUpgrade => r#"func (export "canister_pre_upgrade")"#,
        Function::Start => r#"start $start)(func $start"#,
        Function::PostUpgrade => r#"func (export "canister_post_upgrade")"#,
    };
    match execution {
        Execution::Short => format!(
            r#"({func}
                {LOOP_LOCALS_WAT}
                ;; With `slice_instructions_limit` set to 1K, this should
                ;; take 1 round to complete.
                {LOOP_1K_WAT}
                )"#
        ),
        Execution::Long => format!(
            r#"({func}
                {LOOP_LOCALS_WAT}
                ;; With `slice_instructions_limit` set to 1K, this should
                ;; take 2 rounds to complete.
                {LOOP_1K_WAT}
                {LOOP_1K_WAT}
                )"#
        ),
        Execution::ShortTrap => format!("({func} (unreachable))"),
        Execution::LongTrap => format!(
            r#"({func}
                {LOOP_LOCALS_WAT}
                ;; With `slice_instructions_limit` set to 1K, this should
                ;; take 2 rounds to fail.
                {LOOP_1K_WAT}
                {LOOP_1K_WAT}
                (unreachable)
                )"#
        ),
        Execution::VeryLong | Execution::InstructionsLimit => format!(
            r#"({func}
                {LOOP_LOCALS_WAT}
                ;; With `slice_instructions_limit` set to 1K, this should
                ;; take 3 rounds to complete.
                {LOOP_1K_WAT}
                {LOOP_1K_WAT}
                {LOOP_1K_WAT}
                )"#
        ),
    }
}

/// Returns a new WASM binary for a specified slice of functions.
fn binary(functions: &[(Function, Execution)]) -> Vec<u8> {
    let wat = module(
        functions
            .iter()
            .map(|(f, e)| func(*f, *e))
            .collect::<Vec<_>>()
            .join("\n            "),
    );
    wabt::wat2wasm(wat).unwrap()
}

/// Returns an old empty WASM binary.
fn old_empty_binary() -> Vec<u8> {
    wabt::wat2wasm(module("")).unwrap()
}

/// Returns a new empty WASM binary.
fn new_empty_binary() -> Vec<u8> {
    wabt::wat2wasm(module(r#"(func (export "new"))"#)).unwrap()
}

////////////////////////////////////////////////////////////////////////
// execute_upgrade()
// 1. if let Err(err) = helper.validate_input(..)
// 2. if let Err(err) = helper.reserve_execution_cycles(..)
// 3. match helper.canister().execution_state
//    3a. None
// 4. if !execution_state.exports_method(..)
// 5. match execute_dts(..)
//    5a. Finished
//    5b. Paused

#[test]
fn upgrade_fails_on_invalid_input() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    // The default user id is 1
    test.set_user_id(user_test_id(999));
    let result = test.upgrade_canister(canister_id, new_empty_binary());
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterInvalidController
    );
    assert_eq!(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_not_enough_cycles() {
    let mut test = execution_test_with_max_rounds(1);
    // Should be enough cycles to create the canister, but not enough to upgrade it
    let balance_cycles = test
        .cycles_account_manager()
        .execution_cost((MAX_INSTRUCTIONS_PER_SLICE * 3).into(), test.subnet_size());
    let canister_id = test
        .canister_from_cycles_and_binary(Cycles::new(balance_cycles.into()), old_empty_binary())
        .unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let result = test.upgrade_canister(canister_id, new_empty_binary());
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterOutOfCycles);
    assert_eq!(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_no_execution_state() {
    let mut test = execution_test_with_max_rounds(1);
    // Create canister with no binary and hence no execution state
    let canister_id = test.create_canister(1_000_000_000_u64.into());
    let canister_state_before = test.canister_state(canister_id).clone();

    let result = test.upgrade_canister(canister_id, new_empty_binary());
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterWasmModuleNotFound
    );
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_no_pre_upgrade() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let result = test.upgrade_canister(canister_id, new_empty_binary());
    assert_eq!(result, Ok(()));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_short_pre_upgrade() {
    let mut test = execution_test_with_max_rounds(1);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::Short)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let result = test.upgrade_canister(canister_id, new_empty_binary());
    assert_eq!(result, Ok(()));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_long_pre_upgrade() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::Long)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_empty_binary());
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// upgrade_stage_1_process_pre_upgrade_result()
// 1. if let Err(err) = result

#[test]
fn upgrade_fails_on_short_pre_upgrade_trap() {
    let mut test = execution_test_with_max_rounds(1);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::ShortTrap)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let result = test.upgrade_canister(canister_id, new_empty_binary());
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterTrapped);
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_long_pre_upgrade_trap() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::LongTrap)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_empty_binary());
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterTrapped);
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_long_pre_upgrade_hits_instructions_limit() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::InstructionsLimit)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_empty_binary());
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterInstructionLimitExceeded
    );
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// upgrade_stage_2_and_3a_create_execution_state_and_call_start()
// 1. if let Err(err) = helper.replace_execution_state_and_allocations(..)
// 2. if !execution_state.exports_method(Start)
// 3. match execute_dts(..)
//    3a. Finished
//    3b. Paused

#[test]
fn upgrade_fails_on_invalid_new_canister() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let result = test.upgrade_canister(canister_id, vec![]);
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterInvalidWasm);
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_no_start() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let result = test.upgrade_canister(canister_id, new_empty_binary());
    assert_eq!(result, Ok(()));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_short_start() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::Short)]);
    let result = test.upgrade_canister(canister_id, new_binary);
    assert_eq!(result, Ok(()));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_long_start() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::Long)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// upgrade_stage_3b_process_start_result()
// 1. if let Err(err) = result

#[test]
fn upgrade_fails_on_short_start_trap() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::ShortTrap)]);
    let result = test.upgrade_canister(canister_id, new_binary);
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterTrapped);
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_long_start_trap() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::LongTrap)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterTrapped);
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_long_start_hits_instructions_limit() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::InstructionsLimit)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterInstructionLimitExceeded
    );
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// upgrade_stage_4a_call_post_upgrade()
// 1. if !execution_state.exports_method(PostUpgrade)
// 2. match execute_dts(..)
//    2a. Finished
//    2b. Paused

#[test]
fn upgrade_ok_with_no_post_upgrade() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::Short)]);
    let result = test.upgrade_canister(canister_id, new_binary);
    assert_eq!(result, Ok(()));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_short_post_upgrade() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::Short)]);
    let result = test.upgrade_canister(canister_id, new_binary);
    assert_eq!(result, Ok(()));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_long_post_upgrade() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::Long)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// upgrade_stage_4b_process_post_upgrade_result()
// 1. if let Err(err) = result

#[test]
fn upgrade_fails_on_short_post_upgrade_trap() {
    let mut test = execution_test_with_max_rounds(1);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::ShortTrap)]);
    let result = test.upgrade_canister(canister_id, new_binary);
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterTrapped);
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_long_post_upgrade_trap() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::LongTrap)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterTrapped);
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_fails_on_long_post_upgrade_hits_instructions_limit() {
    // Long execution takes 2 round
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::InstructionsLimit)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterInstructionLimitExceeded
    );
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// PausedPreUpgradeExecution
// 1. Debug -> the paused execution is private and cannot be debug printed :(
// 2. match InstallCodeHelper::resume(..)
//    2a. Err(..)
// 3. match wasm_execution_result
//    3a. Finished (covered with Paused)
//    3b. Paused
// 4. abort(..)

#[test]
fn upgrade_fails_on_pre_upgrade_resume_error() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::Long)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_empty_binary());
    // Change canister controller to make it invalid
    // The default user id is 1, so changing it to 999 make the paused canister invalid
    let canister = test.canister_state_mut(canister_id);
    canister.system_state.controllers = btreeset! {user_test_id(999).get()};
    // Execute one more round
    assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
    test.execute_slice(canister_id);
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterInvalidController
    );
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_paused_pre_upgrade_resume_paused() {
    // Very long execution takes 3 rounds
    let mut test = execution_test_with_max_rounds(3);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::VeryLong)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_empty_binary());
    // Execute more rounds
    for _round in 1..3 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_on_pre_upgrade_abort() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::Long)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_empty_binary());
    // Abort all executions, so the progress is reset
    test.abort_all_paused_executions();
    assert_eq!(
        fetch_int_counter(test.metrics_registry(), "executions_aborted"),
        Some(1)
    );
    // Execute more rounds
    for _round in 0..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// PausedStartExecutionDuringUpgrade
// 1. Debug -> the paused execution is private and cannot be debug printed :(
// 2. match InstallCodeHelper::resume(..)
//    2a. Err(..)
// 3. match wasm_execution_result
//    3a. Finished (covered with Paused)
//    3b. Paused
// 4. abort(..)

#[test]
fn upgrade_fails_on_start_resume_error() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::Long)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Change canister controller to make it invalid
    // The default user id is 1, so changing it to 999 make the paused canister invalid
    let canister = test.canister_state_mut(canister_id);
    canister.system_state.controllers = btreeset! {user_test_id(999).get()};
    // Execute one more round
    assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
    test.execute_slice(canister_id);
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterInvalidController
    );
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_paused_start_resume_paused() {
    // Very long execution takes 3 rounds
    let mut test = execution_test_with_max_rounds(3);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::VeryLong)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..3 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_on_start_abort() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::Start, Execution::Long)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Abort all executions, so the progress is reset
    test.abort_all_paused_executions();
    assert_eq!(
        fetch_int_counter(test.metrics_registry(), "executions_aborted"),
        Some(1)
    );
    // Execute more rounds
    for _round in 0..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// PausedPostUpgradeExecution
// 1. Debug -> the paused execution is private and cannot be debug printed :(
// 2. match InstallCodeHelper::resume(..)
//    2a. Err(..)
// 3. match wasm_execution_result
//    3a. Finished (covered with Paused)
//    3b. Paused
// 4. abort(..)

#[test]
fn upgrade_fails_on_post_upgrade_resume_error() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::Long)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Change canister controller to make it invalid
    // The default user id is 1, so changing it to 999 make the paused canister invalid
    let canister = test.canister_state_mut(canister_id);
    canister.system_state.controllers = btreeset! {user_test_id(999).get()};
    // Execute one more round
    assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
    test.execute_slice(canister_id);
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterInvalidController
    );
    assert_canister_state_after_err(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_with_paused_post_upgrade_resume_paused() {
    // Very long execution takes 3 rounds
    let mut test = execution_test_with_max_rounds(3);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::VeryLong)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds
    for _round in 1..3 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn upgrade_ok_on_post_upgrade_abort() {
    // Long execution takes 2 rounds
    let mut test = execution_test_with_max_rounds(2);
    let canister_id = test.canister_from_binary(old_empty_binary()).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::Long)]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Abort all executions, so the progress is reset
    test.abort_all_paused_executions();
    // Execute more rounds
    for _round in 0..2 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

////////////////////////////////////////////////////////////////////////
// End-to-end: happy paths

#[test]
fn upgrade_ok_with_long_pre_upgrade_long_start_long_post_upgrade() {
    // There are 3 long executions (pre-, start and post-upgrade), 2 rounds each
    let mut test = execution_test_with_max_rounds(6);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::Long)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();
    let canister_state_before = test.canister_state(canister_id).clone();

    let new_binary = binary(&[
        (Function::Start, Execution::Long),
        (Function::PostUpgrade, Execution::Long),
    ]);
    // The first round is executed in the `dts_upgrade_canister()`
    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    // Execute more rounds.
    // If the execution of a pre-upgrade or start function finishes before
    // we hit the slice instruction limit, we start the next execution and
    // reset the slice limit. So the total number of rounds to finish 3
    // 2-round executions is 4.
    for _round in 1..4 {
        assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
        test.execute_slice(canister_id);
    }
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
    assert_canister_state_after_ok(&canister_state_before, test.canister_state(canister_id));
}

#[test]
fn dts_uninstall_with_aborted_upgrade() {
    let mut test = execution_test_with_max_rounds(6);
    let old_binary = binary(&[(Function::PreUpgrade, Execution::Long)]);
    let canister_id = test.canister_from_binary(old_binary).unwrap();

    let new_binary = binary(&[(Function::PostUpgrade, Execution::Long)]);

    let message_id = test.dts_upgrade_canister(canister_id, new_binary);
    assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueInstallCode
    );

    test.abort_all_paused_executions();

    test.uninstall_code(canister_id).unwrap();

    while test.canister_state(canister_id).next_execution() == NextExecution::ContinueInstallCode {
        test.execute_slice(canister_id);
    }

    let err = check_ingress_status(test.ingress_status(&message_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmModuleNotFound);
    assert_eq!(
        err.description(),
        format!(
            "Attempt to execute a message on canister {} which contains no Wasm module",
            canister_id,
        )
    );
}
