use ic_error_types::{ErrorCode, UserError};
use ic_types::{CanisterId, Cycles, NumInstructions};

use crate::execution::test_utilities::{check_ingress_status, ExecutionTest, ExecutionTestBuilder};
use ic_ic00_types::{CanisterInstallMode, EmptyBlob, InstallCodeArgs, Method, Payload};
use ic_replicated_state::canister_state::NextExecution;
use ic_test_utilities_metrics::fetch_int_counter;
use ic_types::ingress::WasmResult;
use ic_types::messages::MessageId;
use ic_types_test_utils::ids::user_test_id;
use wabt::{wat2wasm, wat2wasm_with_features};

const DTS_INSTALL_WAT: &str = r#"
    (module
        (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
        (import "ic0" "stable_read"
            (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
        )
        (import "ic0" "stable_write"
            (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
        )
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32))
        )
        (func (export "canister_query read")
            (call $stable_read (i32.const 0) (i32.const 0) (i32.const 10))
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 10)) ;; length
            (call $msg_reply)
        )
        (func $start
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 12) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 23) (i32.const 1000))
        )
        (func (export "canister_init")
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
        )
        (start $start)
        (memory 0 20)
    )"#;

#[test]
fn install_code_fails_on_invalid_compute_allocation() {
    let mut test = ExecutionTestBuilder::new().build();
    let binary = wabt::wat2wasm("(module)").unwrap();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));
    let err = test
        .install_canister_with_allocation(canister, binary, Some(1_000), None)
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert_eq!(
        "ComputeAllocation expected to be in the range [0..100], got 1_000",
        err.description()
    );
}

#[test]
fn install_code_fails_on_invalid_memory_allocation() {
    let mut test = ExecutionTestBuilder::new().build();
    let binary = wabt::wat2wasm("(module)").unwrap();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));
    let err = test
        .install_canister_with_allocation(canister, binary, None, Some(u64::MAX))
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert_eq!(
        "MemoryAllocation expected to be in the range [0..55_834_574_848], got 18_446_744_073_709_551_615",
        err.description()
    );
}

#[test]
fn dts_resume_works_in_install_code() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(DTS_INSTALL_WAT, features).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };
    let original_system_state = test.canister_state(canister_id).system_state.clone();
    let original_execution_cost = test.canister_execution_cost(canister_id);
    let ingress_id = test.dts_install_code(payload);
    for _ in 0..4 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        assert_eq!(
            test.canister_state(canister_id).system_state.balance(),
            original_system_state.balance()
                - test
                    .cycles_account_manager()
                    .execution_cost(NumInstructions::from(1_000_000), test.subnet_size()),
        );
        test.execute_slice(canister_id);
    }
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        original_system_state.balance()
            - (test.canister_execution_cost(canister_id) - original_execution_cost)
    );
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
}

#[test]
fn dts_abort_works_in_install_code() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(DTS_INSTALL_WAT, features).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };
    let original_system_state = test.canister_state(canister_id).system_state.clone();
    let original_execution_cost = test.canister_execution_cost(canister_id);
    let ingress_id = test.dts_install_code(payload);
    for _ in 0..3 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        assert_eq!(
            test.canister_state(canister_id).system_state.balance(),
            original_system_state.balance()
                - test
                    .cycles_account_manager()
                    .execution_cost(NumInstructions::from(1_000_000), test.subnet_size()),
        );
        test.execute_slice(canister_id);
    }

    test.abort_all_paused_executions();
    assert_eq!(
        fetch_int_counter(test.metrics_registry(), "executions_aborted"),
        Some(1)
    );

    for _ in 0..5 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        assert_eq!(
            test.canister_state(canister_id).system_state.balance(),
            original_system_state.balance()
                - test
                    .cycles_account_manager()
                    .execution_cost(NumInstructions::from(1_000_000), test.subnet_size()),
        );
        test.execute_slice(canister_id);
    }

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        original_system_state.balance()
            - (test.canister_execution_cost(canister_id) - original_execution_cost)
    );

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
}

#[test]
fn install_code_validate_input_compute_allocation() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    test.create_canister_with_allocation(Cycles::new(2_000_000_000_000_000), Some(50), None)
        .unwrap();

    let canister_id = test
        .create_canister_with_allocation(Cycles::new(2_000_000_000_000_000), Some(40), None)
        .unwrap();
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(DTS_INSTALL_WAT, features).unwrap(),
        arg: vec![],
        compute_allocation: Some(candid::Nat::from(90u64)),
        memory_allocation: None,
        query_allocation: None,
    };

    let message_id = test.subnet_message_raw(Method::InstallCode, payload.encode());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    // Start execution of install code.
    test.execute_subnet_message();
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result,
        Err(UserError::new(ErrorCode::SubnetOversubscribed, "Canister requested a compute allocation of 90% which cannot be satisfied because the Subnet's remaining compute capacity is 49%"))
    );
}

#[test]
fn install_code_validate_input_memory_allocation() {
    let mib: u64 = 1024 * 1024;
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(500 * mib as i64)
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    test.create_canister_with_allocation(
        Cycles::new(20_000_000_000_000_000),
        None,
        Some(250 * mib),
    )
    .unwrap();

    let canister_id = test
        .create_canister_with_allocation(
            Cycles::new(20_000_000_000_000_000),
            Some(40),
            Some(240 * mib),
        )
        .unwrap();
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: vec![],
        arg: vec![],
        compute_allocation: None,
        memory_allocation: Some(candid::Nat::from(260 * mib)),
        query_allocation: None,
    };

    let message_id = test.subnet_message_raw(Method::InstallCode, payload.encode());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    // Start execution of install code.
    test.execute_subnet_message();
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result,
        Err(UserError::new(ErrorCode::SubnetOversubscribed, "Canister with memory allocation 260MiB cannot be installed because the Subnet's remaining memory capacity is 10MiB"))
    );
}

#[test]
fn install_code_validate_input_controller() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let controller = user_test_id(1);
    test.set_user_id(controller);
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));

    let sender = user_test_id(2);
    test.set_user_id(sender);
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(DTS_INSTALL_WAT, features).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };

    // Install code from a non-controller.
    let message_id = test.subnet_message_raw(Method::InstallCode, payload.encode());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );
    test.execute_subnet_message();
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterInvalidController,
            format!("Only the controllers of the canister {} can control it.\nCanister's controllers: {}\nSender's ID: {}", canister_id, controller,  sender)
        ))
    );
}

#[test]
fn install_code_validates_execution_state() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let mut payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm(r#"(module (memory 0 20))"#).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };

    // Install code on empty canister.
    assert!(test
        .subnet_message(Method::InstallCode, payload.encode())
        .is_ok());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    payload.wasm_module = wat2wasm_with_features(DTS_INSTALL_WAT, features).unwrap();

    // Install code on non-empty canister fails.
    let message_id = test.subnet_message_raw(Method::InstallCode, payload.encode());
    test.execute_subnet_message();
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(result,
               Err(UserError::new(
                   ErrorCode::CanisterNonEmpty,
                   format!("Canister {} cannot be installed because the canister is not empty. Try installing with mode='reinstall' instead.", canister_id)))
    );
}

fn execute_install_code_message_dts_helper(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    wasm: &str,
) -> MessageId {
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(wasm, features).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };

    // Send install code message.
    let message_id = test.subnet_message_raw(Method::InstallCode, payload.encode());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    // Start execution of install code.
    let original_system_state = test.canister_state(canister_id).system_state.clone();
    test.execute_subnet_message();

    // Execute all slices.
    for _ in 0..2 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        assert_eq!(
            test.canister_state(canister_id).system_state.balance(),
            original_system_state.balance()
                - test
                    .cycles_account_manager()
                    .execution_cost(NumInstructions::from(1_000_000), test.subnet_size()),
        );
        test.execute_slice(canister_id);
    }
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    message_id
}

#[test]
fn install_code_with_start_with_err() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let wasm: &str = r#"
    (module
    
        (func $start
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 13) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 14) (i32.const 1000))
             unreachable
        )
        (start $start)
        (memory 0 20)
    )"#;

    let message_id = execute_install_code_message_dts_helper(&mut test, canister_id, wasm);

    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterTrapped,
            format!("Canister {} trapped: unreachable", canister_id)
        ))
    );
}

#[test]
fn install_code_with_start_with_success() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let wasm: &str = r#"
    (module
        (func $start
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 13) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 14) (i32.const 1000))
        )
        (start $start)
        (memory 0 20)
    )"#;

    let message_id = execute_install_code_message_dts_helper(&mut test, canister_id, wasm);

    assert!(check_ingress_status(test.ingress_status(&message_id)).is_ok());
}

fn start_install_code_dts(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    wasm: &str,
) -> MessageId {
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(wasm, features).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };

    // Send install code message.
    let message_id = test.subnet_message_raw(Method::InstallCode, payload.encode());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    // Start execution of install code.
    test.execute_subnet_message();
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueInstallCode
    );

    message_id
}

fn execute_install_code_init_dts_helper(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    wasm: &str,
) -> MessageId {
    let message_id = start_install_code_dts(test, canister_id, wasm);

    // Execute next slice.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    message_id
}

#[test]
fn install_code_with_init_method_with_error() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let wasm: &str = r#"
    (module
         (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
         (func (export "canister_init")
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (drop (call $stable_grow (i32.const 1)))
            unreachable
        )
        (memory 0 20)
    )"#;

    let message_id = execute_install_code_init_dts_helper(&mut test, canister_id, wasm);

    let result = check_ingress_status(test.ingress_status(&message_id));
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterTrapped,
            format!("Canister {} trapped: unreachable", canister_id)
        ))
    );
}

#[test]
fn install_code_with_init_method_success() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let wasm: &str = r#"
    (module
         (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
         (func (export "canister_init")
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (drop (call $stable_grow (i32.const 1)))
        )
        (memory 0 20)
    )"#;

    let message_id = execute_install_code_init_dts_helper(&mut test, canister_id, wasm);

    assert!(check_ingress_status(test.ingress_status(&message_id)).is_ok());
}

#[test]
fn reserve_cycles_for_execution_fails_when_not_enough_cycles() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let canister_id = test.create_canister(Cycles::new(900_000));
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(DTS_INSTALL_WAT, features).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };
    let original_balance = test.canister_state(canister_id).system_state.balance();
    let message_id = test.dts_install_code(payload);
    let minimum_balance = test.install_code_reserved_execution_cycles();

    // Check reserve execution cycles fails due to not enough balance.
    assert_eq!(
        check_ingress_status(test.ingress_status(&message_id)),
        Err(UserError::new(
            ErrorCode::CanisterOutOfCycles,
            format!("Canister installation failed with `Canister {} is out of cycles: requested {} cycles but the available balance is {} cycles and the freezing threshold 0 cycles`", canister_id, 
            minimum_balance, original_balance)
        ))
    );
}

#[test]
fn install_code_running_out_of_instructions() {
    let mut test = ExecutionTestBuilder::new()
        // Set the install message limit very low to hit it while executing.
        .with_install_code_instruction_limit(1_500)
        .with_install_code_slice_instruction_limit(1000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .with_cost_to_compile_wasm_instruction(0)
        .build();
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let wasm: &str = r#"
    (module
         (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
         (func (export "canister_init")
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (drop (call $stable_grow (i32.const 1)))
            unreachable
        )
        (memory 0 20)
    )"#;

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat2wasm_with_features(wasm, features).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        query_allocation: None,
    };

    // Send install code message and start execution.
    let message_id = test.dts_install_code(payload);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueInstallCode
    );

    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    assert_eq!(
        check_ingress_status(test.ingress_status(&message_id)),
        Err(UserError::new(
            ErrorCode::CanisterInstructionLimitExceeded,
            format!(
                "Canister {} exceeded the instruction limit for single message execution.",
                canister_id
            )
        ))
    );
}

#[test]
fn dts_uninstall_with_aborted_install_code() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let wasm: &str = r#"
    (module
         (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
         (func (export "canister_init")
            (drop (memory.grow (i32.const 1)))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
        )
        (memory 0 20)
    )"#;

    let message_id = start_install_code_dts(&mut test, canister_id, wasm);

    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueInstallCode,
    );

    test.abort_all_paused_executions();

    test.uninstall_code(canister_id).unwrap();

    while test.canister_state(canister_id).next_execution() == NextExecution::ContinueInstallCode {
        test.execute_slice(canister_id);
    }

    let result = check_ingress_status(test.ingress_status(&message_id)).unwrap();
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
}
