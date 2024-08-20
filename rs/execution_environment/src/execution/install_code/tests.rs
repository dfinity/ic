use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_error_types::{ErrorCode, UserError};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_replicated_state::canister_state::system_state::wasm_chunk_store;
use ic_replicated_state::{ExecutionTask, ReplicatedState};
use ic_state_machine_tests::{IngressState, IngressStatus};
use ic_types::{
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
};

use ic_management_canister_types::InstallChunkedCodeArgsLegacy;
use ic_management_canister_types::{
    CanisterChange, CanisterChangeDetails, CanisterChangeOrigin, CanisterInstallMode,
    CanisterInstallModeV2, EmptyBlob, InstallChunkedCodeArgs, InstallCodeArgs, InstallCodeArgsV2,
    Method, Payload, UploadChunkArgs, UploadChunkReply,
};
use ic_replicated_state::canister_state::NextExecution;
use ic_test_utilities_execution_environment::{
    check_ingress_status, get_reply, ExecutionTest, ExecutionTestBuilder,
};
use ic_test_utilities_metrics::fetch_int_counter;
use ic_types::messages::MessageId;
use ic_types::{ingress::WasmResult, MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES};
use ic_types_test_utils::ids::user_test_id;
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use maplit::btreemap;
use std::mem::size_of;

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
    let binary = wat::parse_str("(module)").unwrap();
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
    let binary = wat::parse_str("(module)").unwrap();
    let canister = test.create_canister(Cycles::new(1_000_000_000_000));
    let err = test
        .install_canister_with_allocation(canister, binary, None, Some(u64::MAX))
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert_eq!(
        format!(
            "MemoryAllocation expected to be in the range [0..{}], got 18_446_744_073_709_551_615",
            candid::Nat((MAX_STABLE_MEMORY_IN_BYTES + MAX_WASM_MEMORY_IN_BYTES).into())
        ),
        err.description()
    );
}

#[test]
fn dts_resume_works_in_install_code() {
    const INSTRUCTION_LIMIT: u64 = 3_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(INSTRUCTION_LIMIT)
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .build();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
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
                    .execution_cost(NumInstructions::from(INSTRUCTION_LIMIT), test.subnet_size()),
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
    const INSTRUCTION_LIMIT: u64 = 3_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(INSTRUCTION_LIMIT)
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .build();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
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
                    .execution_cost(NumInstructions::from(INSTRUCTION_LIMIT), test.subnet_size()),
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
                    .execution_cost(NumInstructions::from(INSTRUCTION_LIMIT), test.subnet_size()),
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
        .with_manual_execution()
        .build();
    test.create_canister_with_allocation(Cycles::new(2_000_000_000_000_000), Some(50), None)
        .unwrap();

    let canister_id = test
        .create_canister_with_allocation(Cycles::new(2_000_000_000_000_000), Some(40), None)
        .unwrap();
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: Some(candid::Nat::from(90u64)),
        memory_allocation: None,
        sender_canister_version: None,
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
        Err(UserError::new(ErrorCode::SubnetOversubscribed, "Canister requested a compute allocation of 90% which cannot be satisfied because the Subnet's remaining compute capacity is 49%."))
    );
}

#[test]
fn install_code_validate_input_memory_allocation() {
    let mib: u64 = 1024 * 1024;
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(500 * mib as i64)
        .with_subnet_memory_reservation(0)
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
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
        sender_canister_version: None,
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
        Err(UserError::new(ErrorCode::SubnetOversubscribed, "Canister requested 260.00 MiB of memory but only 250.00 MiB are available in the subnet."))
    );
}

#[test]
fn install_code_validate_input_controller() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .build();
    let controller = user_test_id(1);
    test.set_user_id(controller);
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));

    let sender = user_test_id(2);
    test.set_user_id(sender);
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
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
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let mut payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(r#"(module (memory 0 20))"#).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    // Install code on empty canister.
    assert!(test
        .subnet_message(Method::InstallCode, payload.encode())
        .is_ok());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );

    payload.wasm_module = wat::parse_str(DTS_INSTALL_WAT).unwrap();

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

#[test]
fn install_code_fails_when_not_enough_wasm_custom_sections_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000_000)
        .with_install_code_slice_instruction_limit(1_000_000_000)
        .with_subnet_wasm_custom_sections_memory(32)
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: include_bytes!("../../../tests/test-data/custom_sections.wasm").to_vec(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    // Install code on canister with Wasm sections that are larger than the available memory on the subnet.
    let message_id = test.subnet_message_raw(Method::InstallCode, payload.encode());
    test.execute_subnet_message();
    let result = check_ingress_status(test.ingress_status(&message_id));
    assert!(result.is_err());
}

#[test]
fn install_code_succeeds_with_enough_wasm_custom_sections_memory() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000_000)
        .with_install_code_slice_instruction_limit(1_000_000_000)
        .with_subnet_wasm_custom_sections_memory(1024 * 1024) // 1MiB
        .with_manual_execution()
        .build();
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: include_bytes!("../../../tests/test-data/custom_sections.wasm").to_vec(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    // Install code on canister with Wasm sections that fit in the available memory on the subnet.
    assert!(test
        .subnet_message(Method::InstallCode, payload.encode())
        .is_ok());
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );
}

#[test]
fn install_code_respects_wasm_custom_sections_available_memory() {
    // As we install canisters in a loop, using more memory spawns thousands of
    // canister sandboxes, which lead to a few GiB memory usage.
    let available_wasm_custom_sections_memory = 20 * 1024; // 20KiB

    // This value might need adjustment if something changes in the canister's
    // wasm that gets installed in the test.
    let total_memory_taken_per_canister_in_bytes = 364249;

    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000_000)
        .with_install_code_slice_instruction_limit(1_000_000_000)
        .with_subnet_wasm_custom_sections_memory(available_wasm_custom_sections_memory)
        .with_manual_execution()
        .build();

    let subnet_available_memory_before = test.subnet_available_memory().get_execution_memory();
    let mut iterations = 0;
    loop {
        let canister_id = test
            .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
            .unwrap();

        let payload = InstallCodeArgs {
            mode: CanisterInstallMode::Install,
            canister_id: canister_id.get(),
            wasm_module: include_bytes!("../../../tests/test-data/custom_sections.wasm").to_vec(),
            arg: vec![],
            compute_allocation: None,
            memory_allocation: None,
            sender_canister_version: None,
        };

        if test
            .subnet_message(Method::InstallCode, payload.encode())
            .is_err()
        {
            // We expect that at some point there is not enough wasm custom sections
            // memory left on the subnet and the request to install the canister
            // will fail.
            break;
        }
        iterations += 1;
    }

    // One more request to install a canister with wasm custom sections should fail.
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: include_bytes!("../../../tests/test-data/custom_sections.wasm").to_vec(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };
    let result = test.subnet_message(Method::InstallCode, payload.encode());

    assert!(result.is_err());
    assert_eq!(
        test.subnet_available_memory().get_execution_memory(),
        subnet_available_memory_before - iterations * total_memory_taken_per_canister_in_bytes
    );
}

fn execute_install_code_message_dts_helper(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    wasm: &str,
) -> MessageId {
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(wasm).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
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

    let err = check_ingress_status(test.ingress_status(&message_id)).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {}: Canister trapped: unreachable",
            canister_id
        ),
    );
}

#[test]
fn install_code_with_start_with_success() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
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
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(wasm).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
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

    let err = check_ingress_status(test.ingress_status(&message_id)).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {}: Canister trapped: unreachable",
            canister_id
        ),
    );
}

#[test]
fn install_code_with_init_method_success() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
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
        .with_manual_execution()
        .build();
    // canister history memory usage at the beginning of attempted install
    let canister_history_memory_usage = size_of::<CanisterChange>() + size_of::<PrincipalId>();
    let freezing_threshold_cycles = test.cycles_account_manager().freeze_threshold_cycles(
        ic_config::execution_environment::Config::default().default_freeze_threshold,
        MemoryAllocation::BestEffort,
        NumBytes::new(canister_history_memory_usage as u64),
        NumBytes::new(0),
        ComputeAllocation::zero(),
        test.subnet_size(),
        Cycles::zero(),
    );
    let canister_id = test.create_canister(Cycles::new(900_000) + freezing_threshold_cycles);
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };
    let original_balance = test.canister_state(canister_id).system_state.balance();
    let message_id = test.dts_install_code(payload);
    let minimum_balance = test.install_code_reserved_execution_cycles();

    // Check reserve execution cycles fails due to not enough balance.
    assert_eq!(
        check_ingress_status(test.ingress_status(&message_id)),
        Err(UserError::new(
            ErrorCode::CanisterOutOfCycles,
            format!("Canister installation failed with `Canister {} is out of cycles: please top up the canister with at least {} additional cycles`.", canister_id, (freezing_threshold_cycles + minimum_balance) - original_balance)
        ))
    );
}

#[test]
fn install_code_running_out_of_instructions() {
    let mut test = ExecutionTestBuilder::new()
        // Set the install message limit very low to hit it while executing.
        .with_install_code_instruction_limit(1_500)
        .with_install_code_slice_instruction_limit(1000)
        .with_manual_execution()
        .with_cost_to_compile_wasm_instruction(0)
        .build();
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
        wasm_module: wat::parse_str(wasm).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
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

    let err = check_ingress_status(test.ingress_status(&message_id)).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterInstructionLimitExceeded,
        &format!(
            "Error from Canister {}: \
            Canister exceeded the limit of {} instructions for single message execution.",
            canister_id,
            test.install_code_instructions_limit(),
        ),
    );
}

#[test]
fn dts_uninstall_with_aborted_install_code() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000)
        .with_install_code_slice_instruction_limit(1_000)
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

#[test]
fn dts_install_code_creates_entry_in_subnet_call_context_manager() {
    const INSTRUCTION_LIMIT: u64 = 3_000_000;
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_install_code_instruction_limit(INSTRUCTION_LIMIT)
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id, controllers)
        .unwrap();

    // SubnetCallContextManager does not contain any install code calls before executing the message.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        0
    );

    let args = InstallCodeArgs {
        canister_id: canister_id.get(),
        mode: CanisterInstallMode::Install,
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    test.inject_call_to_ic00(
        Method::InstallCode,
        args.encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    for _ in 0..4 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        // Check that the SubnetCallContextManager contains the call after paused execution.
        assert_eq!(
            test.state()
                .metadata
                .subnet_call_context_manager
                .install_code_calls_len(),
            1
        );
        test.execute_slice(canister_id);
    }

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    // Finished the execution of install code.
    // Check that the SubnetCallContextManager does not contain the call anymore.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        0
    );
}

#[test]
fn subnet_call_context_manager_keeps_install_code_requests_when_abort() {
    const INSTRUCTION_LIMIT: u64 = 3_000_000;
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_install_code_instruction_limit(INSTRUCTION_LIMIT)
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id, controllers)
        .unwrap();

    // SubnetCallContextManager does not contain any install code calls before executing the message.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        0
    );

    let args = InstallCodeArgs {
        canister_id: canister_id.get(),
        mode: CanisterInstallMode::Install,
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    test.inject_call_to_ic00(
        Method::InstallCode,
        args.encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    for _ in 0..3 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        // Check that the SubnetCallContextManager contains the call after paused execution.
        assert_eq!(
            test.state()
                .metadata
                .subnet_call_context_manager
                .install_code_calls_len(),
            1
        );
        test.execute_slice(canister_id);
    }
    test.abort_all_paused_executions();

    // Continues to keep track of install code context after aborting the execution.
    for _ in 0..5 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        // Check that the SubnetCallContextManager contains the call.
        assert_eq!(
            test.state()
                .metadata
                .subnet_call_context_manager
                .install_code_calls_len(),
            1
        );
        test.execute_slice(canister_id);
    }

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    // Finished the execution of install code.
    // Check that the SubnetCallContextManager does not contain the call anymore.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        0
    );
}

#[test]
fn clean_in_progress_install_code_calls_from_subnet_call_context_manager() {
    const INSTRUCTION_LIMIT: u64 = 3_000_000;
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_install_code_instruction_limit(INSTRUCTION_LIMIT)
        // Ensure that all `install_code()` executions will get paused.
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create two canisters.
    let canister_id_1 = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();
    let canister_id_2 = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    // Set controllers.
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id_1, controllers.clone())
        .unwrap();
    test.canister_update_controller(canister_id_2, controllers)
        .unwrap();

    // SubnetCallContextManager does not contain any entries before executing the messages.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        0
    );
    // Neither does canister 1's task queue.
    assert_eq!(
        test.canister_state(canister_id_1)
            .system_state
            .task_queue
            .len(),
        0
    );

    //
    // Test install code call with canister request origin.
    //

    // `install_code()` will not complete execution in one slice and become paused,
    // because we've set a very low `install_code_slice_instruction_limit` above.
    test.inject_call_to_ic00(
        Method::InstallCode,
        install_code_args(canister_id_1).encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // The first task of canister 1 is a `ContinueInstallCode`.
    assert_eq!(
        test.canister_state(canister_id_1).next_execution(),
        NextExecution::ContinueInstallCode
    );
    // And `SubnetCallContextManager` now contains one `InstallCodeCall`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        1
    );

    // Helper function for invoking `after_split()`.
    fn after_split(state: &mut ReplicatedState) {
        state.metadata.split_from = Some(state.metadata.own_subnet_id);
        state.after_split();
    }

    // A no-op subnet split (no canisters migrated).
    after_split(test.state_mut());

    // Retains the `InstallCodeCall` and does not produce a response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        1
    );
    assert!(!test.state().subnet_queues().has_output());

    // Simulate a subnet split that migrates canister 1 to another subnet.
    test.state_mut().take_canister_state(&canister_id_1);
    after_split(test.state_mut());

    // Should have removed the `InstallCodeCall` and produced a reject response.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        0
    );
    assert!(test.state().subnet_queues().has_output());

    //
    // Test install code call with ingress origin.
    //
    assert_eq!(
        test.canister_state(canister_id_2)
            .system_state
            .task_queue
            .len(),
        0
    );

    // Send install code message and start execution.
    let message_id = test.dts_install_code(install_code_args(canister_id_2));

    // The first task of canister 2 is a `ContinueInstallCode`.
    assert_eq!(
        test.canister_state(canister_id_2).next_execution(),
        NextExecution::ContinueInstallCode
    );
    // And `SubnetCallContextManager` now contains one `InstallCodeCall`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        1
    );

    // A no-op subnet split (no canisters migrated).
    after_split(test.state_mut());

    // Retains the `InstallCodeCall` and does not change the ingress state.
    assert_eq!(
        test.canister_state(canister_id_2).next_execution(),
        NextExecution::ContinueInstallCode
    );
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        1
    );
    assert_matches!(
        test.ingress_status(&message_id),
        IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
    );

    // Simulate a subnet split that migrates canister 2 to another subnet.
    test.state_mut().take_canister_state(&canister_id_2);
    after_split(test.state_mut());

    // Should have removed the `InstallCodeCall` and set the ingress state to `Failed`.
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .install_code_calls_len(),
        0
    );
    assert_eq!(
        check_ingress_status(test.ingress_status(&message_id)),
        Err(UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {} migrated during a subnet split", canister_id_2),
        ))
    );
}

/// Ensures that in-progress install code calls are left in a consistent state
/// after a subnet split: i.e. there is no install code call that is tracked by
/// a canister, but not by the subnet call context manager; or the other way
/// around.
#[test]
fn consistent_install_code_calls_after_split() {
    const INSTRUCTION_LIMIT: u64 = 3_000_000;
    let subnet_a = subnet_test_id(1);
    let subnet_b = subnet_test_id(2);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(subnet_a)
        .with_install_code_instruction_limit(INSTRUCTION_LIMIT)
        // Ensure that all `install_code()` executions will get paused.
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .with_caller(subnet_a, caller_canister)
        .build();

    // Create four canisters.
    let mut create_canister = || {
        test.create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
            .unwrap()
    };
    let canister_id_1 = create_canister();
    let canister_id_2 = create_canister();
    let canister_id_3 = create_canister();
    let canister_id_4 = create_canister();

    // Set controllers.
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    let mut set_controllers = |canister_id, controllers| {
        test.canister_update_controller(canister_id, controllers)
            .unwrap();
    };
    set_controllers(canister_id_1, controllers.clone());
    set_controllers(canister_id_2, controllers.clone());
    set_controllers(canister_id_3, controllers.clone());
    set_controllers(canister_id_4, controllers);

    // No in-progress install code calls across the subnet.
    assert_consistent_install_code_calls(test.state(), 0);

    // Start executing one install code call as canister request on each of canisters 1 and 3.
    //
    // `install_code()` will not complete execution in one slice and become paused,
    // because we've set a very low `install_code_slice_instruction_limit` above.
    test.inject_call_to_ic00(
        Method::InstallCode,
        install_code_args(canister_id_1).encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();
    test.inject_call_to_ic00(
        Method::InstallCode,
        install_code_args(canister_id_3).encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // Start executing one install code call as ingress message on each of canisters 2 and 4.
    test.dts_install_code(install_code_args(canister_id_2));
    test.dts_install_code(install_code_args(canister_id_4));

    // Simulate a checkpoint, to abort all paused `install_call()` executions.
    test.abort_all_paused_executions();

    // 4 in-progress install code calls across the subnet.
    assert_consistent_install_code_calls(test.state(), 4);

    // Retain canisters 1 and 2 on subnet A, migrate canisters 3 and 4 to subnet B.
    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange {start: canister_id_1, end: canister_id_2} => subnet_a,
        CanisterIdRange {start: canister_id_3, end: canister_id_4} => subnet_b,
    })
    .unwrap();

    // Split subnet A'.
    let mut state_a = test
        .state()
        .clone()
        .split(subnet_a, &routing_table, None)
        .unwrap();

    // Restore consistency between install code calls tracked by canisters and subnet.
    state_a.after_split();

    // 2 in-progress install code calls across subnet A'.
    assert_consistent_install_code_calls(&state_a, 2);

    // Split subnet B.
    let mut state_b = test
        .state()
        .clone()
        .split(subnet_b, &routing_table, None)
        .unwrap();

    // Restore consistency between install code calls tracked by canisters and subnet.
    state_b.after_split();

    // 0 in-progress install code calls across subnet B.
    assert_consistent_install_code_calls(&state_b, 0);
}

/// Helper function asserting that there is an exact match between aborted
/// install code calls tracked by the subnet call context manager on the one
/// hand; and by the canisters, on the other.
fn assert_consistent_install_code_calls(state: &ReplicatedState, expected_calls: usize) {
    // Collect the call IDs and calls of all aborted install code calls.
    let canister_install_code_contexts: Vec<_> = state
        .canister_states
        .values()
        .filter_map(|canister| {
            if let Some(ExecutionTask::AbortedInstallCode {
                message, call_id, ..
            }) = canister.next_task()
            {
                Some((call_id, message))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(expected_calls, canister_install_code_contexts.len());

    // Clone the `SubnetCallContextManager` and remove all calls collected above from it.
    let mut subnet_call_context_manager = state.metadata.subnet_call_context_manager.clone();
    for (call_id, call) in canister_install_code_contexts {
        subnet_call_context_manager
            .remove_install_code_call(*call_id)
            .unwrap_or_else(|| {
                panic!(
                    "Canister AbortedInstallCode task without matching subnet InstallCodeCall: {} {:?}",
                    call_id, call
                )
            });
    }

    // And ensure that no `InstallCodeCalls` are left over in the `SubnetCallContextManager`.
    assert!(
            subnet_call_context_manager.install_code_calls_len() == 0,
            "InstallCodeCalls in SubnetCallContextManager without matching canister AbortedInstallCode task: {:?}",
            subnet_call_context_manager.remove_non_local_install_code_calls(|_| false)
        );
}

fn install_code_args(canister_id: CanisterId) -> InstallCodeArgs {
    InstallCodeArgs {
        canister_id: canister_id.get(),
        mode: CanisterInstallMode::Install,
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    }
}

#[test]
fn install_chunked_works_from_whitelist() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(CYCLES);

    // Upload two chunks that make up the universal canister.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let wasm_module_hash = ic_crypto_sha2::Sha256::hash(uc_wasm).to_vec();
    let chunk1 = &uc_wasm[..uc_wasm.len() / 2];
    let chunk2 = &uc_wasm[uc_wasm.len() / 2..];
    let hash1 = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: chunk1.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;
    let hash2 = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: chunk2.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Install the universal canister
    let _install_response = get_reply(
        test.subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgs::new(
                CanisterInstallModeV2::Install,
                canister_id,
                Some(canister_id),
                vec![hash1, hash2],
                wasm_module_hash,
                vec![],
            )
            .encode(),
        ),
    );

    // Check the canister is working
    let wasm = ic_universal_canister::wasm().reply().build();

    let result = test.ingress(canister_id, "update", wasm);
    assert_matches!(result, Ok(WasmResult::Reply(_)));
}

#[test]
fn install_chunked_defaults_to_using_target_as_store() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(CYCLES);

    // Upload universal canister.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let wasm_module_hash = ic_crypto_sha2::Sha256::hash(uc_wasm).to_vec();
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Install the universal canister without passing a store canister.
    let _install_response = get_reply(
        test.subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgs::new(
                CanisterInstallModeV2::Install,
                canister_id,
                // No store canister provided!
                None,
                vec![hash],
                wasm_module_hash,
                vec![],
            )
            .encode(),
        ),
    );

    // Check the canister is working
    let wasm = ic_universal_canister::wasm().reply().build();

    let result = test.ingress(canister_id, "update", wasm);
    assert_matches!(result, Ok(WasmResult::Reply(_)));
}

#[test]
fn install_chunked_recorded_in_history() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(CYCLES);

    // Upload universal canister.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let wasm_module_hash = ic_crypto_sha2::Sha256::hash(uc_wasm).to_vec();
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Install the universal canister.
    let _install_response = get_reply(
        test.subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgs::new(
                CanisterInstallModeV2::Install,
                canister_id,
                None,
                vec![hash],
                wasm_module_hash.clone(),
                vec![],
            )
            .encode(),
        ),
    );

    // Check that the canister history records the install.
    // Expect 2 changes, first is canister creation.
    let state = test.canister_state(canister_id);
    assert_eq!(
        state
            .system_state
            .get_canister_history()
            .get_total_num_changes(),
        2
    );
    assert_eq!(
        state
            .system_state
            .get_canister_history()
            .get_changes(2)
            .collect::<Vec<_>>()[1],
        &std::sync::Arc::new(CanisterChange::new(
            test.time().as_nanos_since_unix_epoch(),
            1,
            CanisterChangeOrigin::from_user(test.user_id().get()),
            CanisterChangeDetails::code_deployment(
                CanisterInstallMode::Install,
                wasm_module_hash.try_into().unwrap()
            ),
        ))
    )
}

#[test]
fn install_chunked_works_from_other_canister() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let target_canister = test.create_canister(CYCLES);
    let store_canister = test.create_canister(CYCLES);

    // Upload universal canister chunk.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: store_canister.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Install the universal canister
    let _install_response = get_reply(
        test.subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgs::new(
                CanisterInstallModeV2::Install,
                target_canister,
                Some(store_canister),
                vec![hash.clone()],
                hash,
                vec![],
            )
            .encode(),
        ),
    );

    // Check the canister is working
    let wasm = ic_universal_canister::wasm().reply().build();

    let result = test.ingress(target_canister, "update", wasm);
    assert_matches!(result, Ok(WasmResult::Reply(_)));
}

#[test]
fn install_chunked_works_with_legacy_args() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let target_canister = test.create_canister(CYCLES);
    let store_canister = test.create_canister(CYCLES);

    // Upload universal canister chunk.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: store_canister.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Install the universal canister using legacy args.
    let _install_response = get_reply(
        test.subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgsLegacy::new(
                CanisterInstallModeV2::Install,
                target_canister,
                Some(store_canister),
                vec![hash.clone()],
                hash,
                vec![],
            )
            .encode(),
        ),
    );

    // Check the canister is working
    let wasm = ic_universal_canister::wasm().reply().build();

    let result = test.ingress(target_canister, "update", wasm);
    assert_matches!(result, Ok(WasmResult::Reply(_)));
}

#[test]
fn install_chunked_fails_with_wrong_chunk_hash() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(CYCLES);

    // Upload universal canister chunk.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Modify the hash so it is incorrect
    let mut wrong_hash = hash.clone();
    wrong_hash[0] = wrong_hash[0].wrapping_add(1);

    // Check error on install
    let error = test
        .subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgs::new(
                CanisterInstallModeV2::Install,
                canister_id,
                Some(canister_id),
                vec![wrong_hash],
                hash,
                vec![],
            )
            .encode(),
        )
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::CanisterContractViolation);
}

#[test]
fn install_chunked_fails_with_wrong_wasm_hash() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(CYCLES);

    // Upload universal canister chunk.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Modify the hash so it is incorrect
    let mut wrong_hash = hash.clone();
    wrong_hash[0] = wrong_hash[0].wrapping_add(1);

    // Check error on install
    let error = test
        .subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgs::new(
                CanisterInstallModeV2::Install,
                canister_id,
                Some(canister_id),
                vec![hash],
                wrong_hash,
                vec![],
            )
            .encode(),
        )
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::CanisterContractViolation);
}

#[test]
fn install_chunked_fails_when_store_canister_not_found() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let target_canister = test.create_canister(CYCLES);
    // Store canister doesn't actually exist.
    let store_canister = canister_test_id(0);

    let hash = ic_crypto_sha2::Sha256::hash(UNIVERSAL_CANISTER_WASM).to_vec();

    // Install the universal canister
    let error = test
        .subnet_message(
            "install_chunked_code",
            InstallChunkedCodeArgs::new(
                CanisterInstallModeV2::Install,
                target_canister,
                Some(store_canister),
                vec![hash.clone()],
                hash,
                vec![],
            )
            .encode(),
        )
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::CanisterContractViolation);
}

#[test]
fn install_chunked_works_from_controller_of_store() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let store_canister = test.create_canister(CYCLES);
    let target_canister = test.create_canister(CYCLES);
    // Upload universal canister chunk to store.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: store_canister.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Create universal canister and use it to install on target.
    let uc = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();
    test.set_controller(store_canister, uc.into()).unwrap();
    test.set_controller(target_canister, uc.into()).unwrap();

    // Install UC wasm on target canister from another canister.
    let install = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::InstallChunkedCode,
            call_args()
                .other_side(
                    InstallChunkedCodeArgs::new(
                        CanisterInstallModeV2::Install,
                        target_canister,
                        Some(store_canister),
                        vec![hash.clone()],
                        hash,
                        vec![],
                    )
                    .encode(),
                )
                .on_reject(wasm().reject_message().reject()),
            Cycles::new(CYCLES.get() / 2),
        )
        .build();
    let result = test.ingress(uc, "update", install);
    assert_matches!(result, Ok(WasmResult::Reply(_)));
}

#[test]
fn install_chunked_fails_from_noncontroller_of_store() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let store_canister = test.create_canister(CYCLES);
    let target_canister = test.create_canister(CYCLES);
    // Upload universal canister chunk to store.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: store_canister.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Create universal canister and use it to install on target.
    // Don't make it a controller of the store.
    let uc = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();
    test.set_controller(target_canister, uc.into()).unwrap();

    // Install UC wasm on target canister
    let install = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::InstallChunkedCode,
            call_args()
                .other_side(
                    InstallChunkedCodeArgs::new(
                        CanisterInstallModeV2::Install,
                        target_canister,
                        Some(store_canister),
                        vec![hash.clone()],
                        hash,
                        vec![],
                    )
                    .encode(),
                )
                .on_reject(wasm().reject_message().reject()),
            Cycles::new(CYCLES.get() / 2),
        )
        .build();
    let result = test.ingress(uc, "update", install);
    match result {
        Ok(WasmResult::Reject(reject)) => {
            assert!(
                reject.contains(&format!(
                    "Only the controllers of the canister {} can control it",
                    store_canister
                )),
                "Unexpected reject message {}",
                reject
            );
        }
        other => panic!("Expected reject, but got {:?}", other),
    }
}

/// A canister should be able to use itself as the `store_canister` in
/// `install_chunked_code` even if it isn't its own controller.
#[test]
fn install_chunked_succeeds_from_store_canister() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let target_canister = test.create_canister(CYCLES);
    // Install universal canister to canister which will also be the store and
    // make it a controller of the target.
    let store_canister = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();
    test.set_controller(target_canister, store_canister.into())
        .unwrap();

    // Upload universal canister chunk to store.
    let uc_wasm = UNIVERSAL_CANISTER_WASM;
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: store_canister.into(),
                chunk: uc_wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Install UC wasm on target canister from store canister should succeed
    // even though the store canister isn't its own controller.
    assert!(!test
        .canister_state(store_canister)
        .system_state
        .controllers
        .contains(&store_canister.get()));

    let install = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::InstallChunkedCode,
            call_args()
                .other_side(
                    InstallChunkedCodeArgs::new(
                        CanisterInstallModeV2::Install,
                        target_canister,
                        Some(store_canister),
                        vec![hash.clone()],
                        hash,
                        vec![],
                    )
                    .encode(),
                )
                .on_reject(wasm().reject_message().reject()),
            Cycles::new(CYCLES.get() / 2),
        )
        .build();
    get_reply(test.ingress(store_canister, "update", install));
}

#[test]
fn install_with_dts_correctly_updates_system_state() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(2_000_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .build();

    // Setup of the test: create a canister and set its certified data and
    // global timer.

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));

    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: UNIVERSAL_CANISTER_WASM.to_vec(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    // It might take multiple DTS steps to finish installation.
    let ingress_id = test.dts_install_code(payload);
    test.execute_message(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    check_ingress_status(ingress_status).unwrap();

    // Set the certified data and global timer of the canister.
    let (ingress_id, _) = test.ingress_raw(
        canister_id,
        "update",
        wasm()
            .certified_data_set(&[42])
            .set_global_timer_method(wasm().inc_global_counter())
            .api_global_timer_set(u64::MAX)
            .push_bytes(&[])
            .append_and_reply()
            .build(),
    );

    // It might take multiple DTS steps to finish the update call.
    test.execute_message(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    check_ingress_status(ingress_status).unwrap();

    assert_eq!(
        test.canister_state(canister_id).system_state.certified_data,
        vec![42]
    );

    assert!(test
        .canister_state(canister_id)
        .system_state
        .global_timer
        .to_nanos_since_unix_epoch()
        .is_some());

    let version_before = test
        .canister_state(canister_id)
        .system_state
        .canister_version;

    let history_entries_before = test
        .canister_state(canister_id)
        .system_state
        .get_canister_history()
        .get_total_num_changes();

    // Reinstall the canister with DTS.
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Reinstall,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    let ingress_id = test.dts_install_code(payload);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueInstallCode
    );

    test.execute_message(canister_id);

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    let ingress_status = test.ingress_status(&ingress_id);
    check_ingress_status(ingress_status).unwrap();

    // Check that the system state is properly updated.

    assert_eq!(
        test.canister_state(canister_id).system_state.certified_data,
        vec![] as Vec<u8>
    );

    assert!(test
        .canister_state(canister_id)
        .system_state
        .global_timer
        .to_nanos_since_unix_epoch()
        .is_none());

    let version_after = test
        .canister_state(canister_id)
        .system_state
        .canister_version;

    assert_eq!(version_before + 1, version_after);

    let history_entries_after = test
        .canister_state(canister_id)
        .system_state
        .get_canister_history()
        .get_total_num_changes();

    assert_eq!(history_entries_before + 1, history_entries_after);
}

#[test]
fn upgrade_with_dts_correctly_updates_system_state() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(2_000_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .with_manual_execution()
        .build();

    // Setup of the test: create a canister and set its certified data and
    // global timer.

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));

    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module: UNIVERSAL_CANISTER_WASM.to_vec(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    // It might take multiple DTS steps to finish installation.
    let ingress_id = test.dts_install_code(payload);
    test.execute_message(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    check_ingress_status(ingress_status).unwrap();

    // Set the certified data and global timer of the canister.
    let (ingress_id, _) = test.ingress_raw(
        canister_id,
        "update",
        wasm()
            .certified_data_set(&[42])
            .set_global_timer_method(wasm().inc_global_counter())
            .api_global_timer_set(u64::MAX)
            .push_bytes(&[])
            .append_and_reply()
            .build(),
    );

    // It might take multiple DTS steps to finish the update call.
    test.execute_message(canister_id);
    let ingress_status = test.ingress_status(&ingress_id);
    check_ingress_status(ingress_status).unwrap();

    assert_eq!(
        test.canister_state(canister_id).system_state.certified_data,
        vec![42]
    );

    assert!(test
        .canister_state(canister_id)
        .system_state
        .global_timer
        .to_nanos_since_unix_epoch()
        .is_some());

    let version_before = test
        .canister_state(canister_id)
        .system_state
        .canister_version;

    let history_entries_before = test
        .canister_state(canister_id)
        .system_state
        .get_canister_history()
        .get_total_num_changes();

    // Upgrade the canister with DTS.
    let payload = InstallCodeArgs {
        mode: CanisterInstallMode::Upgrade,
        canister_id: canister_id.get(),
        wasm_module: wat::parse_str(DTS_INSTALL_WAT).unwrap(),
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
        sender_canister_version: None,
    };

    let ingress_id = test.dts_install_code(payload);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueInstallCode
    );

    test.execute_message(canister_id);

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));

    // Check that the system state is properly updated.

    // Certified data is preserved on ugprades.
    assert_eq!(
        test.canister_state(canister_id).system_state.certified_data,
        vec![42]
    );

    assert!(test
        .canister_state(canister_id)
        .system_state
        .global_timer
        .to_nanos_since_unix_epoch()
        .is_none());

    let version_after = test
        .canister_state(canister_id)
        .system_state
        .canister_version;

    assert_eq!(version_before + 1, version_after);

    let history_entries_after = test
        .canister_state(canister_id)
        .system_state
        .get_canister_history()
        .get_total_num_changes();

    assert_eq!(history_entries_before + 1, history_entries_after);
}

#[test]
fn failed_install_chunked_charges_for_wasm_assembly() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(CYCLES);

    let wasm = wat::parse_str("(module)").unwrap();
    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    let mut wrong_hash = hash.clone();
    wrong_hash[0] = wrong_hash[0].wrapping_add(1);

    let initial_cycles = test.canister_state(canister_id).system_state.balance();

    let method_name = "install_chunked_code";
    let arg = InstallChunkedCodeArgs::new(
        CanisterInstallModeV2::Install,
        canister_id,
        Some(canister_id),
        vec![hash],
        wrong_hash,
        vec![],
    )
    .encode();

    let expected_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(wasm_chunk_store::chunk_size().get()),
        test.subnet_size(),
    );

    // Install the universal canister
    let install_err = test.subnet_message(method_name, arg).unwrap_err();
    assert_eq!(install_err.code(), ErrorCode::CanisterContractViolation);
    let final_cycles = test.canister_state(canister_id).system_state.balance();
    let charged_cycles = initial_cycles - final_cycles;
    // There seems to be a rounding difference from prepay and refund.
    assert!(
        charged_cycles - expected_cost <= Cycles::from(1_u64)
            && expected_cost - charged_cycles <= Cycles::from(1_u64),
        "Charged cycles {} differs from expected cost {}",
        charged_cycles,
        expected_cost
    );
}

#[test]
fn successful_install_chunked_charges_for_wasm_assembly() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new().build();
    let wasm = wat::parse_str("(module)").unwrap();

    // Get the charges for a normal install
    let charge_for_regular_install = {
        let canister_id = test.create_canister(CYCLES);
        let initial_cycles = test.canister_state(canister_id).system_state.balance();
        let method_name = "install_code";
        let arg = InstallCodeArgsV2::new(
            CanisterInstallModeV2::Install,
            canister_id,
            wasm.clone(),
            vec![],
            None,
            None,
        )
        .encode();
        let _response = test.subnet_message(method_name, arg).unwrap();
        let final_cycles = test.canister_state(canister_id).system_state.balance();
        initial_cycles - final_cycles
    };

    let canister_id = test.create_canister(CYCLES);

    let hash = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: wasm.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    let initial_cycles = test.canister_state(canister_id).system_state.balance();

    let method_name = "install_chunked_code";
    let arg = InstallChunkedCodeArgs::new(
        CanisterInstallModeV2::Install,
        canister_id,
        Some(canister_id),
        vec![hash.clone()],
        hash,
        vec![],
    )
    .encode();

    // There is a fixed overhead in the `execution_cost` which we don't want to
    // double count.
    let fixed_execution_overhead = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(0), test.subnet_size());
    let expected_cost = test.cycles_account_manager().execution_cost(
        NumInstructions::from(wasm_chunk_store::chunk_size().get()),
        test.subnet_size(),
    ) - fixed_execution_overhead
        + charge_for_regular_install;

    // Install the universal canister
    let _response = test.subnet_message(method_name, arg).unwrap();
    let final_cycles = test.canister_state(canister_id).system_state.balance();
    let charged_cycles = initial_cycles - final_cycles;
    // There seems to be a rounding difference from prepay and refund.
    assert!(
        charged_cycles - expected_cost <= Cycles::from(1_u64)
            && expected_cost - charged_cycles <= Cycles::from(1_u64),
        "Charged cycles {} differs from expected cost {}",
        charged_cycles,
        expected_cost
    );
}

#[test]
fn install_chunked_with_dts_works() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(1_000_000_000)
        .with_install_code_slice_instruction_limit(1_000)
        .build();

    let canister_id = test.create_canister(CYCLES);

    // Upload two chunks that make up the universal canister.
    let dts_wasm = &wat::parse_str(DTS_INSTALL_WAT).unwrap();
    let wasm_module_hash = ic_crypto_sha2::Sha256::hash(dts_wasm).to_vec();
    let chunk1 = &dts_wasm[..dts_wasm.len() / 2];
    let chunk2 = &dts_wasm[dts_wasm.len() / 2..];
    let hash1 = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: chunk1.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;
    let hash2 = UploadChunkReply::decode(&get_reply(
        test.subnet_message(
            "upload_chunk",
            UploadChunkArgs {
                canister_id: canister_id.into(),
                chunk: chunk2.to_vec(),
            }
            .encode(),
        ),
    ))
    .unwrap()
    .hash;

    // Do an install that triggers DTS.
    let ingress_id = test.subnet_message_raw(
        "install_chunked_code",
        InstallChunkedCodeArgs::new(
            CanisterInstallModeV2::Install,
            canister_id,
            Some(canister_id),
            vec![hash1, hash2],
            wasm_module_hash,
            vec![],
        )
        .encode(),
    );
    test.execute_subnet_message();

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueInstallCode
    );

    test.execute_message(canister_id);

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
}
