use ic_error_types::ErrorCode;
use ic_types::Cycles;

use crate::execution::test_utilities::{check_ingress_status, ExecutionTestBuilder};
use ic_ic00_types::{CanisterInstallMode, EmptyBlob, InstallCodeArgs, Payload};
use ic_replicated_state::canister_state::NextExecution;
use ic_types::ingress::WasmResult;
use wabt::wat2wasm_with_features;

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
            (drop (call $stable_grow (i32.const 1)))
            (call $stable_write (i32.const 0) (i32.const 0) (i32.const 1000))
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
        "MemoryAllocation expected to be in the range [0..12_884_901_888], got 18_446_744_073_709_551_615",
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
    let ingress_id = test.dts_install_code(payload);
    for _ in 0..4 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        assert_eq!(
            test.canister_state(canister_id).system_state.balance(),
            original_system_state.balance(),
        );
        test.execute_slice(canister_id);
    }
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
    // TODO(RUN-286): Make this assertion more precise.
    assert!(
        test.canister_state(canister_id).system_state.balance() < original_system_state.balance(),
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
    let ingress_id = test.dts_install_code(payload);
    for _ in 0..3 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        assert_eq!(
            test.canister_state(canister_id).system_state.balance(),
            original_system_state.balance(),
        );
        test.execute_slice(canister_id);
    }

    test.abort_all_paused_executions();

    for _ in 0..5 {
        assert_eq!(
            test.canister_state(canister_id).next_execution(),
            NextExecution::ContinueInstallCode
        );
        assert_eq!(
            test.canister_state(canister_id).system_state.balance(),
            original_system_state.balance(),
        );
        test.execute_slice(canister_id);
    }

    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );
    // TODO(RUN-286): Make this assertion more precise.
    assert!(
        test.canister_state(canister_id).system_state.balance() < original_system_state.balance(),
    );

    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
}
