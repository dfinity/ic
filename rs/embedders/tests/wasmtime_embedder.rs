use assert_matches::assert_matches;
use ic_config::{
    embedders::{Config, StableMemoryPageLimit},
    flag_status::FlagStatus,
};
use ic_embedders::{
    wasm_utils::instrumentation::instruction_to_cost,
    wasm_utils::instrumentation::WasmMemoryType,
    wasmtime_embedder::{system_api_complexity, CanisterMemoryType},
};
use ic_interfaces::execution_environment::{ExecutionMode, HypervisorError, SystemApi, TrapCode};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{canister_state::WASM_PAGE_SIZE_IN_BYTES, Global};
use ic_test_utilities_embedders::{WasmtimeInstanceBuilder, DEFAULT_NUM_INSTRUCTIONS};
use ic_test_utilities_types::ids::{call_context_test_id, user_test_id};
use ic_types::{
    ingress::WasmResult,
    messages::RejectContext,
    methods::{FuncRef, WasmClosure, WasmMethod},
    time::UNIX_EPOCH,
    Cycles, NumBytes, NumInstructions,
};

const WASM_PAGE_SIZE: u32 = wasmtime_environ::Memory::DEFAULT_PAGE_SIZE;

#[cfg(target_os = "linux")]
use ic_types::PrincipalId;

/// Ensures that attempts to execute messages on wasm modules that do not
/// define memory fails.
#[test]
fn cannot_execute_wasm_without_memory() {
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(
            r#"
          (module
            (import "ic0" "msg_arg_data_copy"
              (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
            (func (export "canister_update should_fail_with_contract_violation")
              (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 0))
            )
          )
        "#,
        )
        .build();

    let result = instance.run(ic_types::methods::FuncRef::Method(
        ic_types::methods::WasmMethod::Update("should_fail_with_contract_violation".to_string()),
    ));

    match result {
        Ok(_) => panic!("Expected a HypervisorError::ContractViolation"),
        Err(err) => {
            assert_eq!(
                err,
                ic_interfaces::execution_environment::HypervisorError::ToolchainContractViolation {
                    error: "WebAssembly module must define memory".to_string(),
                }
            );
        }
    }
}

#[test]
fn correctly_count_instructions() {
    let data_size = 1024;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(
            format!(
                r#"
                    (module
                        (import "ic0" "msg_arg_data_copy"
                            (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
                        (memory 1)
                        (func (export "canister_update test_msg_arg_data_copy")
                            (call $ic0_msg_arg_data_copy
                                (i32.const 0) (i32.const 0) (i32.const {DATA_SIZE}))
                        )
                    )
                    "#,
                DATA_SIZE = data_size
            )
            .as_str(),
        )
        .with_api_type(ic_system_api::ApiType::init(
            UNIX_EPOCH,
            vec![0; 1024],
            user_test_id(24).get(),
        ))
        .build();

    instance
        .run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::Update("test_msg_arg_data_copy".to_string()),
        ))
        .unwrap();

    let instruction_counter = instance.instruction_counter();
    let system_api = &instance.store_data().system_api().unwrap();
    let instructions_used = system_api.slice_instructions_executed(instruction_counter);

    let const_cost = instruction_to_cost(
        &wasmparser::Operator::I32Const { value: 1 },
        WasmMemoryType::Wasm32,
    );
    let call_cost = instruction_to_cost(
        &wasmparser::Operator::Call { function_index: 0 },
        WasmMemoryType::Wasm32,
    );

    let expected_instructions = 1 // Function is 1 instruction.
            + 3 * const_cost
            + call_cost
            + system_api_complexity::overhead::MSG_ARG_DATA_COPY.get()
            + data_size;
    assert_eq!(instructions_used.get(), expected_instructions);
}

#[test]
fn instruction_limit_traps() {
    let data_size = 1024;
    let instruction_limit = NumInstructions::from(1000);
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(
            format!(
                r#"
                    (module
                        (import "ic0" "msg_arg_data_copy"
                            (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
                        (memory 1)
                        (func (export "canister_update test_msg_arg_data_copy")
                            (call $ic0_msg_arg_data_copy
                                (i32.const 0) (i32.const 0) (i32.const {DATA_SIZE}))
                        )
                    )
                    "#,
                DATA_SIZE = data_size
            )
            .as_str(),
        )
        .with_api_type(ic_system_api::ApiType::init(
            UNIX_EPOCH,
            vec![0; 1024],
            user_test_id(24).get(),
        ))
        .with_num_instructions(instruction_limit)
        .build();

    let result = instance.run(ic_types::methods::FuncRef::Method(
        ic_types::methods::WasmMethod::Update("test_msg_arg_data_copy".to_string()),
    ));

    assert_eq!(
        result.err(),
        Some(HypervisorError::InstructionLimitExceeded(instruction_limit))
    );
}

#[test]
fn correctly_report_performance_counter() {
    let data_size = 1024;

    let const_cost = instruction_to_cost(
        &wasmparser::Operator::I32Const { value: 1 },
        WasmMemoryType::Wasm32,
    );
    let call_cost = instruction_to_cost(
        &wasmparser::Operator::Call { function_index: 0 },
        WasmMemoryType::Wasm32,
    );
    let drop_const_cost =
        instruction_to_cost(&wasmparser::Operator::Drop, WasmMemoryType::Wasm32) + const_cost;
    let global_set_cost = instruction_to_cost(
        &wasmparser::Operator::GlobalSet { global_index: 0 },
        WasmMemoryType::Wasm32,
    );

    // Note: the instrumentation is a stack machine, which counts and subtracts
    // the number of instructions for the whole block. The "dynamic" part of
    // System API calls gets added when the API is actually called.
    //
    // High-level, the test function is:
    //   data_copy1()
    //   perf_counter1()
    //   data_copy2()
    //   perf_counter2()
    //
    // So, the first perf counter will catch the whole test func static part
    // + first data copy and performance counter dynamic part.
    // The second perf counter will catch on top the second data copy dynamic part.
    let expected_instructions_counter1 = 1 // Function is 1 instruction.
            + 3 * const_cost
            + call_cost
            + system_api_complexity::overhead::MSG_ARG_DATA_COPY.get()
            + data_size
            + drop_const_cost
            + const_cost
            + call_cost
            + system_api_complexity::overhead::PERFORMANCE_COUNTER.get()
            + global_set_cost
            + 2 * drop_const_cost
            + 3 * const_cost
            + call_cost
            + const_cost
            + call_cost
            + global_set_cost;
    // Includes dynamic part for second data copy and performance counter calls
    let expected_instructions_counter2 = expected_instructions_counter1
        + system_api_complexity::overhead::MSG_ARG_DATA_COPY.get()
        + data_size
        + system_api_complexity::overhead::PERFORMANCE_COUNTER.get();
    let expected_instructions = expected_instructions_counter2;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(
            format!(
                r#"
                    (module
                        (import "ic0" "msg_arg_data_copy"
                            (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
                        (import "ic0" "performance_counter"
                            (func $ic0_performance_counter (param i32) (result i64)))
                        (memory 1)
                        (global $performance_counter1 (export "performance_counter1")
                            (mut i64) (i64.const 0))
                        (global $performance_counter2 (export "performance_counter2")
                            (mut i64) (i64.const 0))

                        (func (export "canister_update test_performance_counter")
                            ;; do a system call and a bit of instructions
                            (call $ic0_msg_arg_data_copy
                                (i32.const 0) (i32.const 0) (i32.const {DATA_SIZE}))
                            (drop (i32.const 0))
                            (call $ic0_performance_counter (i32.const 0))
                            (global.set $performance_counter1)

                            ;; do one more system call and a bit more instructions
                            (drop (i32.const 0))
                            (drop (i32.const 0))
                            (call $ic0_msg_arg_data_copy
                               (i32.const 0) (i32.const 0) (i32.const {DATA_SIZE}))

                            (call $ic0_performance_counter (i32.const 0))
                            (global.set $performance_counter2)
                        )
                    )
                    "#,
                DATA_SIZE = data_size
            )
            .as_str(),
        )
        .with_api_type(ic_system_api::ApiType::init(
            UNIX_EPOCH,
            vec![0; 1024],
            user_test_id(24).get(),
        ))
        .with_num_instructions((expected_instructions * 2).into())
        .build();

    let res = instance
        .run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::Update("test_performance_counter".to_string()),
        ))
        .unwrap();
    let Global::I64(performance_counter1) = res.exported_globals[0] else {
        panic!("Error getting performance_counter1");
    };
    let Global::I64(performance_counter2) = res.exported_globals[1] else {
        panic!("Error getting performance_counter2");
    };
    let instruction_counter = instance.instruction_counter();
    let system_api = &instance.store_data().system_api().unwrap();
    let instructions_used = system_api.slice_instructions_executed(instruction_counter);
    assert_eq!(performance_counter1 as u64, expected_instructions_counter1);
    assert_eq!(performance_counter2 as u64, expected_instructions_counter2);

    assert_eq!(instructions_used.get(), expected_instructions);
}

#[test]
fn stack_overflow_traps() {
    use std::thread;
    let builder = thread::Builder::new();
    let handler = builder
        // Default thread stack gets overflowed before the wasmtime
        .stack_size(8192000)
        .spawn(|| {
            let mut instance = WasmtimeInstanceBuilder::new()
                .with_wat(
                    r#"
                        (module
                            (func $f (export "canister_update f")
                            ;; Define many local variables to quickly overflow the stack
                            (local i64) (local i64) (local i64) (local i64) (local i64)
                            (local i64) (local i64) (local i64) (local i64) (local i64)
                            (local i64) (local i64) (local i64) (local i64) (local i64)
                            (local i64) (local i64) (local i64) (local i64) (local i64)
                            ;; call "f" recursively
                            (call $f)
                            )
                            (memory 0)
                        )
                        "#,
                )
                .build();

            let result = instance.run(ic_types::methods::FuncRef::Method(
                ic_types::methods::WasmMethod::Update("f".to_string()),
            ));

            assert_eq!(
                result.err(),
                Some(
                    ic_interfaces::execution_environment::HypervisorError::Trapped(
                        ic_interfaces::execution_environment::TrapCode::StackOverflow
                    )
                )
            );
        })
        .unwrap();

    handler.join().unwrap();
}

#[test]
// Takes a Wasm with two mutable globals and checks whether we can set and get
// their values.
fn can_set_and_get_global() {
    let wat = r#"
                    (module
                      ;; global 0, visible
                      (global (export "g1") (mut i64) (i64.const 0))
                      ;; global 1, instrumentation makes visible because mutable
                      (global (mut i64) (i64.const 1357))
                      ;; global 2, not visible
                      (global i64 (i64.const 2))
                      ;; global 3, visible
                      (global (export "g2") (mut i32) (i32.const 42))
                      (func (export "canister_update test"))
                    )"#;

    // Initial read, the globals should have a value of 0 and 42 respectively.
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(
        res.exported_globals[..],
        [
            Global::I64(0),
            Global::I32(42),
            Global::I64(1357),
            // Minus 1 instruction for function.
            Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64 - 1)
        ]
    );

    // Change the value of globals and verify we can get them back.
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(wat)
        .with_globals(vec![
            Global::I64(5),
            Global::I32(12),
            Global::I64(2468),
            // Last global is the instruction counter which will be
            // overwritten anyway.
            Global::I64(0),
        ])
        .build();

    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(
        res.exported_globals[..],
        [
            Global::I64(5),
            Global::I32(12),
            Global::I64(2468),
            // Minus 1 instruction for function.
            Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64 - 1),
        ]
    );
}

#[test]
// Takes a Wasm with two mutable float globals and checks whether we can set and
// get their values.
fn can_set_and_get_float_globals() {
    let wat = r#"
                    (module
                        (import "ic0" "msg_reply" (func $msg_reply))
                        (func $test
                            (call $msg_reply)
                        )
                        (global (export "g1") (mut f64) (f64.const 0.0))
                        (global (export "g2") (mut f32) (f32.const 42.42))
                        (func (export "canister_update test"))
                    )"#;

    // Initial read, the globals should have a value of 0.0 and 42.42 respectively.
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(
        res.exported_globals[..],
        [
            Global::F64(0.0),
            Global::F32(42.42),
            // Minus 1 instruction for function.
            Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64 - 1),
        ]
    );

    // Change the value of globals and verify we can get them back.
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(wat)
        .with_globals(vec![
            Global::F64(5.3),
            Global::F32(12.37),
            // Last global is the instruction counter which will be
            // overwritten anyway.
            Global::I64(0),
        ])
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(
        res.exported_globals[..],
        [
            Global::F64(5.3),
            Global::F32(12.37),
            // Minus 1 instruction for function.
            Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64 - 1),
        ]
    );
}

#[test]
#[should_panic(expected = "attempt to set global to value of wrong type")]
fn try_to_set_globals_with_wrong_types() {
    let _instance = WasmtimeInstanceBuilder::new()
        .with_wat(
            r#"
                    (module
                      (global (export "g1") (mut i64) (i64.const 0))
                      (global (export "g2") (mut i32) (i32.const 42))
                    )"#,
        )
        // Should fail because of not correct type of the second one.
        .with_globals(vec![
            Global::I64(5),
            Global::I64(12),
            // Last global is the instruction counter which will be
            // overwritten anyway.
            Global::I64(0),
        ])
        .build();
}

#[test]
#[should_panic(
    expected = "Given number of exported globals 3 is not equal to the number of instance exported globals 2"
)]
fn try_to_set_globals_that_are_more_than_the_instance_globals() {
    let _instance = WasmtimeInstanceBuilder::new()
        // Module only exports one global, but instrumentation adds a second.
        .with_wat(
            r#"
                (module
                    (global (export "g") (mut i64) (i64.const 42))
                )"#,
        )
        .with_globals(vec![Global::I64(0); 3])
        .build();
}

#[test]
#[should_panic(
    expected = "Given number of exported globals 1 is not equal to the number of instance exported globals 2"
)]
fn try_to_set_globals_that_are_less_than_the_instance_globals() {
    let _instance = WasmtimeInstanceBuilder::new()
        // Module only exports one global, but instrumentation adds a second.
        .with_wat(
            r#"
                (module
                    (global (export "g") (mut i64) (i64.const 42))
                )"#,
        )
        .with_globals(vec![Global::I64(0); 1])
        .build();
}

#[test]
fn calling_function_with_invalid_index_fails() {
    let func_idx = 111;
    let wat = r#"
            (module
                (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
                (func $test (param i64 i32)
                    (call $ic_trap (i32.const 0) (i32.const 6))
                )
                (table funcref (elem $test))
                (memory (export "memory") 1)
            )"#;
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance
        .run(FuncRef::UpdateClosure(WasmClosure::new(func_idx, 1)))
        .unwrap_err();
    assert_eq!(err, HypervisorError::FunctionNotFound(0, func_idx));
}

#[test]
fn calling_function_with_invalid_signature_fails() {
    let wat = r#"
            (module
                (import "ic0" "trap" (func $ic_trap (param i32 i32)))
                (func $test
                    (call $ic_trap (i32.const 0) (i32.const 6))
                )
                (table funcref (elem $test))
                (memory (export "memory") 1)
            )"#;
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance
        .run(FuncRef::UpdateClosure(WasmClosure::new(0, 1)))
        .unwrap_err();
    assert_eq!(
        err,
        HypervisorError::ToolchainContractViolation {
            error: "function invocation does not match its signature".to_string(),
        }
    );
}

#[test]
fn calling_function_by_index() {
    let wat = r#"
            (module
                (import "ic0" "trap" (func $ic_trap (param i32 i32)))
                (func $test (param i32)
                    (call $ic_trap (i32.const 0) (i32.const 6))
                )
                (table funcref (elem $test))
                (memory (export "memory") 1)
            )"#;
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance
        .run(FuncRef::UpdateClosure(WasmClosure::new(0, 0)))
        .unwrap_err();
    assert_eq!(
        err,
        HypervisorError::CalledTrap(std::str::from_utf8(&[0; 6]).unwrap().to_string())
    );
}

#[test]
fn zero_size_memory() {
    let wat = r#"
            (module
                (import "ic0" "trap" (func $ic_trap (param i32 i32)))
                (func $test (param i32)
                    (call $ic_trap (i32.const 0) (i32.const 0))
                )
                (table funcref (elem $test))
                (memory (export "memory") 0)
            )"#;
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance
        .run(FuncRef::UpdateClosure(WasmClosure::new(0, 0)))
        .unwrap_err();
    assert_eq!(
        err,
        HypervisorError::CalledTrap(std::str::from_utf8(&[0; 0]).unwrap().to_string())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn read_before_write_stats() {
    // This wasm does a direct write to page 0.
    let direct_wat = r#"
            (module
                (import "ic0" "msg_reply" (func $msg_reply))
                (memory (export "memory") 1)
                (func (export "canister_update write")
                    (i32.store (i32.const 0) (i32.const 111))
                    (call $msg_reply)
                )
            )"#;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(direct_wat)
        .with_api_type(ic_system_api::ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::zero(),
            PrincipalId::new_user_test_id(0),
            0.into(),
        ))
        .build();
    instance
        .run(FuncRef::Method(WasmMethod::Update("write".to_string())))
        .unwrap();
    let stats = instance.get_stats();
    assert_eq!(stats.wasm_direct_write_count, 1);
    assert_eq!(stats.wasm_read_before_write_count, 0);

    // This wasm does a read then write to page 0.
    let read_then_write_wat = r#"
            (module
                (import "ic0" "msg_reply" (func $msg_reply))
                (memory (export "memory") 1)
                (func (export "canister_update write")
                    (drop (i32.load (i32.const 4096)))
                    (i32.store (i32.const 4096) (i32.const 111))
                    (call $msg_reply)
                )
            )"#;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(read_then_write_wat)
        .with_api_type(ic_system_api::ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::zero(),
            PrincipalId::new_user_test_id(0),
            0.into(),
        ))
        .build();
    instance
        .run(FuncRef::Method(WasmMethod::Update("write".to_string())))
        .unwrap();
    let stats = instance.get_stats();
    assert_eq!(stats.wasm_direct_write_count, 0);
    assert_eq!(stats.wasm_read_before_write_count, 1);
}

#[test]
fn stable_write_and_read() {
    let wat = r#"
            (module
                (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $pages i32) (result i32)))
                (import "ic0" "stable_read"
                    (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))
                (import "ic0" "stable_write"
                    (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))

                (import "ic0" "trap" (func $ic_trap (param i32 i32)))
                (func $test (export "canister_update test")

                    (i32.store (i32.const 10) (i32.const 72))
                    (i32.store (i32.const 11) (i32.const 101))
                    (i32.store (i32.const 12) (i32.const 108))
                    (i32.store (i32.const 13) (i32.const 108))
                    (i32.store (i32.const 14) (i32.const 111))

                    (drop (call $ic0_stable_grow (i32.const 1)))
                    (call $ic0_stable_write (i32.const 100) (i32.const 10) (i32.const 5))
                    (call $ic0_stable_read (i32.const 0) (i32.const 100) (i32.const 5))

                    (call $ic_trap (i32.const 0) (i32.const 5))
                )
                (memory (export "memory") 1)
            )"#;
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap_err();
    assert_eq!(err, HypervisorError::CalledTrap("Hello".to_string()));
}

#[test]
fn stable64_write_and_read() {
    let wat = r#"
            (module
                (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $pages i32) (result i32)))
                (import "ic0" "stable64_read"
                    (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
                (import "ic0" "stable64_write"
                    (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))

                (import "ic0" "trap" (func $ic_trap (param i32 i32)))
                (func $test (export "canister_update test")

                    (i32.store (i32.const 10) (i32.const 72))
                    (i32.store (i32.const 11) (i32.const 101))
                    (i32.store (i32.const 12) (i32.const 108))
                    (i32.store (i32.const 13) (i32.const 108))
                    (i32.store (i32.const 14) (i32.const 111))

                    (drop (call $ic0_stable_grow (i32.const 1)))
                    (call $ic0_stable64_write (i64.const 100) (i64.const 10) (i64.const 5))
                    (call $ic0_stable64_read (i64.const 0) (i64.const 100) (i64.const 5))

                    (call $ic_trap (i32.const 0) (i32.const 5))
                )
                (table funcref (elem $test))
                (memory (export "memory") 1)
            )"#;
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap_err();
    assert_eq!(err, HypervisorError::CalledTrap("Hello".to_string()));
}

#[test]
fn stable_read_accessed_pages_allowance() {
    fn func_ref(name: &str) -> FuncRef {
        FuncRef::Method(WasmMethod::Update(name.to_string()))
    }
    let wat = r#"
            (module
                (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $pages i32) (result i32)))
                (import "ic0" "stable_read"
                    (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))
                (import "ic0" "stable_write"
                    (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))

                (func (export "canister_update read_within_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable_write (i32.const 100) (i32.const 10) (i32.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable_read (i32.const 10) (i32.const 4094) (i32.const 5))
                    ;; touch page 0, 1 and 2
                    (call $ic0_stable_read (i32.const 10) (i32.const 4094) (i32.const 8194))
                )

                (func (export "canister_update write_within_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable_read (i32.const 10) (i32.const 100) (i32.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable_write (i32.const 4094) (i32.const 10) (i32.const 5))
                    ;; touch page 0, 1 and 2
                    (call $ic0_stable_write (i32.const 4094) (i32.const 10) (i32.const 8194))
                )

                (func (export "canister_update read_above_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable_write (i32.const 100) (i32.const 10) (i32.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable_read (i32.const 10) (i32.const 4094) (i32.const 5))
                    ;; touch pages 0, 1, 2, 3
                    (call $ic0_stable_read (i32.const 10) (i32.const 4094) (i32.const 8195))
                )

                (func (export "canister_update write_above_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable_read (i32.const 10) (i32.const 100) (i32.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable_write (i32.const 4094) (i32.const 10) (i32.const 5))
                    ;; touch page 0, 1 and 2
                    (call $ic0_stable_write (i32.const 4094) (i32.const 10) (i32.const 8195))
                )

                (memory (export "memory") 5)
            )"#;

    use HypervisorError::*;

    let mut config = Config {
        stable_memory_accessed_page_limit: StableMemoryPageLimit {
            message: ic_types::NumOsPages::new(3),
            upgrade: ic_types::NumOsPages::new(3),
            query: ic_types::NumOsPages::new(3),
        },
        ..Default::default()
    };
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    instance.run(func_ref("read_within_limit")).unwrap();

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    instance.run(func_ref("write_within_limit")).unwrap();

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("read_above_limit")).unwrap_err();
    assert_matches!(err, MemoryAccessLimitExceeded(_));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("write_above_limit")).unwrap_err();
    assert_matches!(err, MemoryAccessLimitExceeded(_));
}

#[test]
fn stable64_read_accessed_pages_allowance() {
    fn func_ref(name: &str) -> FuncRef {
        FuncRef::Method(WasmMethod::Update(name.to_string()))
    }
    let wat = r#"
            (module
                (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $pages i32) (result i32)))
                (import "ic0" "stable64_read"
                    (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
                (import "ic0" "stable64_write"
                    (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))

                (func (export "canister_update read_within_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable64_write (i64.const 100) (i64.const 10) (i64.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable64_read (i64.const 10) (i64.const 4094) (i64.const 5))
                    ;; touch page 0, 1 and 2
                    (call $ic0_stable64_read (i64.const 10) (i64.const 4094) (i64.const 8194))
                )

                (func (export "canister_update write_within_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable64_read (i64.const 10) (i64.const 100) (i64.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable64_write (i64.const 4094) (i64.const 10) (i64.const 5))
                    ;; touch page 0, 1 and 2
                    (call $ic0_stable64_write (i64.const 4094) (i64.const 10) (i64.const 8194))
                )

                (func (export "canister_update read_above_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable64_write (i64.const 100) (i64.const 10) (i64.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable64_read (i64.const 10) (i64.const 4094) (i64.const 5))
                    ;; touch pages 0, 1, 2, 3
                    (call $ic0_stable64_read (i64.const 10) (i64.const 4094) (i64.const 8195))
                )

                (func (export "canister_update write_above_limit")
                    (drop (call $ic0_stable_grow (i32.const 10)))
                    ;; touch page 0
                    (call $ic0_stable64_read (i64.const 10) (i64.const 100) (i64.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable64_write (i64.const 4094) (i64.const 10) (i64.const 5))
                    ;; touch page 0, 1 and 2
                    (call $ic0_stable64_write (i64.const 4094) (i64.const 10) (i64.const 8195))
                )

                (memory (export "memory") 5)
            )"#;

    use HypervisorError::*;

    let mut config = Config {
        stable_memory_accessed_page_limit: StableMemoryPageLimit {
            message: ic_types::NumOsPages::new(3),
            upgrade: ic_types::NumOsPages::new(3),
            query: ic_types::NumOsPages::new(3),
        },
        ..Default::default()
    };
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    instance.run(func_ref("read_within_limit")).unwrap();

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    instance.run(func_ref("write_within_limit")).unwrap();

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("read_above_limit")).unwrap_err();
    assert_matches!(err, MemoryAccessLimitExceeded(_));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("write_above_limit")).unwrap_err();
    assert_matches!(err, MemoryAccessLimitExceeded(_));
}

#[test]
fn multiple_stable_write() {
    let wat = r#"
            (module
                (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $pages i32) (result i32)))
                (import "ic0" "stable_read"
                    (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))
                (import "ic0" "stable_write"
                    (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))

                (func $test (export "canister_update test")

                    (i32.store (i32.const 10) (i32.const 72))
                    (i32.store (i32.const 11) (i32.const 101))
                    (i32.store (i32.const 12) (i32.const 108))
                    (i32.store (i32.const 13) (i32.const 108))
                    (i32.store (i32.const 14) (i32.const 111))

                    (drop (call $ic0_stable_grow (i32.const 30)))
                    ;; touch page 0
                    (call $ic0_stable_write (i32.const 100) (i32.const 10) (i32.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable_write (i32.const 4094) (i32.const 10) (i32.const 5))
                    ;; touch page 5 and 6
                    (call $ic0_stable_write (i32.const 24574) (i32.const 10) (i32.const 5))
                    ;; touch page 4 and 5
                    (call $ic0_stable_write (i32.const 20478) (i32.const 10) (i32.const 5))
                    ;; touch pages 5-14
                    (call $ic0_stable_write (i32.const 20480) (i32.const 0) (i32.const 40960))
                    (call $ic0_stable_read (i32.const 0) (i32.const 100) (i32.const 5))
                )
                (table funcref (elem $test))
                (memory (export "memory") 5)
            )"#;
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let _res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    // one dirty heap page and 13 stable
    assert_eq!(instance.get_stats().dirty_pages(), 1 + 13);
}

#[test]
fn multiple_stable64_write() {
    let wat = r#"
            (module
                (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $pages i32) (result i32)))
                (import "ic0" "stable64_read"
                    (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
                (import "ic0" "stable64_write"
                    (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))

                (func $test (export "canister_update test")

                    (i32.store (i32.const 10) (i32.const 72))
                    (i32.store (i32.const 11) (i32.const 101))
                    (i32.store (i32.const 12) (i32.const 108))
                    (i32.store (i32.const 13) (i32.const 108))
                    (i32.store (i32.const 14) (i32.const 111))

                    (drop (call $ic0_stable_grow (i32.const 30)))
                    ;; touch page 0
                    (call $ic0_stable64_write (i64.const 100) (i64.const 10) (i64.const 5))
                    ;; touch page 0 and 1
                    (call $ic0_stable64_write (i64.const 4094) (i64.const 10) (i64.const 5))
                    ;; touch page 5 and 6
                    (call $ic0_stable64_write (i64.const 24574) (i64.const 10) (i64.const 5))
                    ;; touch page 4 and 5
                    (call $ic0_stable64_write (i64.const 20478) (i64.const 10) (i64.const 5))
                    ;; touch pages 5-14
                    (call $ic0_stable64_write (i64.const 20480) (i64.const 0) (i64.const 40960))
                    (call $ic0_stable64_read (i64.const 0) (i64.const 100) (i64.const 5))
                )
                (table funcref (elem $test))
                (memory (export "memory") 5)
            )"#;
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let _res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    // one dirty heap page and 13 stable
    assert_eq!(instance.get_stats().dirty_pages(), 1 + 13);
}

#[test]
fn stable_read_out_of_bounds() {
    fn func_ref(name: &str) -> FuncRef {
        FuncRef::Method(WasmMethod::Update(name.to_string()))
    }

    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
            (func (export "canister_update test_src")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading from stable memory just after the page should trap.
                (call $stable_read (i32.const 0) (i32.const 65536) (i32.const 1))
            )
            (func (export "canister_update test_dst")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading into heap just after the second page should trap.
                (call $stable_read (i32.const 131072) (i32.const 0) (i32.const 1))
            )
            (func (export "canister_update test_len_heap")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Reading into heap with dst + len after the second page should trap.
                (call $stable_read (i32.const 65536) (i32.const 0) (i32.const 65537))
            )
            (func (export "canister_update test_len_stable")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Reading from stable mem with src + len after the second page should trap.
                (call $stable_read (i32.const 0) (i32.const 65536) (i32.const 65537))
            )
            (func (export "canister_update test_len_both")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Reading with dst + len and src + len after the second page should trap.
                (call $stable_read (i32.const 65536) (i32.const 65536) (i32.const 65537))
            )
            (memory 2 2)
        )"#;

    use HypervisorError::*;
    use TrapCode::*;

    // Host stable memory
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    // native stable memory
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));
}

#[test]
fn stable64_read_out_of_bounds() {
    fn func_ref(name: &str) -> FuncRef {
        FuncRef::Method(WasmMethod::Update(name.to_string()))
    }

    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                (import "ic0" "stable64_read"
                    (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64)))

            (func (export "canister_update test_src")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading from stable memory just after the page should trap.
                (call $stable64_read (i64.const 0) (i64.const 65536) (i64.const 1))
            )
            (func (export "canister_update test_dst")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading into heap with dst > u32::max should trap.
                (call $stable64_read (i64.const 4294967296) (i64.const 0) (i64.const 1))
            )
            (func (export "canister_update test_len")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading into heap with len > u32::max should trap.
                (call $stable64_read (i64.const 0) (i64.const 0) (i64.const 4294967296))
            )
            (func (export "canister_update test_len_heap")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Reading into heap with dst + len after the second page should trap.
                (call $stable64_read (i64.const 65536) (i64.const 0) (i64.const 65537))
            )
            (func (export "canister_update test_len_stable")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Reading from stable mem with src + len after the second page should trap.
                (call $stable64_read (i64.const 0) (i64.const 65536) (i64.const 65537))
            )
            (func (export "canister_update test_len_both")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Reading with dst + len and src + len after the second page should trap.
                (call $stable64_read (i64.const 65536) (i64.const 65536) (i64.const 65537))
            )
            (memory 2 2)
        )"#;

    use HypervisorError::*;
    use TrapCode::*;

    // Host stable memory
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    // Native stable memory
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));
}

#[test]
fn stable_write_out_of_bounds() {
    fn func_ref(name: &str) -> FuncRef {
        FuncRef::Method(WasmMethod::Update(name.to_string()))
    }

    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
            (func (export "canister_update test_dst")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Writing to stable memory just after the page should trap.
                (call $stable_write (i32.const 65536) (i32.const 0) (i32.const 1))
            )
            (func (export "canister_update test_src")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading from heap just after the second page should trap.
                (call $stable_write (i32.const 0) (i32.const 131072) (i32.const 1))
            )
            (func (export "canister_update test_len_heap")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Writing to stable memory with src + len after the second page should trap.
                (call $stable_write (i32.const 0) (i32.const 65537) (i32.const 65536))
            )
            (func (export "canister_update test_len_stable")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Writing to stable memory with dst + len after the second page should trap.
                (call $stable_write (i32.const 65537) (i32.const 0) (i32.const 65536))
            )
            (func (export "canister_update test_len_both")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Writing to stable memory with dst + len and src + len after the second page should trap.
                (call $stable_write (i32.const 65537) (i32.const 65537) (i32.const 65536))
            )
            (memory 2 2)
        )"#;

    use HypervisorError::*;
    use TrapCode::*;

    // Host stable memory
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    // native stable memory
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));
}

#[test]
fn stable64_write_out_of_bounds() {
    fn func_ref(name: &str) -> FuncRef {
        FuncRef::Method(WasmMethod::Update(name.to_string()))
    }

    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64)))
            (func (export "canister_update test_dst")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Writing to stable memory just after the page should trap.
                (call $stable64_write (i64.const 65536) (i64.const 0) (i64.const 1))
            )
            (func (export "canister_update test_src")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Writing into heap with src > i32::max should trap.
                (call $stable64_write (i64.const 0) (i64.const 4294967296) (i64.const 1))
            )
            (func (export "canister_update test_len")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Writing into heap with len > u32::max should trap.
                (call $stable64_write (i64.const 0) (i64.const 0) (i64.const 4294967296))
            )
            (func (export "canister_update test_len_heap")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Writing to stable memory with src + len after the second page should trap.
                (call $stable64_write (i64.const 0) (i64.const 65537) (i64.const 65536))
            )
            (func (export "canister_update test_len_stable")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Writing to stable memory with dst + len after the second page should trap.
                (call $stable64_write (i64.const 65537) (i64.const 0) (i64.const 65536))
            )
            (func (export "canister_update test_len_both")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 2)))
                ;; Writing to stable memory with dst + len and src + len after the second page should trap.
                (call $stable64_write (i64.const 65537) (i64.const 65537) (i64.const 65536))
            )

            (memory 2 2)
        )"#;

    use HypervisorError::*;
    use TrapCode::*;

    // Host stable memory
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    // native stable memory
    let mut config = Config::default();
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_src")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_dst")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_heap")).unwrap_err();
    assert_eq!(err, Trapped(HeapOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config.clone())
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_stable")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let err = instance.run(func_ref("test_len_both")).unwrap_err();
    assert_eq!(err, Trapped(StableMemoryOutOfBounds));
}

/// Test that stable memory access past the normal 32-bit range (including
/// guard pages) works properly.
#[test]
fn stable_access_beyond_32_bit_range() {
    fn func_ref(name: &str) -> FuncRef {
        FuncRef::Method(WasmMethod::Update(name.to_string()))
    }

    let gb = 1024 * 1024 * 1024;
    // We'll grow stable memory to 30 GB and then try writing to the last byte.
    let bytes_to_access = 30 * gb;
    let max_stable_memory_in_wasm_pages = bytes_to_access / WASM_PAGE_SIZE_IN_BYTES as u64;
    let last_byte_of_stable_memory = bytes_to_access - 1;

    let wat = format!(
        r#"
        (module
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64)))
            (func (export "canister_update write_to_last_page")
                ;; Grow stable memory to the maximum size
                (i64.eq (i64.const -1) (call $stable_grow (i64.const {max_stable_memory_in_wasm_pages})))
                (if
                    (then unreachable)
                )

                ;; Write to the last byte of stable memory
                (call $stable64_write (i64.const {last_byte_of_stable_memory}) (i64.const 0) (i64.const 1))
            )
            (memory 2 2)
        )"#
    );

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(&wat)
        .with_canister_memory_limit(NumBytes::from(40 * gb))
        .build();
    instance.run(func_ref("write_to_last_page")).unwrap();
}

/// Test that a particular OOB memory access is caught by wasmtime.
#[test]
fn wasm_heap_oob_access() {
    let wat = r#"
            (module
                (type (;0;) (func))
                (func (;0;) (type 0)
                    i32.const -943208505
                    i32.load8_s offset=3933426208
                    unreachable
                )
                (memory (;0;) 652 38945)
                (export "canister_update test" (func 0))
            )"#;

    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    let err = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap_err();
    assert_eq!(err, HypervisorError::Trapped(TrapCode::HeapOutOfBounds));
}

#[test]
fn passive_data_segment() {
    let wat = r#"
        (module
            (export "memory" (memory 0))
            (func (export "canister_update test")
                i32.const 1024  ;; target memory address
                i32.const 0     ;; data segment offset
                i32.const 4     ;; byte length
                memory.init 0   ;; load passive data segment by index

                i32.const 1024
                i32.load
                i32.const 0x04030201 ;; little endian
                i32.ne
                if
                    unreachable
                end
            )
            (memory i32 1)
            (data (;0;) "\01\02\03\04")
    )"#;
    let mut instance = WasmtimeInstanceBuilder::new().with_wat(wat).build();
    instance
        .run(FuncRef::Method(WasmMethod::Update(String::from("test"))))
        .unwrap();
}

/// Calculate debug_print instruction cost from the message length.
fn debug_print_cost(bytes: usize) -> u64 {
    let const_cost = instruction_to_cost(
        &wasmparser::Operator::I32Const { value: 1 },
        WasmMemoryType::Wasm32,
    );
    let call_cost = instruction_to_cost(
        &wasmparser::Operator::Call { function_index: 0 },
        WasmMemoryType::Wasm32,
    );
    3 * const_cost + call_cost + system_api_complexity::overhead::DEBUG_PRINT.get() + bytes as u64
}

// The maximum allowed size of a canister log buffer.
pub const MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE: usize = 4 * 1024;

/// Calculate logging instruction cost from the allocated and transmitted bytes.
fn canister_logging_cost(allocated_bytes: usize, transmitted_bytes: usize) -> u64 {
    const BYTE_TRANSMISSION_COST_FACTOR: usize = 50;
    debug_print_cost(2 * allocated_bytes + BYTE_TRANSMISSION_COST_FACTOR * transmitted_bytes)
}

/// Calculate debug_print and canister logging instruction cost from the message length,
/// allocated bytes, and transmitted bytes.
fn debug_print_and_canister_logging_cost(
    debug_print_bytes: usize,
    allocated_bytes: usize,
    transmitted_bytes: usize,
) -> u64 {
    const BYTE_TRANSMISSION_COST_FACTOR: usize = 50;
    let canister_logging_bytes =
        2 * allocated_bytes + BYTE_TRANSMISSION_COST_FACTOR * transmitted_bytes;
    debug_print_cost(debug_print_bytes + canister_logging_bytes)
}

/// Create a WAT that calls debug_print with a message of a given length.
fn create_debug_print_wat(message_len: usize) -> String {
    let message = "a".repeat(message_len);
    format!(
        r#"
        (module
            (import "ic0" "debug_print" (func $debug_print (param i32) (param i32)))

            (func $test (export "canister_update test")
                (call $debug_print (i32.const 5) (i32.const {message_len})))

            (memory $memory 1)
            (export "memory" (memory $memory))
            (data (i32.const 5) "{message}")
        )"#
    )
}

/// Create a WAT that calls debug_print with a message of a given length; wasm64
fn create_debug_print64_wat(message_len: usize) -> String {
    let message = "a".repeat(message_len);
    format!(
        r#"
        (module
            (import "ic0" "debug_print" (func $debug_print (param i64) (param i64)))

            (func $test (export "canister_update test")
                (call $debug_print (i64.const 5) (i64.const {message_len})))

            (memory $memory i64 1)
            (export "memory" (memory $memory))
            (data (i64.const 5) "{message}")
        )"#
    )
}

#[test]
fn wasm_debug_print_instructions_charging() {
    // Test debug print is charged only when rate limiting is disabled or for system subnets.
    let message_len = 42;
    let test_cases = vec![
        // (rate_limiting, subnet_type, expected_instructions)
        (
            FlagStatus::Disabled,
            SubnetType::System,
            debug_print_and_canister_logging_cost(message_len, message_len, message_len),
        ),
        (
            FlagStatus::Disabled,
            SubnetType::Application,
            debug_print_and_canister_logging_cost(message_len, message_len, message_len),
        ),
        (
            FlagStatus::Disabled,
            SubnetType::VerifiedApplication,
            debug_print_and_canister_logging_cost(message_len, message_len, message_len),
        ),
        (
            FlagStatus::Enabled,
            SubnetType::System,
            debug_print_and_canister_logging_cost(message_len, message_len, message_len),
        ),
        (
            FlagStatus::Enabled,
            SubnetType::Application,
            debug_print_and_canister_logging_cost(0, message_len, message_len),
        ),
        (
            FlagStatus::Enabled,
            SubnetType::VerifiedApplication,
            debug_print_and_canister_logging_cost(0, message_len, message_len),
        ),
    ];
    for (rate_limiting, subnet_type, expected_instructions) in test_cases.clone() {
        let mut config = Config::default();
        config.feature_flags.rate_limiting_of_debug_prints = rate_limiting;
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_config(config)
            .with_subnet_type(subnet_type)
            .with_wat(&create_debug_print_wat(message_len))
            .build();
        let before = instance.instruction_counter();
        instance
            .run(FuncRef::Method(WasmMethod::Update(String::from("test"))))
            .unwrap();
        let instructions_used = before - instance.instruction_counter();

        assert_eq!(
            instructions_used, expected_instructions as i64,
            "rate_limiting: {rate_limiting:?}, subnet_type: {subnet_type:?}"
        );
    }

    // same for wasm64
    for (rate_limiting, subnet_type, expected_instructions) in test_cases {
        let mut config = Config::default();
        config.feature_flags.rate_limiting_of_debug_prints = rate_limiting;
        config.feature_flags.wasm64 = FlagStatus::Enabled;
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_config(config)
            .with_subnet_type(subnet_type)
            .with_wat(&create_debug_print64_wat(message_len))
            .build();
        let before = instance.instruction_counter();
        instance
            .run(FuncRef::Method(WasmMethod::Update(String::from("test"))))
            .unwrap();
        let instructions_used = before - instance.instruction_counter();

        assert_eq!(instructions_used, expected_instructions as i64);
    }
}

#[test]
fn wasm_canister_logging_instructions_charging() {
    // Test charging for canister logging is limited by the maximum allowed buffer size.
    let test_cases = vec![
        // (message_len, expected_instructions)
        (0, canister_logging_cost(0, 0)),
        (1, canister_logging_cost(1, 1)),
        (10, canister_logging_cost(10, 10)),
        (100, canister_logging_cost(100, 100)),
        (1_000, canister_logging_cost(1_000, 1_000)),
        (
            10_000,
            canister_logging_cost(
                MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE,
                MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE,
            ),
        ),
    ];
    for (message_len, expected_instructions) in test_cases.clone() {
        let mut config = Config::default();
        config.feature_flags.rate_limiting_of_debug_prints = FlagStatus::Enabled;
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_config(config)
            .with_subnet_type(SubnetType::Application)
            .with_wat(&create_debug_print_wat(message_len))
            .build();
        let before = instance.instruction_counter();
        instance
            .run(FuncRef::Method(WasmMethod::Update(String::from("test"))))
            .unwrap();
        let instructions_used = before - instance.instruction_counter();

        assert_eq!(instructions_used, expected_instructions as i64);
    }

    // same for wasm64
    for (message_len, expected_instructions) in test_cases {
        let mut config = Config::default();
        config.feature_flags.rate_limiting_of_debug_prints = FlagStatus::Enabled;
        config.feature_flags.wasm64 = FlagStatus::Enabled;
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_config(config)
            .with_subnet_type(SubnetType::Application)
            .with_wat(&create_debug_print64_wat(message_len))
            .build();
        let before = instance.instruction_counter();
        instance
            .run(FuncRef::Method(WasmMethod::Update(String::from("test"))))
            .unwrap();
        let instructions_used = before - instance.instruction_counter();

        assert_eq!(instructions_used, expected_instructions as i64);
    }
}

#[test]
fn wasm_logging_new_records_after_exceeding_log_size_limit() {
    // Test verifies that canister logging continues adding new records after exceeding
    // the log size limit. The test charges both for bytes allocation and transmission
    // for the first call only, while subsequent calls are not charged for transmission.

    // Set the message length to a value exceeding the maximum allowed log buffer size.
    let message_len = 10_000;
    assert!(MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE < message_len);

    fn run_test(mut instance: ic_embedders::wasmtime_embedder::WasmtimeInstance) {
        // Call the WASM method multiple times.
        for i in 0..10 {
            let before = instance.instruction_counter();
            instance
                .run(FuncRef::Method(WasmMethod::Update(String::from("test"))))
                .unwrap();
            let instructions_used = before - instance.instruction_counter();
            let system_api = &instance.store_data().system_api().unwrap();
            // Assert that there is no space left in the canister log, but the next index is incremented.
            assert_eq!(system_api.canister_log().remaining_space(), 0);
            assert_eq!(system_api.canister_log().next_idx(), i + 1);
            // Check the instructions used for each call.
            match i {
                // Expect charge for max allowed message length on first call only (for allocation and transmission).
                0 => assert_eq!(
                    instructions_used,
                    canister_logging_cost(
                        MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE,
                        MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE
                    ) as i64
                ),
                // Expect allocation charge only, no transmission charge for subsequent calls.
                _ => assert_eq!(
                    instructions_used,
                    canister_logging_cost(MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE, 0) as i64
                ),
            }
        }
    }

    let mut config = Config::default();
    config.feature_flags.rate_limiting_of_debug_prints = FlagStatus::Enabled;
    let instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_subnet_type(SubnetType::Application)
        .with_wat(&create_debug_print_wat(message_len))
        .build();

    run_test(instance);

    // same for wasm64
    let mut config = Config::default();
    config.feature_flags.rate_limiting_of_debug_prints = FlagStatus::Enabled;
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_subnet_type(SubnetType::Application)
        .with_wat(&create_debug_print64_wat(message_len))
        .build();

    run_test(instance);
}

#[test]
// Verify that we can create 64 bit memory and write to it
fn wasm64_basic_test() {
    let wat = r#"
    (module
        (global $g1 (export "g1") (mut i64) (i64.const 0))
        (func $test (export "canister_update test")
            (i64.store (i64.const 0) (memory.grow (i64.const 1)))
            (i64.store (i64.const 20) (i64.const 137))
            (i64.load (i64.const 20))
            global.set $g1
        )
        (memory (export "memory") i64 10)
    )"#;

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(res.exported_globals[0], Global::I64(137));
}

#[test]
// Verify that we can create 64 bit memory and write to it
fn memory_copy_test() {
    let wat = r#"
    (module
        (global $g1 (export "g1") (mut i64) (i64.const 0))
        (func $test (export "canister_update test")
            (i64.store (i32.const 20) (i64.const 137))
            (memory.copy (i32.const 50) (i32.const 20) (i32.const 8))
            (i64.load (i32.const 50))
            global.set $g1
        )
        (memory (export "memory") 10)
    )"#;

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(res.exported_globals[0], Global::I64(137));
}

#[test]
fn wasm64_memory_copy_test() {
    let wat = r#"
    (module
        (global $g1 (export "g1") (mut i64) (i64.const 0))
        (func $test (export "canister_update test")
            (i64.store (i64.const 20) (i64.const 137))
            (memory.copy (i64.const 50) (i64.const 20) (i64.const 8))
            (i64.load (i64.const 50))
            global.set $g1
        )
        (memory (export "memory") i64 10)
    )"#;

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(res.exported_globals[0], Global::I64(137));
}

#[test]
fn wasm64_memory_init_test() {
    let wat = r#"
       (module
            (export "memory" (memory 0))
            (func (export "canister_update test")
                i64.const 1024  ;; target memory address
                i32.const 0     ;; data segment offset
                i32.const 4     ;; byte length
                memory.init 0   ;; load passive data segment by index
            )
            (memory i64 1)
            (data (;0;) "\01\02\03\04")
    )"#;

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    match instance.run(FuncRef::Method(WasmMethod::Update("test".to_string()))) {
        Ok(_) => {}
        Err(e) => panic!("Error: {:?}", e),
    }
}

#[test]
// Verify behavior of failed memory grow in wasm64 mode
fn wasm64_handles_memory_grow_failure_test() {
    let wat = r#"
    (module
        (global $g1 (export "g1") (mut i64) (i64.const 0))
        (global $g2 (export "g2") (mut i64) (i64.const 0))
        (func $test (export "canister_update test")
            (memory.grow (i64.const 165536))
            global.set $g1
            (i64.const 137)
            global.set $g2
        )
        (memory (export "memory") i64 10)
    )"#;

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(res.exported_globals[0], Global::I64(-1));
    assert_eq!(res.exported_globals[1], Global::I64(137));
}

#[test]
fn wasm64_import_system_api_functions() {
    let wat = r#"
    (module
      (import "ic0" "msg_reply" (func $msg_reply))
      (import "ic0" "msg_reply_data_append"
        (func $ic0_msg_reply_data_append (param i64) (param i64)))
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i64)))
      (import "ic0" "msg_caller_copy"
        (func $ic0_msg_caller_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_caller_size"
        (func $ic0_msg_caller_size (result i64)))
      (import "ic0" "msg_method_name_copy"
        (func $ic0_msg_method_name_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_method_name_size"
        (func $ic0_msg_method_name_size (result i64)))

      (import "ic0" "msg_reject"
        (func $ic0_msg_reject (param i64) (param i64)))
      (import "ic0" "msg_reject_msg_copy"
        (func $ic0_msg_reject_msg_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_reject_msg_size"
        (func $ic0_msg_reject_msg_size (result i64)))


      (import "ic0" "canister_self_copy"
        (func $ic0_canister_self_copy (param i64) (param i64) (param i64)))
      (import "ic0" "canister_self_size"
        (func $ic0_canister_self_size (result i64)))

      (import "ic0" "debug_print"
        (func $ic0_debug_print (param i64) (param i64)))
      (import "ic0" "trap"
        (func $ic0_trap (param i64) (param i64)))

      (import "ic0" "call_new"
        (func $ic0_call_new
            (param i64 i64)
            (param $method_name_src i64)    (param $method_name_len i64)
            (param $reply_fun i64)          (param $reply_env i64)
            (param $reject_fun i64)         (param $reject_env i64)
        )
      )
      (import "ic0" "call_on_cleanup"
        (func $ic0_call_on_cleanup (param $fun i64) (param $env i64)))
      (import "ic0" "call_data_append" 
        (func $ic0_call_data_append (param i64) (param i64)))

      (import "ic0" "canister_cycle_balance128"
        (func $ic0_canister_cycle_balance128 (param i64)))
      (import "ic0" "msg_cycles_available128"
        (func $ic0_msg_cycles_available128 (param i64)))
      (import "ic0" "msg_cycles_refunded128"
        (func $ic0_msg_cycles_refunded128 (param i64)))
      (import "ic0" "msg_cycles_accept128"
        (func $ic0_msg_cycles_accept128 (param i64) (param i64) (param i64)))
      (import "ic0" "cycles_burn128"
        (func $ic0_cycles_burn128 (param i64) (param i64) (param i64)))

      (import "ic0" "certified_data_set"
        (func $ic0_certified_data_set (param i64) (param i64)))

      (import "ic0" "data_certificate_copy"
        (func $ic0_data_certificate_copy (param i64) (param i64) (param i64)))
      (import "ic0" "data_certificate_size"
        (func $ic0_data_certificate_size (result i64)))

      (import "ic0" "is_controller"
        (func $ic0_is_controller (param i64) (param i64) (result i32)))

        (global $g1 (export "g1") (mut i64) (i64.const 0))
        (func $test (export "canister_update test")
            (i64.store (i64.const 0) (memory.grow (i64.const 1)))
            (i64.store (i64.const 20) (i64.const 137))
            (i64.load (i64.const 20))
            global.set $g1
        )

        ;; actually calling this would result in ContractViolation for invalid ApiType
        ;; we just want to check that it compiles and signatures match
        (func $call_all
            (call $ic0_msg_caller_copy (i64.const 4096) (i64.const 0) (call $ic0_msg_caller_size))
            (call $ic0_msg_arg_data_copy (i64.const 4096) (i64.const 0) (call $ic0_msg_arg_data_size))
            (call $ic0_canister_self_copy (i64.const 4096) (i64.const 0) (call $ic0_canister_self_size))
            (call $ic0_msg_method_name_copy (i64.const 4096) (i64.const 0) (call $ic0_msg_method_name_size))
            (call $ic0_msg_reply_data_append (i64.const 0) (i64.const 5))
            (call $ic0_msg_reject (i64.const 0) (i64.const 5))
            (call $ic0_msg_reject_msg_copy (i64.const 4096) (i64.const 0) (call $ic0_msg_reject_msg_size))
            (call $ic0_canister_cycle_balance128 (i64.const 4096))
            (call $ic0_debug_print (i64.const 0) (i64.const 5))
            (call $ic0_trap (i64.const 0) (i64.const 5))
            (call $ic0_call_new
                (i64.const 100) (i64.const 10)  ;; callee canister id
                (i64.const 0) (i64.const 18)    ;; method name
                (i64.const 11) (i64.const 22)   ;; on_reply closure
                (i64.const 33) (i64.const 44)   ;; on_reject closure
            )
            (call $ic0_call_on_cleanup
                (i64.const 33) (i64.const 44)   ;; cleanup closure
            )
            (call $ic0_call_data_append (i64.const 0) (i64.const 5))
            (call $ic0_msg_cycles_available128 (i64.const 4096))
            (call $ic0_msg_cycles_refunded128 (i64.const 4096))
            (call $ic0_msg_cycles_accept128 (i64.const 500) (i64.const 5) (i64.const 4096))
            (call $ic0_cycles_burn128 (i64.const 500) (i64.const 5) (i64.const 4096))

            (call $ic0_certified_data_set (i64.const 0) (i64.const 5))
            (call $ic0_data_certificate_copy (i64.const 4096) (i64.const 0) (call $ic0_data_certificate_size))
            (drop (call $ic0_is_controller (i64.const 0) (i64.const 5)))

          )


        (memory (export "memory") i64 10)
    )"#;

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    assert_eq!(res.exported_globals[0], Global::I64(137));
}

#[test]
fn wasm64_msg_caller_copy() {
    let wat = r#"
    (module
      (import "ic0" "msg_caller_copy"
        (func $ic0_msg_caller_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_caller_size"
        (func $ic0_msg_caller_size (result i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (call $ic0_msg_caller_size)
        global.set $g1
        (call $ic0_msg_caller_copy (i64.const 0) (i64.const 0) (call $ic0_msg_caller_size))
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let payload = vec![0u8; 32];
    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        payload,
        Cycles::zero(),
        caller,
        call_context_test_id(13),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0
    // Size of the write is returned via the global at idx 0

    let caller_bytes = caller.as_slice();
    assert_eq!(
        res.exported_globals[0],
        Global::I64(caller_bytes.len() as i64)
    );

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..caller_bytes.len()].copy_from_slice(caller_bytes);

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn wasm64_msg_arg_data_copy() {
    let wat = r#"
    (module
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (call $ic0_msg_arg_data_size)
        global.set $g1
        (call $ic0_msg_arg_data_copy (i64.const 0) (i64.const 0) (call $ic0_msg_arg_data_size))
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let payload: Vec<u8> = vec![1, 3, 5, 7];
    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        payload.clone(),
        Cycles::zero(),
        caller,
        call_context_test_id(13),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0
    // Size of the write is returned via the global at idx 0

    assert_eq!(res.exported_globals[0], Global::I64(payload.len() as i64));

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..payload.len()].copy_from_slice(payload.as_slice());

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn wasm64_msg_method_name_copy() {
    let wat = r#"
    (module
      (import "ic0" "msg_method_name_copy"
        (func $ic0_msg_method_name_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_method_name_size"
        (func $ic0_msg_method_name_size (result i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (call $ic0_msg_method_name_size)
        global.set $g1
        (call $ic0_msg_method_name_copy (i64.const 0) (i64.const 0) (call $ic0_msg_method_name_size))
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let payload: Vec<u8> = vec![1, 3, 5, 7];
    let msg_name = "test".to_string();
    let api =
        ic_system_api::ApiType::inspect_message(caller, msg_name.clone(), payload, UNIX_EPOCH);

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0
    // Size of the write is returned via the global at idx 0

    assert_eq!(res.exported_globals[0], Global::I64(msg_name.len() as i64));

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..msg_name.len()].copy_from_slice(msg_name.as_bytes());

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn wasm64_msg_reply_data_append() {
    let wat = r#"
    (module
      (import "ic0" "msg_reply" (func $ic0_msg_reply))
      (import "ic0" "msg_reply_data_append"
        (func $ic0_msg_reply_data_append (param i64) (param i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (i64.store8 (i64.const 1) (i64.const 5))
        (i64.store8 (i64.const 2) (i64.const 1))
        (i64.store8 (i64.const 3) (i64.const 4))
        (i64.store8 (i64.const 4) (i64.const 2))
        (i64.store8 (i64.const 5) (i64.const 3))
        (i64.const 5)
        global.set $g1
        (call $ic0_msg_reply_data_append (i64.const 1) (i64.const 5))
        (call $ic0_msg_reply)
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let payload: Vec<u8> = vec![1, 3, 5, 7];
    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        payload,
        Cycles::zero(),
        caller,
        call_context_test_id(13),
    );
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance.run(FuncRef::Method(WasmMethod::Update("test".to_string())));

    let wasm_res = instance
        .store_data_mut()
        .system_api_mut()
        .unwrap()
        .take_execution_result(res.as_ref().err());

    assert_eq!(wasm_res, Ok(Some(WasmResult::Reply(vec![5, 1, 4, 2, 3]))));
}

#[test]
fn wasm64_msg_reject() {
    let wat = r#"
    (module
      (import "ic0" "msg_reject"
        (func $ic0_msg_reject (param i64) (param i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (i64.store8 (i64.const 0) (i64.const 103)) ;;g
        (i64.store8 (i64.const 1) (i64.const 111)) ;;o
        (i64.store8 (i64.const 2) (i64.const 97))  ;;a
        (i64.store8 (i64.const 3) (i64.const 119)) ;;w
        (i64.store8 (i64.const 4) (i64.const 97))  ;;a
        (i64.store8 (i64.const 5) (i64.const 121)) ;;y
        (i64.const 6)
        global.set $g1

        (call $ic0_msg_reject (i64.const 0) (i64.const 6))
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let payload: Vec<u8> = vec![1, 3, 5, 7];
    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        payload,
        Cycles::zero(),
        caller,
        call_context_test_id(13),
    );
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance.run(FuncRef::Method(WasmMethod::Update("test".to_string())));

    let wasm_res = instance
        .store_data_mut()
        .system_api_mut()
        .unwrap()
        .take_execution_result(res.as_ref().err());

    assert_eq!(wasm_res, Ok(Some(WasmResult::Reject("goaway".to_string()))));
}

#[test]
fn wasm64_reject_msg_copy() {
    let wat = r#"
    (module
      (import "ic0" "msg_reject_msg_copy"
        (func $ic0_msg_reject_msg_copy (param i64) (param i64) (param i64)))
      (import "ic0" "msg_reject_msg_size"
        (func $ic0_msg_reject_msg_size (result i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (call $ic0_msg_reject_msg_size)
        global.set $g1
        (call $ic0_msg_reject_msg_copy (i64.const 0) (i64.const 0) (call $ic0_msg_reject_msg_size))
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let reject_msg = "go away".to_string();
    let api = ic_system_api::ApiType::reject_callback(
        UNIX_EPOCH,
        caller,
        RejectContext::new(
            ic_error_types::RejectCode::CanisterReject,
            reject_msg.clone(),
        ),
        Cycles::zero(),
        call_context_test_id(13),
        false,
        ExecutionMode::Replicated,
        NumInstructions::new(700),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0
    // Size of the write is returned via the global at idx 0

    assert_eq!(
        res.exported_globals[0],
        Global::I64(reject_msg.len() as i64)
    );

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..reject_msg.len()].copy_from_slice(reject_msg.as_bytes());

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn wasm64_canister_self_copy() {
    let wat = r#"
    (module
      (import "ic0" "canister_self_copy"
        (func $ic0_canister_self_copy (param i64) (param i64) (param i64)))
      (import "ic0" "canister_self_size"
        (func $ic0_canister_self_size (result i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (call $ic0_canister_self_size)
        global.set $g1
        (call $ic0_canister_self_copy (i64.const 0) (i64.const 0) (call $ic0_canister_self_size))
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let payload: Vec<u8> = vec![1, 3, 5, 7];
    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        payload.clone(),
        Cycles::zero(),
        caller,
        call_context_test_id(13),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();

    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // This is the system state used by WasmtimeInstanceBuilder
    let system_state = ic_test_utilities_state::SystemStateBuilder::default().build();
    let canister_id = system_state.canister_id.get_ref().as_slice();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0
    // Size of the write is returned via the global at idx 0

    assert_eq!(
        res.exported_globals[0],
        Global::I64(canister_id.len() as i64)
    );

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..canister_id.len()].copy_from_slice(canister_id);

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn wasm64_trap() {
    let wat = r#"
    (module
      (import "ic0" "trap"
        (func $ic0_trap (param i64) (param i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (i64.store8 (i64.const 10) (i64.const 72))  ;;H
        (i64.store8 (i64.const 11) (i64.const 101)) ;;e
        (i64.store8 (i64.const 12) (i64.const 108)) ;;l
        (i64.store8 (i64.const 13) (i64.const 108)) ;;l
        (i64.store8 (i64.const 14) (i64.const 111)) ;;o
        (i64.const 5)
        global.set $g1

        (call $ic0_trap (i64.const 10) (i64.const 5))
      )

      (memory (export "memory") i64 1)
    )"#;

    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        Vec::new(),
        Cycles::zero(),
        user_test_id(24).get(),
        call_context_test_id(13),
    );
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let err = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap_err();

    assert_eq!(err, HypervisorError::CalledTrap("Hello".to_string()));
}

#[test]
fn wasm64_canister_cycle_balance128() {
    let wat = r#"
    (module
      (import "ic0" "canister_cycle_balance128"
        (func $ic0_canister_cycle_balance128 (param i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (i64.const 137)
        global.set $g1
        (call $ic0_canister_cycle_balance128 (i64.const 0))
      )

      (memory (export "memory") i64 1)
    )"#;

    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        vec![],
        Cycles::zero(),
        user_test_id(24).get(),
        call_context_test_id(13),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0

    assert_eq!(res.exported_globals[0], Global::I64(137));

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let balance = instance
        .store_data_mut()
        .system_api_mut()
        .unwrap()
        .ic0_canister_cycle_balance()
        .unwrap() as u128;

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..16].copy_from_slice(&balance.to_le_bytes());

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn wasm64_msg_cycles_refunded128() {
    let wat = r#"
    (module
      (import "ic0" "msg_cycles_refunded128"
        (func $ic0_msg_cycles_refunded128 (param i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (i64.const 137)
        global.set $g1
        (call $ic0_msg_cycles_refunded128 (i64.const 0))
      )

      (memory (export "memory") i64 1)
    )"#;

    let caller = user_test_id(24).get();
    let reject_msg = "go away".to_string();
    let api = ic_system_api::ApiType::reject_callback(
        UNIX_EPOCH,
        caller,
        RejectContext::new(
            ic_error_types::RejectCode::CanisterReject,
            reject_msg.clone(),
        ),
        Cycles::new(777),
        call_context_test_id(13),
        false,
        ExecutionMode::Replicated,
        NumInstructions::new(700),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0

    assert_eq!(res.exported_globals[0], Global::I64(137));

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let x = 777u128;

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..16].copy_from_slice(&x.to_le_bytes());

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn wasm64_cycles_burn128() {
    let wat = r#"
    (module
      (import "ic0" "cycles_burn128"
        (func $ic0_cycles_burn128 (param i64) (param i64) (param i64)))

      (global $g1 (export "g1") (mut i64) (i64.const 0))
      (func $test (export "canister_update test")
        (i64.const 137)
        global.set $g1
        (call $ic0_cycles_burn128 (i64.const 0) (i64.const 33) (i64.const 0))
      )

      (memory (export "memory") i64 1)
    )"#;

    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        vec![],
        Cycles::zero(),
        user_test_id(24).get(),
        call_context_test_id(13),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();

    // After this call, we expect the instance to have a memory with size of 1 wasm page
    // of which the first OS page was touched and contains relevant data at offset 0

    assert_eq!(res.exported_globals[0], Global::I64(137));

    // only first os page should have been touched
    assert_eq!(res.wasm_dirty_pages, vec![ic_sys::PageIndex::new(0)]);

    // actual heap is larger, but we can only access first os page, the rest is protected
    let dirty_heap_size = ic_sys::PAGE_SIZE;

    let wasm_heap: &[u8] = unsafe {
        let addr = instance.heap_addr(CanisterMemoryType::Heap);
        let size_in_bytes =
            instance.heap_size(CanisterMemoryType::Heap).get() * WASM_PAGE_SIZE_IN_BYTES;
        assert!(size_in_bytes >= dirty_heap_size);
        std::slice::from_raw_parts_mut(addr as *mut _, dirty_heap_size)
    };

    let x = 33u128;

    let mut expected_heap = vec![0; dirty_heap_size];
    expected_heap[0..16].copy_from_slice(&x.to_le_bytes());

    assert_eq!(wasm_heap, expected_heap);
}

#[test]
fn large_wasm64_memory_allocation_test() {
    // This test checks if maximum memory size
    // is capped to the maximum allowed memory size in 64 bit mode.

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let max_heap_size_in_pages = config.max_wasm_memory_size.get() / WASM_PAGE_SIZE as u64;
    let wat = format!(
        r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param $src i64) (param $size i64)))
        (func $test (export "canister_update test")
            ;; store the result of memory.grow at heap address 0
            (i64.store (i64.const 0) (memory.grow (i64.const 1)))
            ;; return the result of memory.grow
            (call $msg_reply_data_append (i64.const 0) (i64.const 1))
            (call $msg_reply)
        )
        ;; declare a memory with initial size max_heap and another max large value
        (memory i64 {} {})
    )"#,
        max_heap_size_in_pages,
        max_heap_size_in_pages * 100
    );

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_api_type(ic_system_api::ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::zero(),
            user_test_id(24).get(),
            call_context_test_id(13),
        ))
        .with_wat(&wat)
        .build();

    let result = instance.run(FuncRef::Method(WasmMethod::Update("test".to_string())));
    let wasm_res = instance
        .store_data_mut()
        .system_api_mut()
        .unwrap()
        .take_execution_result(result.as_ref().err());

    // The reply is actually the encoding of -1 (the memory grow failed).
    assert_eq!(wasm_res, Ok(Some(WasmResult::Reply(vec![255]))));
}

#[test]
fn large_wasm64_stable_read_write_test() {
    // This test checks if we allow stable_read and stable_write to work with offsets
    // larger than 4 GiB in the wasm heap memory in 64 bit mode.
    let wat = r#"
    (module
        (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
        (import "ic0" "stable64_read"
            (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
        (import "ic0" "stable64_write"
            (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param $src i64) (param $size i64)))
        (func $test (export "canister_update test")

            (i64.store (i64.const 4294967312) (i64.const 72))
            (i64.store (i64.const 4294967313) (i64.const 101))
            (i64.store (i64.const 4294967314) (i64.const 108))
            (i64.store (i64.const 4294967315) (i64.const 108))
            (i64.store (i64.const 4294967316) (i64.const 111))
           
            (drop (call $stable_grow (i64.const 10)))

            ;; Write to stable memory from large heap offset.
            (call $ic0_stable64_write (i64.const 0) (i64.const 4294967312) (i64.const 5))
            ;; Read from stable memory at a different heap offset.
            (call $ic0_stable64_read (i64.const 4294967320) (i64.const 0) (i64.const 5))
           
            ;; Return the result of the read operation.
            (call $msg_reply_data_append (i64.const 4294967320) (i64.const 5))
            (call $msg_reply)
        )
        (memory i64 70007 70007)
    )"#;

    let gb = 1024 * 1024 * 1024;

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    config.feature_flags.wasm_native_stable_memory = FlagStatus::Enabled;
    // Declare a large heap.
    config.max_wasm_memory_size = NumBytes::from(10 * gb);

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_api_type(ic_system_api::ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::zero(),
            user_test_id(24).get(),
            call_context_test_id(13),
        ))
        .with_wat(wat)
        .with_canister_memory_limit(NumBytes::from(40 * gb))
        .build();

    let result = instance.run(FuncRef::Method(WasmMethod::Update("test".to_string())));
    let wasm_res = instance
        .store_data_mut()
        .system_api_mut()
        .unwrap()
        .take_execution_result(result.as_ref().err());

    assert_eq!(
        wasm_res,
        Ok(Some(WasmResult::Reply(vec![72, 101, 108, 108, 111])))
    );
}

#[test]
fn wasm64_saturate_fun_index() {
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i64 i64)
                    (param $method_name_src i64)    (param $method_name_len i64)
                    (param $reply_fun i64)          (param $reply_env i64)
                    (param $reject_fun i64)         (param $reject_env i64)
                )
            )
            (import "ic0" "call_data_append"
                (func $ic0_call_data_append (param $src i64) (param $size i64))
            )
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "call_on_cleanup"
                (func $ic0_call_on_cleanup (param $fun i64) (param $env i64)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i64.const 100) (i64.const 10)  ;; callee canister id = 777
                    (i64.const 0) (i64.const 18)    ;; refers to "some_remote_method" on the heap
                    (i64.const -1) (i64.const 22)   ;; on_reply closure
                    (i64.const -1) (i64.const 44)   ;; on_reject closure
                )
                (call $ic0_call_data_append
                    (i64.const 19) (i64.const 3)    ;; refers to "XYZ" on the heap
                )
                (call $ic0_call_on_cleanup
                    (i64.const -1) (i64.const 66)   ;; cleanup closure
                )
                (call $ic0_call_perform)
                drop
                (call $msg_reply)
            )
            (memory i64 1 1)
            (data (i64.const 0) "some_remote_method XYZ")
            (data (i64.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;

    let api = ic_system_api::ApiType::update(
        UNIX_EPOCH,
        vec![],
        Cycles::zero(),
        user_test_id(24).get(),
        call_context_test_id(13),
    );

    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm64 = FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_api_type(api)
        .build();
    let _res = instance.run(FuncRef::Method(WasmMethod::Update("test".to_string())));

    let system_state_changes = instance
        .store_data_mut()
        .system_api_mut()
        .unwrap()
        .take_system_state_changes();

    // call_perform should trigger one callback update
    let callback_update = system_state_changes
        .callback_updates
        .first()
        .unwrap()
        .clone();
    match callback_update {
        ic_system_api::sandbox_safe_system_state::CallbackUpdate::Register(_id, callback) => {
            assert_eq!(
                callback.on_reply,
                WasmClosure {
                    func_idx: u32::MAX,
                    env: 22
                }
            );
            assert_eq!(
                callback.on_reject,
                WasmClosure {
                    func_idx: u32::MAX,
                    env: 44
                }
            );
            assert_eq!(
                callback.on_cleanup,
                Some(WasmClosure {
                    func_idx: u32::MAX,
                    env: 66
                })
            );
        }
        ic_system_api::sandbox_safe_system_state::CallbackUpdate::Unregister(_) => {
            panic!("Expected registration of new calback")
        }
    }
}
