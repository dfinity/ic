use assert_matches::assert_matches;
use ic_embedders::{
    wasm_utils::instrumentation::instruction_to_cost_new, wasmtime_embedder::system_api_complexity,
};
use ic_interfaces::execution_environment::{HypervisorError, SystemApi, TrapCode};
use ic_replicated_state::{canister_state::WASM_PAGE_SIZE_IN_BYTES, Global};
use ic_test_utilities::wasmtime_instance::{WasmtimeInstanceBuilder, DEFAULT_NUM_INSTRUCTIONS};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{
    methods::{FuncRef, WasmClosure, WasmMethod},
    time::UNIX_EPOCH,
    NumBytes,
};

#[cfg(target_os = "linux")]
use ic_types::{Cycles, PrincipalId};

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
                ic_interfaces::execution_environment::HypervisorError::ContractViolation(
                    "WebAssembly module must define memory".to_string()
                )
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

    let const_cost = instruction_to_cost_new(&wasmparser::Operator::I32Const { value: 1 });
    let call_cost = instruction_to_cost_new(&wasmparser::Operator::Call { function_index: 0 });

    let expected_instructions = 1 // Function is 1 instruction.
            + 3 * const_cost
            + call_cost
            + system_api_complexity::overhead::new::MSG_ARG_DATA_COPY.get()
            + data_size;
    assert_eq!(instructions_used.get(), expected_instructions);
}

#[test]
fn instruction_limit_traps() {
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
        .with_num_instructions(1000.into())
        .build();

    let result = instance.run(ic_types::methods::FuncRef::Method(
        ic_types::methods::WasmMethod::Update("test_msg_arg_data_copy".to_string()),
    ));

    assert_eq!(
        result.err(),
        Some(HypervisorError::InstructionLimitExceeded)
    );
}

#[test]
fn correctly_report_performance_counter() {
    let data_size = 1024;

    let const_cost = instruction_to_cost_new(&wasmparser::Operator::I32Const { value: 1 });
    let call_cost = instruction_to_cost_new(&wasmparser::Operator::Call { function_index: 0 });
    let drop_const_cost = instruction_to_cost_new(&wasmparser::Operator::Drop) + const_cost;
    let global_set_cost =
        instruction_to_cost_new(&wasmparser::Operator::GlobalSet { global_index: 0 });

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
            + system_api_complexity::overhead::new::MSG_ARG_DATA_COPY.get()
            + data_size
            + drop_const_cost
            + const_cost
            + call_cost
            + system_api_complexity::overhead::new::PERFORMANCE_COUNTER.get()
            + global_set_cost
            + 2 * drop_const_cost
            + 3 * const_cost
            + call_cost
            + const_cost
            + call_cost
            + global_set_cost;
    // Includes dynamic part for second data copy and performance counter calls
    let expected_instructions_counter2 = expected_instructions_counter1
        + system_api_complexity::overhead::new::MSG_ARG_DATA_COPY.get()
        + data_size
        + system_api_complexity::overhead::new::PERFORMANCE_COUNTER.get();
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
#[should_panic(expected = "global of type I32 cannot be set to I64")]
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
        HypervisorError::ContractViolation(
            "function invocation does not match its signature".to_string()
        )
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
    assert_eq!(stats.direct_write_count, 1);
    assert_eq!(stats.read_before_write_count, 0);

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
    assert_eq!(stats.direct_write_count, 0);
    assert_eq!(stats.read_before_write_count, 1);
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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;
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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;
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

    let mut config = ic_config::embedders::Config {
        stable_memory_accessed_page_limit: ic_types::NumPages::new(3),
        ..Default::default()
    };
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;
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

    let mut config = ic_config::embedders::Config {
        stable_memory_accessed_page_limit: ic_types::NumPages::new(3),
        ..Default::default()
    };
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;
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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let _res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    // one dirty heap page and 13 stable
    assert_eq!(instance.get_stats().dirty_pages, 1 + 13);
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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .build();
    let _res = instance
        .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
        .unwrap();
    // one dirty heap page and 13 stable
    assert_eq!(instance.get_stats().dirty_pages, 1 + 13);
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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;

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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;

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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;

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
    let mut config = ic_config::embedders::Config::default();
    config.feature_flags.wasm_native_stable_memory = ic_config::flag_status::FlagStatus::Enabled;
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
