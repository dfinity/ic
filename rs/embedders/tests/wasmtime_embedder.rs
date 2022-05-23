use ic_embedders::wasmtime_embedder::system_api_complexity;
use ic_interfaces::execution_environment::SystemApi;
use ic_replicated_state::Global;
use ic_test_utilities::{
    mock_time, types::ids::user_test_id, wasmtime_instance::WasmtimeInstanceBuilder,
};
use ic_types::methods::{FuncRef, WasmMethod};

#[cfg(test)]
mod test {
    use ic_interfaces::execution_environment::HypervisorError;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities::wasmtime_instance::DEFAULT_NUM_INSTRUCTIONS;
    use ic_types::PrincipalId;

    use super::*;

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
            ic_types::methods::WasmMethod::Update(
                "should_fail_with_contract_violation".to_string(),
            ),
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
                mock_time(),
                vec![0; 1024],
                user_test_id(24).get(),
            ))
            .build();

        instance
            .run(ic_types::methods::FuncRef::Method(
                ic_types::methods::WasmMethod::Update("test_msg_arg_data_copy".to_string()),
            ))
            .unwrap();

        let system_api = &instance.store_data_mut().system_api;
        let instructions_limit = system_api.total_instruction_limit();
        let num_instructions = instance.get_num_instructions();
        let instructions_used = instructions_limit - num_instructions;

        let call_msg_arg_data_copy_with_3_const = 4;
        let expected_instructions = call_msg_arg_data_copy_with_3_const
            + data_size
            + system_api_complexity::overhead::MSG_ARG_DATA_COPY.get();
        assert_eq!(instructions_used.get(), expected_instructions);
    }

    #[test]
    fn instruction_limit_traps() {
        let data_size = 1024;
        let call_msg_arg_data_copy_with_3_const = 4;
        let expected_instructions = call_msg_arg_data_copy_with_3_const
            + data_size
            + system_api_complexity::overhead::MSG_ARG_DATA_COPY.get();
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
                mock_time(),
                vec![0; 1024],
                user_test_id(24).get(),
            ))
            .with_num_instructions((expected_instructions - 1).into())
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

        let wasm_const = 1;
        let wasm_call_msg_arg_data_copy_with_3_const = 1 + 3 * wasm_const;
        let wasm_call_performance_counter_with_const = 1 + wasm_const;
        let wasm_drop_const = 1 + wasm_const;
        let wasm_global_set = 1;
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
        let expected_instructions_counter1 = (wasm_call_msg_arg_data_copy_with_3_const
                + data_size
                + system_api_complexity::overhead::MSG_ARG_DATA_COPY.get())
                + wasm_drop_const
                + wasm_call_performance_counter_with_const
                + system_api_complexity::overhead::PERFORMANCE_COUNTER.get()
                + wasm_global_set
                + wasm_drop_const
                + wasm_drop_const
                + wasm_call_msg_arg_data_copy_with_3_const // No data size
                + wasm_call_performance_counter_with_const
                + wasm_global_set;
        // Includes dynamic part for second data copy and performance counter calls
        let expected_instructions_counter2 = expected_instructions_counter1
            + (data_size + system_api_complexity::overhead::MSG_ARG_DATA_COPY.get())
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
                mock_time(),
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
        let performance_counter1 = match res.exported_globals[0] {
            Global::I64(c) => c as u64,
            _ => panic!("Error getting performance_counter1"),
        };
        let performance_counter2 = match res.exported_globals[1] {
            Global::I64(c) => c as u64,
            _ => panic!("Error getting performance_counter2"),
        };
        let system_api = &instance.store_data_mut().system_api;
        let instructions_limit = system_api.total_instruction_limit();
        let num_instructions = instance.get_num_instructions();
        let instructions_used = instructions_limit - num_instructions;
        assert_eq!(performance_counter1, expected_instructions_counter1);
        assert_eq!(performance_counter2, expected_instructions_counter2);

        assert_eq!(instructions_used.get(), expected_instructions);
    }

    const CALL_NEW_CALL_PERFORM_WAT: &str = r#"
    (module
        (import "ic0" "call_new"
            (func $ic0_call_new
            (param $callee_src i32)         (param $callee_size i32)
            (param $name_src i32)           (param $name_size i32)
            (param $reply_fun i32)          (param $reply_env i32)
            (param $reject_fun i32)         (param $reject_env i32)
        ))
        (import "ic0" "call_perform"
            (func $ic0_call_perform (result i32)))
        (memory 1)
        (func (export "canister_update test_call_perform")
            (call $ic0_call_new
                (i32.const 0)   (i32.const 10)
                (i32.const 100) (i32.const 18)
                (i32.const 11)  (i32.const 0) ;; non-existent function
                (i32.const 22)  (i32.const 0) ;; non-existent function
            )
            (drop (call $ic0_call_perform))
        )
    )
    "#;

    #[test]
    fn correctly_observe_system_api_complexity() {
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_wat(CALL_NEW_CALL_PERFORM_WAT)
            .with_api_type(ic_system_api::ApiType::update(
                mock_time(),
                vec![],
                0.into(),
                PrincipalId::new_user_test_id(0),
                0.into(),
            ))
            .build();

        instance
            .run(ic_types::methods::FuncRef::Method(
                ic_types::methods::WasmMethod::Update("test_call_perform".to_string()),
            ))
            .unwrap();

        let system_api = &instance.store_data_mut().system_api;
        let instructions_limit = system_api.total_instruction_limit();
        let num_instructions = instance.get_num_instructions();
        let instructions_used = instructions_limit - num_instructions;

        let call_new_with_8_const = 9;
        let drop_with_call_perform = 2;
        let expected_instructions = call_new_with_8_const
            + drop_with_call_perform
            + system_api_complexity::overhead::CALL_NEW.get()
            + system_api_complexity::overhead::CALL_PERFORM.get();
        assert_eq!(instructions_used.get(), expected_instructions);

        let total_cpu_complexity = instance
            .into_store_data()
            .system_api
            .get_total_execution_complexity()
            .cpu;
        let expected_cpu_complexity =
            system_api_complexity::cpu::CALL_NEW + system_api_complexity::cpu::CALL_PERFORM;
        assert_eq!(total_cpu_complexity, expected_cpu_complexity);
    }

    #[test]
    fn complex_system_api_call_traps() {
        let subnet_type = SubnetType::Application;
        let expected_cpu_complexity = system_api_complexity::cpu::CALL_NEW.get()
            + system_api_complexity::cpu::CALL_PERFORM.get();
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_wat(CALL_NEW_CALL_PERFORM_WAT)
            .with_api_type(ic_system_api::ApiType::update(
                mock_time(),
                vec![],
                0.into(),
                PrincipalId::new_user_test_id(0),
                0.into(),
            ))
            .with_num_instructions((expected_cpu_complexity - 1).into())
            .with_subnet_type(subnet_type)
            .build();

        let result = instance.run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::Update("test_call_perform".to_string()),
        ));

        assert_eq!(
            result.err(),
            Some(HypervisorError::InstructionLimitExceeded)
        );
    }

    #[test]
    fn complex_system_api_call_does_not_trap_on_system_subnet() {
        // The same setup as previously, but with the System subnet type
        let subnet_type = SubnetType::System;
        let expected_cpu_complexity = (system_api_complexity::cpu::CALL_NEW.get()
            + system_api_complexity::cpu::CALL_PERFORM.get())
            * 5; // times 5B instructions per message / nanos_in_sec
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_wat(CALL_NEW_CALL_PERFORM_WAT)
            .with_api_type(ic_system_api::ApiType::update(
                mock_time(),
                vec![],
                0.into(),
                PrincipalId::new_user_test_id(0),
                0.into(),
            ))
            .with_num_instructions((expected_cpu_complexity - 1).into())
            .with_subnet_type(subnet_type)
            .build();

        let result = instance.run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::Update("test_call_perform".to_string()),
        ));

        // Should not fail on System subnet
        assert!(result.is_ok());
    }

    /// The spec doesn't allow exported functions to have results.
    #[test]
    fn function_with_results_traps() {
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_wat(
                r#"
          (module
            (func $f (export "canister_update f") (result i64)
              (i64.const 1)
            )
          )
        "#,
            )
            .build();

        let result = instance.run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::Update("f".to_string()),
        ));

        match result {
            Ok(_) => panic!("Expected a HypervisorError::ContractViolation"),
            Err(err) => {
                assert!(matches!(
                    err,
                    ic_interfaces::execution_environment::HypervisorError::ContractViolation(_)
                ));
            }
        }
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
                Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64)
            ]
        );

        // Change the value of globals and verify we can get them back.
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_wat(wat)
            .with_globals(vec![Global::I64(5), Global::I32(12), Global::I64(2468)])
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
                Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64),
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
                Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64),
            ]
        );

        // Change the value of globals and verify we can get them back.
        let mut instance = WasmtimeInstanceBuilder::new()
            .with_wat(wat)
            .with_globals(vec![Global::F64(5.3), Global::F32(12.37)])
            .build();
        let res = instance
            .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
            .unwrap();
        assert_eq!(
            res.exported_globals[..],
            [
                Global::F64(5.3),
                Global::F32(12.37),
                Global::I64(DEFAULT_NUM_INSTRUCTIONS.get() as i64),
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
            .with_globals(vec![Global::I64(5), Global::I64(12)])
            .build();
    }

    #[test]
    #[should_panic(
        expected = "Given exported globals length 513 is more than instance exported globals length 2"
    )]
    fn try_to_set_globals_that_are_more_than_the_instace_globals() {
        // Globals take up a single 4K byte page and they are represented by 64 bits
        // each, so by default there are 4096 * 8 bits / 64 bits = 512 globals.
        const DEFAULT_GLOBALS_LENGTH: usize = 512;

        let _instance = WasmtimeInstanceBuilder::new()
            // Module only exports one global, but instrumentation adds a second.
            .with_wat(
                r#"
                (module
                    (global (export "g") (mut i64) (i64.const 42))
                )"#,
            )
            .with_globals(vec![Global::I64(0); DEFAULT_GLOBALS_LENGTH + 1])
            .build();
    }
}
