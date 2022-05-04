use ic_replicated_state::Global;
use ic_test_utilities::wasmtime_instance::WasmtimeInstanceBuilder;
use ic_types::methods::{FuncRef, WasmMethod};

#[cfg(test)]
mod test {
    use ic_test_utilities::wasmtime_instance::DEFAULT_NUM_INSTRUCTIONS;

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
