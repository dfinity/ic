mod execution_tests {
    use crate::CompilationCostHandling;
    use ic_error_types::ErrorCode;
    use ic_replicated_state::{
        ExecutionState, ExportedFunctions, Memory,
        canister_state::{
            execution_state::{WasmBinary, WasmExecutionMode, WasmMetadata},
            system_state::log_memory_store::LogMemoryStore,
        },
    };
    use ic_test_utilities_execution_environment::{ExecutionTestBuilder, wat_compilation_cost};
    use ic_test_utilities_metrics::{fetch_histogram_stats, fetch_int_counter_vec};
    use ic_types::Cycles;
    use ic_types::{batch::CanisterCyclesCostSchedule, methods::WasmMethod};
    use ic_wasm_types::CanisterModule;
    use maplit::btreemap;
    use std::path::PathBuf;

    const WAT_EMPTY: &str = "(module)";
    const WAT_WITH_GO: &str = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func $go (call $msg_reply))
            (export "canister_update go" (func $go))
        )"#;

    #[test]
    fn compilation_of_repeated_instructions_succeeds() {
        let mut test = ExecutionTestBuilder::new().build();
        let wat = format!(
            r#"
            (module
                (func (result i64)
                    (i64.const 1)
                    {}
                )
                (func)
            )"#,
            "(i64.add (i64.const 1))".repeat(20_000)
        );
        test.canister_from_wat(wat).unwrap();
        let largest_function_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_largest_function_instruction_count",
        )
        .unwrap();
        assert_eq!(largest_function_metric.count, 1);
    }

    #[test]
    fn compilation_metrics_are_recorded_during_installation() {
        let mut test = ExecutionTestBuilder::new().build();
        let wat1 = r#"
        (module
            (func (result i64)
                (i64.const 1)
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
            )
            (func)
        )"#;
        let wat2 = "(module)";
        test.canister_from_wat(wat1).unwrap();
        test.canister_from_wat(wat2).unwrap();
        let largest_function_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_largest_function_instruction_count",
        )
        .unwrap();
        assert_eq!(largest_function_metric.count, 2);
        assert_eq!(largest_function_metric.sum, 8.0);
        let compilation_time_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_wasm_compile_time_seconds",
        )
        .unwrap();
        assert_eq!(compilation_time_metric.count, 2);
    }

    #[test]
    fn compilation_metrics_are_recorded_during_update() {
        let mut test = ExecutionTestBuilder::new().build();
        let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func $go 
                (i64.const 1)
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
                (drop)
                (call $msg_reply)
            )
            (export "canister_update go" (func $go))
        )"#;
        let canister_id = test.canister_from_wat(wat).unwrap();
        let canister_state = test.canister_state_mut(canister_id);
        // Clear caches so that we are forced to recompile.
        canister_state
            .execution_state
            .as_mut()
            .unwrap()
            .wasm_binary
            .clear_compilation_cache();
        test.execution_environment()
            .clear_compilation_cache_for_testing();
        test.ingress(canister_id, "go", vec![]).unwrap();
        let largest_function_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_largest_function_instruction_count",
        )
        .unwrap();
        // Compiled once for install and once for execution.
        assert_eq!(largest_function_metric.count, 2);
        assert_eq!(largest_function_metric.sum, 20.0);
        let compilation_time_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_wasm_compile_time_seconds",
        )
        .unwrap();
        assert_eq!(compilation_time_metric.count, 2);
    }

    #[test]
    fn compilation_shared_from_install_to_update() {
        let mut test = ExecutionTestBuilder::new().build();

        // Install canister with wat.
        let canister_id1 = test.canister_from_wat(WAT_WITH_GO).unwrap();
        let canister_state = test.canister_state_mut(canister_id1);

        // Clear caches so that we are forced to recompile.
        canister_state
            .execution_state
            .as_mut()
            .unwrap()
            .wasm_binary
            .clear_compilation_cache();
        test.execution_environment()
            .clear_compilation_cache_for_testing();

        // Install second canister with same wat.
        let _canister_id2 = test.canister_from_wat(WAT_WITH_GO).unwrap();

        // Now an update on the first canister shouldn't require compilation. So we
        // get one compilation for each canister install.
        test.ingress(canister_id1, "go", vec![]).unwrap();
        let compilation_time_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_wasm_compile_time_seconds",
        )
        .unwrap();
        assert_eq!(compilation_time_metric.count, 2);
    }

    #[test]
    fn compilation_shared_from_update_to_update() {
        let mut test = ExecutionTestBuilder::new().build();

        // Install two canisters with the same wat.
        let canister_id1 = test.canister_from_wat(WAT_WITH_GO).unwrap();
        let canister_id2 = test.canister_from_wat(WAT_WITH_GO).unwrap();

        // Clear caches so that we are forced to recompile.
        test.canister_state_mut(canister_id1)
            .execution_state
            .as_mut()
            .unwrap()
            .wasm_binary
            .clear_compilation_cache();
        test.canister_state_mut(canister_id2)
            .execution_state
            .as_mut()
            .unwrap()
            .wasm_binary
            .clear_compilation_cache();
        test.execution_environment()
            .clear_compilation_cache_for_testing();

        // Now an update on one canister will require compilation, but not on the
        // second. So we get 2 compilations in total (1 for first install and 1 for
        // one of the updates).
        test.ingress(canister_id1, "go", vec![]).unwrap();
        test.ingress(canister_id2, "go", vec![]).unwrap();
        let compilation_time_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_wasm_compile_time_seconds",
        )
        .unwrap();
        assert_eq!(compilation_time_metric.count, 2);
    }

    #[test]
    fn compilation_shared_from_install_to_install() {
        let mut test = ExecutionTestBuilder::new().build();

        // Install two canisters with the same wat.
        let _canister_id1 = test.canister_from_wat(WAT_EMPTY).unwrap();
        let _canister_id2 = test.canister_from_wat(WAT_EMPTY).unwrap();

        // Compilation will have been shared so we should have only compiled once.
        let compilation_time_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_wasm_compile_time_seconds",
        )
        .unwrap();
        assert_eq!(compilation_time_metric.count, 1);
    }

    #[test]
    fn compilation_shared_from_update_to_install() {
        let mut test = ExecutionTestBuilder::new().build();

        let canister_id1 = test.canister_from_wat(WAT_WITH_GO).unwrap();

        // Clear caches so that we are forced to recompile.
        test.canister_state_mut(canister_id1)
            .execution_state
            .as_mut()
            .unwrap()
            .wasm_binary
            .clear_compilation_cache();
        test.execution_environment()
            .clear_compilation_cache_for_testing();

        // Now an update on one canister will require compilation, but a new install
        // with the same wasm won't require a compilation.
        test.ingress(canister_id1, "go", vec![]).unwrap();
        let _canister_id2 = test.canister_from_wat(WAT_WITH_GO).unwrap();
        let compilation_time_metric = fetch_histogram_stats(
            test.metrics_registry(),
            "hypervisor_wasm_compile_time_seconds",
        )
        .unwrap();
        assert_eq!(compilation_time_metric.count, 2);
    }

    /// When installing the same wat twice, we should ignore the compilation cost on
    /// the second install because the module is expected to be cached.
    #[test]
    fn compilation_cost_ignored_from_install_to_install() {
        let mut test = ExecutionTestBuilder::new().build();

        // Install two canisters with the same wat.
        let canister_id1 = test.canister_from_wat(WAT_EMPTY).unwrap();
        let initial_balance = Cycles::new(1_000_000_000_000);
        let canister_id2 = test
            .canister_from_cycles_and_wat(initial_balance, WAT_EMPTY)
            .unwrap();

        let compilation_instructions = wat_compilation_cost(WAT_EMPTY);
        assert_eq!(
            test.canister_executed_instructions(canister_id1),
            compilation_instructions
        );
        let reduced_compilation_instructions = CompilationCostHandling::CountReducedAmount
            .adjusted_compilation_cost(compilation_instructions);
        assert_eq!(
            test.canister_executed_instructions(canister_id2),
            reduced_compilation_instructions,
        );

        // Check that the canister has been charged cycles for the reduced compilation cost
        assert_eq!(
            test.canister_state(canister_id2).system_state.balance(),
            initial_balance
                - test.cycles_account_manager().execution_cost(
                    reduced_compilation_instructions,
                    test.subnet_size(),
                    CanisterCyclesCostSchedule::Normal,
                    WasmExecutionMode::Wasm32 // Does not matter if it is Wasm64 or Wasm32 for this test.
                )
        );
    }

    /// If a checkpoint occurs between two installs of the same wasm, the
    /// compilation cost will be incorporated both times because we can't assume it
    /// stayed in the cache.
    #[test]
    fn compilation_cost_charged_when_state_is_cleared() {
        let mut test = ExecutionTestBuilder::new().build();

        // Install two canisters with the same wat.
        let canister_id1 = test.canister_from_wat(WAT_EMPTY).unwrap();
        test.state_mut().metadata.expected_compiled_wasms.clear();
        let initial_balance = Cycles::new(1_000_000_000_000);
        let canister_id2 = test
            .canister_from_cycles_and_wat(initial_balance, WAT_EMPTY)
            .unwrap();

        let compilation_instructions = wat_compilation_cost(WAT_EMPTY);
        assert_eq!(
            test.canister_executed_instructions(canister_id1),
            compilation_instructions
        );
        assert_eq!(
            test.canister_executed_instructions(canister_id2),
            compilation_instructions,
        );

        // Check that the canister has been charged cycles for the full compilation cost
        assert_eq!(
            test.canister_state(canister_id2).system_state.balance(),
            initial_balance
                - test.cycles_account_manager().execution_cost(
                    compilation_instructions,
                    test.subnet_size(),
                    CanisterCyclesCostSchedule::Normal,
                    WasmExecutionMode::Wasm32 // Does not matter if it is Wasm64 or Wasm32 for this test.
                )
        );
    }

    /// Check that compilation errors are stored in the EmbedderCache so that we
    /// don't keep trying to recompile bad WASMS.
    #[test]
    fn compilation_error_cached() {
        let mut test = ExecutionTestBuilder::new().build();

        // Create a canister with invalid wasm. This can't be done through the
        // normal install because the install would be rejected.
        let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
        let canister_state = test.canister_state_mut(canister_id);
        assert!(canister_state.execution_state.is_none());
        canister_state.execution_state = Some(ExecutionState::new(
            PathBuf::new(),
            WasmBinary::new(CanisterModule::new(b"invalid wasm".to_vec())),
            ExportedFunctions::new(
                vec![WasmMethod::Update("go".to_string())]
                    .into_iter()
                    .collect(),
            ),
            Memory::new_for_testing(),
            Memory::new_for_testing(),
            LogMemoryStore::new_for_testing(),
            Vec::new(),
            WasmMetadata::default(),
        ));

        // Call the same method on the canister twice.
        let executed_instructions_before = test.canister_executed_instructions(canister_id);
        assert_eq!(
            test.ingress(canister_id, "go", vec![]).unwrap_err().code(),
            ErrorCode::CanisterInvalidWasm
        );
        assert_eq!(
            test.ingress(canister_id, "go", vec![]).unwrap_err().code(),
            ErrorCode::CanisterInvalidWasm
        );
        let executed_instructions_after = test.canister_executed_instructions(canister_id);
        assert_eq!(executed_instructions_before, executed_instructions_after);

        // Only the first update should trigger a compilation.
        let cache_lookup_metric = fetch_int_counter_vec(
            test.metrics_registry(),
            "sandboxed_execution_replica_cache_lookups",
        );
        assert_eq!(
            cache_lookup_metric,
            btreemap! {
                btreemap!{
                    "lookup_result".to_string() => "cache_miss".to_string(),
                } => 1,
                btreemap!{
                    "lookup_result".to_string() => "embedder_cache_hit_compilation_error".to_string(),
                } => 1,
            }
        );
    }

    #[test]
    fn compilation_error_shared_from_update_to_update() {
        let mut test = ExecutionTestBuilder::new().build();

        // Create two canisters with invalid wasm. This can't be done through the
        // normal install because the install would be rejected.
        let canister_id1 = test.create_canister(Cycles::new(1_000_000_000_000));
        let canister_state = test.canister_state_mut(canister_id1);
        assert!(canister_state.execution_state.is_none());
        canister_state.execution_state = Some(ExecutionState::new(
            PathBuf::new(),
            WasmBinary::new(CanisterModule::new(b"invalid wasm".to_vec())),
            ExportedFunctions::new(
                vec![WasmMethod::Update("go".to_string())]
                    .into_iter()
                    .collect(),
            ),
            Memory::new_for_testing(),
            Memory::new_for_testing(),
            Vec::new(),
            WasmMetadata::default(),
        ));
        let canister_id2 = test.create_canister(Cycles::new(1_000_000_000_000));
        let canister_state = test.canister_state_mut(canister_id2);
        assert!(canister_state.execution_state.is_none());
        canister_state.execution_state = Some(ExecutionState::new(
            PathBuf::new(),
            WasmBinary::new(CanisterModule::new(b"invalid wasm".to_vec())),
            ExportedFunctions::new(
                vec![WasmMethod::Update("go".to_string())]
                    .into_iter()
                    .collect(),
            ),
            Memory::new_for_testing(),
            Memory::new_for_testing(),
            Vec::new(),
            WasmMetadata::default(),
        ));

        // Execute an update on each canister.
        assert_eq!(
            test.ingress(canister_id1, "go", vec![]).unwrap_err().code(),
            ErrorCode::CanisterInvalidWasm
        );
        assert_eq!(
            test.ingress(canister_id2, "go", vec![]).unwrap_err().code(),
            ErrorCode::CanisterInvalidWasm
        );

        // Only the first update should trigger a compilation.
        let cache_lookup_metric = fetch_int_counter_vec(
            test.metrics_registry(),
            "sandboxed_execution_replica_cache_lookups",
        );
        assert_eq!(
            cache_lookup_metric,
            btreemap! {
                btreemap!{
                    "lookup_result".to_string() => "cache_miss".to_string(),
                } => 1,
                btreemap!{
                    "lookup_result".to_string() => "compilation_cache_hit_compilation_error".to_string(),
                } => 1,
            }
        );
    }

    #[test]
    fn compilation_error_shared_from_install_to_update() {
        let mut test = ExecutionTestBuilder::new().build();

        // Create a canister with invalid wasm. This can't be done through the
        // normal install because the install would be rejected.
        let canister_id1 = test.create_canister(Cycles::new(1_000_000_000_000));
        let canister_state = test.canister_state_mut(canister_id1);
        assert!(canister_state.execution_state.is_none());
        canister_state.execution_state = Some(ExecutionState::new(
            PathBuf::new(),
            WasmBinary::new(CanisterModule::new(b"\x00asm invalid wasm".to_vec())),
            ExportedFunctions::new(
                vec![WasmMethod::Update("go".to_string())]
                    .into_iter()
                    .collect(),
            ),
            Memory::new_for_testing(),
            Memory::new_for_testing(),
            Vec::new(),
            WasmMetadata::default(),
        ));
        // Install a canister with the same invalid wasm.
        assert_eq!(
            test.canister_from_binary(b"\x00asm invalid wasm".to_vec())
                .unwrap_err()
                .code(),
            ErrorCode::CanisterInvalidWasm
        );

        // Execute an update on the first canister.
        assert_eq!(
            test.ingress(canister_id1, "go", vec![]).unwrap_err().code(),
            ErrorCode::CanisterInvalidWasm
        );

        // Only the install should trigger a compilation.
        let cache_lookup_metric = fetch_int_counter_vec(
            test.metrics_registry(),
            "sandboxed_execution_replica_cache_lookups",
        );
        assert_eq!(
            cache_lookup_metric,
            btreemap! {
                btreemap!{
                    "lookup_result".to_string() => "cache_miss".to_string(),
                } => 1,
                btreemap!{
                    "lookup_result".to_string() => "compilation_cache_hit_compilation_error".to_string(),
                } => 1,
            }
        );
    }

    /// When computation of the wasm code size fails, we don't even attempt to
    /// compile the wasm in the sandbox. Even in this case the error should we
    /// stored in the compilation cache.
    #[test]
    fn compilation_error_shared_from_install_to_update_when_size_computation_fails() {
        let mut test = ExecutionTestBuilder::new().build();

        // Create a canister with invalid wasm. This can't be done through the
        // normal install because the install would be rejected.
        let canister_id1 = test.create_canister(Cycles::new(1_000_000_000_000));
        let canister_state = test.canister_state_mut(canister_id1);
        assert!(canister_state.execution_state.is_none());
        canister_state.execution_state = Some(ExecutionState::new(
            PathBuf::new(),
            // Without the '\x00asm' prefix, the check for wasm code length will fail.
            WasmBinary::new(CanisterModule::new(b"invalid wasm".to_vec())),
            ExportedFunctions::new(
                vec![WasmMethod::Update("go".to_string())]
                    .into_iter()
                    .collect(),
            ),
            Memory::new_for_testing(),
            Memory::new_for_testing(),
            Vec::new(),
            WasmMetadata::default(),
        ));
        // Install a canister with the same invalid wasm.
        assert_eq!(
            test.canister_from_binary(b"invalid wasm".to_vec())
                .unwrap_err()
                .code(),
            ErrorCode::CanisterInvalidWasm
        );

        // Execute an update on the first canister.
        assert_eq!(
            test.ingress(canister_id1, "go", vec![]).unwrap_err().code(),
            ErrorCode::CanisterInvalidWasm
        );

        // Only the install should trigger a compilation.
        let cache_lookup_metric = fetch_int_counter_vec(
            test.metrics_registry(),
            "sandboxed_execution_replica_cache_lookups",
        );
        assert_eq!(
            cache_lookup_metric,
            btreemap! {
                btreemap!{
                    "lookup_result".to_string() => "compilation_cache_hit_compilation_error".to_string(),
                } => 1,
            }
        );
    }
}

mod state_machine_tests {
    //! The `execution_tests` need to mock clearing of the
    //! `expected_compiled_wasms` set at checkpoints. These tests are running a
    //! full scheduler so they exercise the actual checkpoint logic.

    use crate::CompilationCostHandling;
    use ic_state_machine_tests::StateMachine;
    use ic_test_utilities_execution_environment::wat_compilation_cost;

    /// A canister with an update and a query method.
    const TEST_CANISTER: &str = r#"
            (module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $write (call $msg_reply))
              (func $read (call $msg_reply))

              (export "canister_query read" (func $read))
              (export "canister_update write" (func $write))
			)"#;

    #[test]
    fn compilation_cost_ignored_from_install_to_install() {
        let env = StateMachine::new();

        let expected_compilation_instructions = wat_compilation_cost(TEST_CANISTER);

        // Installing first canister takes some instructions.
        let _canister_id1 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        assert_eq!(
            env.subnet_message_instructions(),
            expected_compilation_instructions.get() as f64,
        );

        // Installing another canister with the same Wasm doesn't take instructions.
        let _canister_id2 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        assert_eq!(
            env.subnet_message_instructions(),
            expected_compilation_instructions.get() as f64
                + CompilationCostHandling::CountReducedAmount
                    .adjusted_compilation_cost(expected_compilation_instructions)
                    .get() as f64
        );
    }

    #[test]
    fn compilation_cost_charged_after_checkpoint_between_installs() {
        let env = StateMachine::new();
        // Enabling checkpoints causes a checkpoint round on each installation.
        env.set_checkpoints_enabled(true);

        let expected_compilation_instructions = wat_compilation_cost(TEST_CANISTER).get() as f64;

        // Installing first canister takes some instructions.
        let _canister_id1 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        assert_eq!(
            env.subnet_message_instructions(),
            expected_compilation_instructions,
        );

        // Installing another canister with the same Wasm uses instructions because
        // there was a checkpoint since the last install.
        let _canister_id2 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        assert_eq!(
            env.subnet_message_instructions(),
            2.0 * expected_compilation_instructions,
        );
    }
}
