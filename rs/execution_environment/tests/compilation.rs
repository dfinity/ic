mod execution_tests {
    use std::path::PathBuf;

    use ic_config::{embedders::Config as EmbeddersConfig, flag_status::FlagStatus};
    use ic_error_types::ErrorCode;
    use ic_execution_environment::CompilationCostHandling;
    use ic_replicated_state::{
        canister_state::execution_state::{WasmBinary, WasmMetadata},
        ExecutionState, ExportedFunctions, Memory,
    };
    use ic_state_machine_tests::Cycles;
    use ic_test_utilities::execution_environment::{wat_compilation_cost, ExecutionTestBuilder};
    use ic_test_utilities_metrics::{fetch_histogram_stats, fetch_int_counter_vec};
    use ic_types::methods::WasmMethod;
    use ic_wasm_types::CanisterModule;
    use maplit::btreemap;

    const WAT_EMPTY: &str = "(module)";
    const WAT_WITH_GO: &str = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func $go (call $msg_reply))
            (export "canister_update go" (func $go))
        )"#;

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
        match EmbeddersConfig::default().feature_flags.module_sharing {
            FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 2),
            FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 3),
        }
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
        match EmbeddersConfig::default().feature_flags.module_sharing {
            FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 2),
            FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 4),
        }
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
        match EmbeddersConfig::default().feature_flags.module_sharing {
            FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 1),
            FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 2),
        }
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
        match EmbeddersConfig::default().feature_flags.module_sharing {
            FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 2),
            FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 3),
        }
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

        // Only the first install should have cost instructions.
        assert_eq!(
            test.canister_executed_instructions(canister_id1),
            wat_compilation_cost(WAT_EMPTY)
        );
        let compilation_cost_handling =
            match EmbeddersConfig::default().feature_flags.module_sharing {
                FlagStatus::Enabled => CompilationCostHandling::CountReducedAmount,
                FlagStatus::Disabled => CompilationCostHandling::CountFullAmount,
            };
        assert_eq!(
            test.canister_executed_instructions(canister_id2),
            compilation_cost_handling.adjusted_compilation_cost(wat_compilation_cost(WAT_EMPTY))
        );
        // Even though we didn't need to recompile, the canister should still be
        // charged for it.
        assert_eq!(
            test.canister_state(canister_id2).system_state.balance(),
            initial_balance
                - test
                    .cycles_account_manager()
                    .execution_cost(wat_compilation_cost(WAT_EMPTY), test.subnet_size())
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
        let canister_id2 = test.canister_from_wat(WAT_EMPTY).unwrap();

        assert_eq!(
            test.canister_executed_instructions(canister_id1),
            wat_compilation_cost(WAT_EMPTY)
        );
        assert_eq!(
            test.canister_executed_instructions(canister_id2),
            wat_compilation_cost(WAT_EMPTY)
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
            Memory::default(),
            Memory::default(),
            Vec::new(),
            WasmMetadata::default(),
        ));

        // Call the same method on the canister twice.
        assert_eq!(
            test.ingress(canister_id, "go", vec![]).unwrap_err().code(),
            ErrorCode::CanisterInvalidWasm
        );
        assert_eq!(
            test.ingress(canister_id, "go", vec![]).unwrap_err().code(),
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
                    "lookup_result".to_string() => "embedder_cache_hit_compilation_error".to_string(),
                } => 1,
            }
        );
    }
}

mod state_machine_tests {
    //! The `execution_tests` need to mock clearing of the
    //! `expected_compiled_wasms` set at checkpoints. These tests are running a
    //! full scheduler so they exercise the actual checkpoint logic.

    use ic_config::{embedders::Config as EmbeddersConfig, flag_status::FlagStatus};
    use ic_execution_environment::CompilationCostHandling;
    use ic_state_machine_tests::StateMachine;
    use ic_test_utilities::execution_environment::wat_compilation_cost;

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

        // Installing another canister with the same WASM doesn't take instructions.
        let _canister_id2 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        let compilation_cost_handling =
            match EmbeddersConfig::default().feature_flags.module_sharing {
                FlagStatus::Enabled => CompilationCostHandling::CountReducedAmount,
                FlagStatus::Disabled => CompilationCostHandling::CountFullAmount,
            };
        assert_eq!(
            env.subnet_message_instructions(),
            match EmbeddersConfig::default().feature_flags.module_sharing {
                FlagStatus::Enabled =>
                    expected_compilation_instructions.get() as f64
                        + compilation_cost_handling
                            .adjusted_compilation_cost(expected_compilation_instructions)
                            .get() as f64,
                FlagStatus::Disabled => 2.0 * (expected_compilation_instructions.get() as f64),
            }
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

        // Installing another canister with the same WASM uses instructions because
        // there was a checkpoint since the last install.
        let _canister_id2 = env.install_canister_wat(TEST_CANISTER, vec![], None);
        assert_eq!(
            env.subnet_message_instructions(),
            2.0 * expected_compilation_instructions,
        );
    }
}
