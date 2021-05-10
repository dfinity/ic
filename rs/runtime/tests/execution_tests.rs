#[cfg(test)]
pub mod tests {
    use ic_config::embedders::{Config, EmbedderType};
    use ic_embedders::*;
    use ic_interfaces::execution_environment::{
        EarlyResult, ExecResult, ExecResultVariant, SubnetAvailableMemory,
    };
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{ExecutionState, Global};
    use ic_system_api::ApiType;
    use ic_test_utilities::{
        cycles_account_manager::CyclesAccountManagerBuilder,
        mock_time,
        state::SystemStateBuilder,
        types::ids::{call_context_test_id, subnet_test_id, user_test_id},
    };
    use ic_types::{
        methods::{FuncRef, WasmMethod},
        CanisterId, ComputeAllocation, Cycles, NumBytes, NumInstructions,
    };
    use ic_wasm_utils::validation::WasmValidationLimits;
    use lazy_static::lazy_static;
    use maplit::btreemap;
    use runtime::*;
    use std::{sync::Arc, time::Duration};

    lazy_static! {
        static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
            SubnetAvailableMemory::new(NumBytes::new(std::u64::MAX));
    }

    fn exec_state(wast: &str) -> ExecutionState {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let wasm_binary = wabt::wat2wasm(wast).unwrap();
        ExecutionState::new(
            wasm_binary,
            tmpdir.path().into(),
            WasmValidationLimits::default(),
        )
        .unwrap()
    }

    fn dummy_api() -> ApiType {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let routing_table = Arc::new(RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
        }));
        let subnet_records = Arc::new(btreemap! {
            subnet_id => subnet_type,
        });
        ApiType::update(
            mock_time(),
            vec![],
            Cycles::from(0),
            user_test_id(24).get(),
            call_context_test_id(13),
            subnet_id,
            subnet_type,
            routing_table,
            subnet_records,
        )
    }

    fn dummy_input(
        execution_state: ExecutionState,
        fun: &str,
        num_instructions: NumInstructions,
    ) -> WasmExecutionInput {
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        WasmExecutionInput {
            api_type: dummy_api(),
            system_state: SystemStateBuilder::default().build(),
            instructions_limit: num_instructions,
            canister_memory_limit: NumBytes::from(4 << 30),
            canister_current_memory_usage: NumBytes::from(0),
            subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            compute_allocation: ComputeAllocation::default(),
            func_ref: FuncRef::Method(WasmMethod::Update(fun.to_string())),
            execution_state,
            cycles_account_manager,
        }
    }

    const COUNTER_WAST: &str = r#"
                (module
                  (func $bump
                    global.get 0
                    i32.const 1
                    i32.add
                    global.set 0
                  )
                  (export "canister_update bump" (func $bump))
                  (global (export "g") (mut i32) (i32.const 234))
                )
            "#;

    pub fn can_top_up_num_instructions_test(embedder_type: EmbedderType) {
        let log = ic_logger::replica_logger::no_op_logger();
        let dispatcher = WasmExecutionDispatcher::new(embedder_type, Config::default(), log);

        // First check how many instructions get eaten
        let start_num_instructions = 1000;
        let consumed_num_instructions;
        let input = dummy_input(
            exec_state(COUNTER_WAST),
            "bump",
            NumInstructions::from(start_num_instructions),
        );
        let exec_state = if let ExecutionResult::WasmExecutionOutput(output) =
            dispatcher.execute(input).get()
        {
            assert!(output.wasm_result.is_ok());
            consumed_num_instructions = start_num_instructions - output.num_instructions_left.get();
            output.execution_state
        } else {
            panic!("Should have finished");
        };

        // Now give it not enough instructions and to up after pause
        let input = dummy_input(
            exec_state,
            "bump",
            NumInstructions::from(consumed_num_instructions - 1),
        );
        let result_after_resume =
            if let ExecutionResult::ResumeToken(rt) = dispatcher.execute(input).get() {
                rt.resume(NumInstructions::from(1000)).get()
            } else {
                panic!("Should have paused");
            };

        if let ExecutionResult::WasmExecutionOutput(output) = result_after_resume {
            assert!(output.wasm_result.is_ok());
            assert_eq!(output.execution_state.exported_globals[0], Global::I32(236));
            assert_eq!(output.num_instructions_left.get(), 1000 - 1);
        } else {
            panic!("Should have finished");
        }
    }

    pub fn interleaved_computation_test(embedder_type: EmbedderType) {
        let log = ic_logger::replica_logger::no_op_logger();
        let mut config = Config::default();
        config.num_runtime_generic_threads = 2; //make sure we have at least two workers
        let dispatcher = WasmExecutionDispatcher::new(embedder_type, config, log);

        let input_a = dummy_input(exec_state(COUNTER_WAST), "bump", NumInstructions::from(1));
        let input_b = dummy_input(exec_state(COUNTER_WAST), "bump", NumInstructions::from(100));

        let resume_token_a = match dispatcher.execute(input_a).get() {
            ExecutionResult::ResumeToken(rt) => rt,
            _ => panic!("Should have paused"),
        };

        match dispatcher.execute(input_b).get() {
            ExecutionResult::WasmExecutionOutput(output) => {
                assert!(output.wasm_result.is_ok());
                assert_eq!(output.execution_state.exported_globals[0], Global::I32(235));
            }
            _ => panic!("Should have finished"),
        };

        match resume_token_a.resume(NumInstructions::from(1000)).get() {
            ExecutionResult::WasmExecutionOutput(output) => {
                assert!(output.wasm_result.is_ok());
                assert_eq!(output.execution_state.exported_globals[0], Global::I32(235));
            }
            _ => panic!("Should have finished"),
        }
    }

    fn run_twice(
        embedder_type: EmbedderType,
        wast: &str,
        fn_name: &str,
    ) -> (Duration, NumInstructions, Duration, NumInstructions) {
        let log = ic_logger::replica_logger::no_op_logger();
        let dispatcher = WasmExecutionDispatcher::new(embedder_type, Config::default(), log);

        let num_instructions = NumInstructions::from(1000000);
        let start_time = std::time::Instant::now();
        let input = dummy_input(exec_state(&wast), fn_name, num_instructions);

        let num_instructions_consumed_1;
        let num_instructions_consumed_2;

        let exec_state =
            if let ExecutionResult::WasmExecutionOutput(output) = dispatcher.execute(input).get() {
                assert!(output.wasm_result.is_ok());
                assert_eq!(output.execution_state.exported_globals[0], Global::I32(235));
                num_instructions_consumed_1 = num_instructions - output.num_instructions_left;
                output.execution_state
            } else {
                panic!("Should have finished");
            };

        let duration_1 = start_time.elapsed();
        let start_time = std::time::Instant::now();

        let input = dummy_input(exec_state, fn_name, NumInstructions::from(1000000));
        let _exec_state =
            if let ExecutionResult::WasmExecutionOutput(output) = dispatcher.execute(input).get() {
                assert!(output.wasm_result.is_ok());
                assert_eq!(output.execution_state.exported_globals[0], Global::I32(236));
                num_instructions_consumed_2 = num_instructions - output.num_instructions_left;
                output.execution_state
            } else {
                panic!("Should have finished");
            };
        let duration_2 = start_time.elapsed();
        (
            duration_1,
            num_instructions_consumed_1,
            duration_2,
            num_instructions_consumed_2,
        )
    }

    // This test is not intended for CI
    // It allows to investigate compilation and execution times of potential
    // compiler bombs
    pub fn many_globals_test(embedder_type: EmbedderType) {
        fn glob_export(i: u64) -> String {
            format!(
                "
                 (global (export \"g{}\") (mut i32) (i32.const 234))",
                i
            )
        }

        fn func_export(i: u64, add: u64) -> String {
            let fn_name = format!("bump_{}_{}", i, add);
            format!(
                "
                 (func ${}
                    global.get {}
                    i32.const {}
                    i32.add
                    global.set {}
                 )
                 (export \"canister_update {}\" (func ${}))
                ",
                fn_name, i, add, i, fn_name, fn_name
            )
        }

        fn generate_wast(glob_count: u64, func_count: u64) -> String {
            let mut wast: String = r#"
            (module
            "#
            .to_string();

            for i in 0..func_count {
                wast.push_str(&func_export(0, i));
            }
            for i in 0..glob_count {
                wast.push_str(&glob_export(i));
            }

            wast.push_str(
                r#"
            )"#,
            );
            wast
        }

        let wast = generate_wast(10000, 10);

        let (d1, g1, d2, g2) = run_twice(embedder_type, &wast, "bump_0_1");

        println!("First run time:  {}", d1.as_millis());
        println!("First run cycles consumed:  {}", g1);
        println!("Second run time: {}", d2.as_millis());
        println!("Second run cycles consumed: {}", g2);
    }

    pub fn many_args_test(embedder_type: EmbedderType) {
        fn func_export(arg_count: u64, local_count: u64, add_idx: u64) -> String {
            let fn_name = format!("bump_{}", add_idx);
            let mut res = format!(
                "
                 (func ${} ",
                fn_name
            );
            for _i in 0..arg_count {
                res.push_str(" (param i32)");
            }

            for _i in 0..local_count {
                res.push_str(" (local i32)");
            }

            res.push_str(&format!(
                "
                    global.get 0
                    local.get {}
                    i32.add
                    global.set 0
                 )
                ",
                add_idx
            ));
            res
        }

        fn generate_wast(arg_count: u64, local_count: u64) -> String {
            let mut wast: String = r#"
            (module
            "#
            .to_string();

            wast.push_str(&func_export(arg_count, local_count, 0));

            wast.push_str(
                r#"
                (func $bump
                    (call $bump_0"#,
            );

            for _i in 0..arg_count {
                wast.push_str(" (i32.const 1)");
            }

            wast.push_str(
                r#"))
                (export "canister_update bump" (func $bump))
                (global (export "g") (mut i32) (i32.const 234))
            )"#,
            );
            wast
        }

        let wast = generate_wast(1000, 1);
        let (d1, g1, d2, g2) = run_twice(embedder_type, &wast, "bump");

        println!("First run time:  {}", d1.as_millis());
        println!("First run cycles consumed:  {}", g1);
        println!("Second run time: {}", d2.as_millis());
        println!("Second run cycles consumed: {}", g2);
    }

    #[allow(dead_code)]
    pub fn select_smoke_test(embedder_type: EmbedderType) {
        let log = ic_logger::replica_logger::no_op_logger();
        let mut config = Config::default();
        config.num_runtime_generic_threads = 2;
        let dispatcher = WasmExecutionDispatcher::new(embedder_type, Config::default(), log);

        let start_cycles = 10000;

        let input1 = dummy_input(
            exec_state(COUNTER_WAST),
            "bump",
            NumInstructions::from(start_cycles),
        );
        let input2 = dummy_input(
            exec_state(COUNTER_WAST),
            "bump",
            NumInstructions::from(start_cycles),
        );
        let input3 = dummy_input(
            exec_state(COUNTER_WAST),
            "bump",
            NumInstructions::from(start_cycles),
        );

        let res1 = ExecResult::new(Box::new(dispatcher.execute(input1)));
        let res2 = ExecResult::new(Box::new(dispatcher.execute(input2)));
        let res3 = ExecResult::new(Box::new(dispatcher.execute(input3)));

        let res1 = res1.and_then(|output| {
            assert!(output.wasm_result.is_ok());
            assert_eq!(output.execution_state.exported_globals[0], Global::I32(235));
            1
        });

        let res2 = res2.and_then(|output| {
            assert!(output.wasm_result.is_ok());
            assert_eq!(output.execution_state.exported_globals[0], Global::I32(235));
            10
        });

        let res3 = res3.and_then(|output| {
            assert!(output.wasm_result.is_ok());
            assert_eq!(output.execution_state.exported_globals[0], Global::I32(235));
            100
        });

        let mut sel = ExecSelect::new(vec![res1, res2, res3]);

        let mut sum = 0;
        let res_a = sel.select();
        let res_b = sel.select();
        let res_c = sel.select();

        assert!(res_a.is_some());
        match res_a.unwrap() {
            ExecResultVariant::Completed(x) => sum += x,
            ExecResultVariant::Interrupted(_) => panic!("Didn't expect pause here"),
        }

        assert!(res_b.is_some());
        match res_b.unwrap() {
            ExecResultVariant::Completed(x) => sum += x,
            ExecResultVariant::Interrupted(_) => panic!("Didn't expect pause here"),
        }

        assert!(res_c.is_some());
        match res_c.unwrap() {
            ExecResultVariant::Completed(x) => sum += x,
            ExecResultVariant::Interrupted(_) => panic!("Didn't expect pause here"),
        }

        assert_eq!(sum, 111, "Not all results returned correctly");
    }

    #[allow(dead_code)]
    pub fn select_test(embedder_type: EmbedderType) {
        let log = ic_logger::replica_logger::no_op_logger();
        let mut config = Config::default();
        config.num_runtime_generic_threads = 2;
        let dispatcher = WasmExecutionDispatcher::new(embedder_type, Config::default(), log);

        let num_jobs = 50;
        let num_pause_jobs = 20;
        let num_early_results = 10;

        let mut inputs = Vec::new();

        for _ in 0..num_jobs {
            inputs.push(dummy_input(
                exec_state(COUNTER_WAST),
                "bump",
                NumInstructions::from(100000),
            ));
        }

        for _ in 0..num_pause_jobs {
            inputs.push(dummy_input(
                exec_state(COUNTER_WAST),
                "bump",
                NumInstructions::from(1),
            ));
        }

        let mut results: Vec<_> = inputs
            .into_iter()
            .map(|input| {
                ExecResult::new(Box::new(dispatcher.execute(input)))
                    .and_then(|output| {
                        assert!(output.wasm_result.is_ok());
                        assert_eq!(output.execution_state.exported_globals[0], Global::I32(235));
                        1
                    })
                    .and_then(|idx| -idx)
            })
            .collect();

        for _ in 0..num_early_results {
            results.push(EarlyResult::new(10).and_then(|x| x as i64 - 11));
        }

        let mut sel = ExecSelect::new(results);

        let mut sum = 0;
        let mut num_paused = 0;

        while let Some(res) = sel.select() {
            match res {
                ExecResultVariant::Completed(x) => sum += x,
                ExecResultVariant::Interrupted(rt) => {
                    num_paused += 1;
                    sum += rt.resume(NumInstructions::from(100000)).get_no_pause();
                }
            }
        }

        assert_eq!(
            sum,
            -(num_jobs + num_pause_jobs + num_early_results),
            "Not all results returned correctly"
        );
        assert_eq!(num_paused, num_pause_jobs, "Paused job count doesn't match");
    }
}
