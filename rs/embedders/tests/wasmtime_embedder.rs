use ic_config::embedders::PersistenceType;
use ic_embedders::{
    wasm_utils::instrumentation::{instrument, InstructionCostTable},
    WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::{ExecutionParameters, SubnetAvailableMemory};
use ic_replicated_state::{Global, NumWasmPages};
use ic_system_api::SystemStateAccessor;
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, mock_time, state::SystemStateBuilder,
    types::ids::user_test_id,
};
use ic_types::{
    methods::{FuncRef, WasmMethod},
    ComputeAllocation, NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;
use std::sync::Arc;

fn execution_parameters() -> ExecutionParameters {
    ExecutionParameters {
        instruction_limit: NumInstructions::new(5_000_000_000),
        canister_memory_limit: ic_types::NumBytes::from(4 << 30),
        subnet_available_memory: SubnetAvailableMemory::new(i64::MAX / 2),
        compute_allocation: ComputeAllocation::default(),
    }
}

#[cfg(test)]
mod tests {
    use ic_replicated_state::Memory;
    use ic_test_utilities::types::ids::canister_test_id;
    use memory_tracker::DirtyPageTracking;

    use super::*;

    fn logger() -> ic_logger::ReplicaLogger {
        use slog::Drain;

        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(drain, slog::o!()).into()
    }

    fn wat2wasm(wat: &str) -> Result<BinaryEncodedWasm, wabt::Error> {
        wabt::wat2wasm(wat).map(BinaryEncodedWasm::new)
    }

    /// Ensures that attempts to execute messages on wasm modules that do not
    /// define memory fails.
    #[test]
    fn cannot_execute_wasm_without_memory() {
        let log = logger();
        let wasm = wabt::wat2wasm(
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
        .expect("wat");

        let embedder = WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log.clone());
        let output =
            instrument(&BinaryEncodedWasm::new(wasm), &InstructionCostTable::new()).unwrap();

        let compiled = embedder
            .compile(PersistenceType::Sigsegv, &output.binary)
            .expect("compiled");

        let user_id = ic_test_utilities::types::ids::user_test_id(24);

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let system_state = ic_test_utilities::state::SystemStateBuilder::default().build();
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            cycles_account_manager,
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(ic_test_utilities::mock_time(), vec![], user_id.get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log,
        );

        let mut instance = embedder
            .new_instance(
                canister_test_id(1),
                &compiled,
                &[],
                ic_replicated_state::NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
        // Note: system API calls get charged per call, see system_api::charges
        instance.set_num_instructions(NumInstructions::new(1000));

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
    fn stack_overflow_traps() {
        let log = logger();
        let wasm = wabt::wat2wasm(
            r#"
          (module
            (func $f (export "canister_update f") (result i64)
              ;; define a large number of local variables to quickly overflow the stack
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
        .expect("wat");

        let embedder = WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log.clone());

        let compiled = embedder
            .compile(
                PersistenceType::Sigsegv,
                &ic_wasm_types::BinaryEncodedWasm::new(wasm),
            )
            .expect("compiled");

        let user_id = ic_test_utilities::types::ids::user_test_id(24);

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let system_state = ic_test_utilities::state::SystemStateBuilder::default().build();
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            cycles_account_manager,
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(ic_test_utilities::mock_time(), vec![], user_id.get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log,
        );

        let mut instance = embedder
            .new_instance(
                canister_test_id(1),
                &compiled,
                &[],
                ic_replicated_state::NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");

        let result = instance.run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::Update("f".to_string()),
        ));

        match result {
            Ok(_) => panic!("Expected a HypervisorError::Trapped"),
            Err(err) => {
                assert_eq!(
                    err,
                    ic_interfaces::execution_environment::HypervisorError::Trapped(
                        ic_interfaces::execution_environment::TrapCode::StackOverflow
                    )
                );
            }
        }
    }

    #[test]
    // takes a Wasm with two mutable globals and checks whether we can set and get
    // their values.
    fn can_set_and_get_global() {
        let log = logger();
        let wasm = &wat2wasm(
            r#"
                    (module
                      ;; global 0, visible
                      (global (export "g1") (mut i64) (i64.const 0))
                      ;; global 1, not visible
                      (global (mut i64) (i64.const 1))
                      ;; global 2, not visible
                      (global i64 (i64.const 2))
                      ;; global 3, visible
                      (global (export "g2") (mut i32) (i32.const 42))
                      (func (export "canister_update test"))
                    )"#,
        )
        .unwrap();
        let embedder = WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log.clone());
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());

        let system_state = SystemStateBuilder::default().build();
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            Arc::clone(&cycles_account_manager),
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(mock_time(), vec![], user_test_id(24).get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log.clone(),
        );
        let mut inst = embedder
            .new_instance(
                canister_test_id(1),
                &embedder.compile(PersistenceType::Sigsegv, wasm).unwrap(),
                &[],
                NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");

        // Initial read, the globals should have a value of 0 and 42 respectively.
        let res = inst
            .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
            .unwrap();
        assert_eq!(res.exported_globals[..], [Global::I64(0), Global::I32(42)]);

        // Change the value of globals and verify we can get them back.
        let system_state = SystemStateBuilder::default().build();
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            cycles_account_manager,
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(mock_time(), vec![], user_test_id(24).get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log,
        );

        let mut inst = embedder
            .new_instance(
                canister_test_id(1),
                &embedder.compile(PersistenceType::Sigsegv, wasm).unwrap(),
                &[Global::I64(5), Global::I32(12)],
                NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
        let res = inst
            .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
            .unwrap();
        assert_eq!(res.exported_globals[..], [Global::I64(5), Global::I32(12)]);
    }

    #[test]
    // Takes a Wasm with two mutable float globals and checks whether we can set and
    // get their values.
    fn can_set_and_get_float_globals() {
        let log = logger();
        let wasm = &wat2wasm(
            r#"
                    (module
                        (import "ic0" "msg_reply" (func $msg_reply))
                        (func $test
                            (call $msg_reply)
                        )
                        (global (export "g1") (mut f64) (f64.const 0.0))
                        (global (export "g2") (mut f32) (f32.const 42.42))
                        (func (export "canister_update test"))
                    )"#,
        )
        .unwrap();
        let embedder = WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log.clone());
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let system_state = SystemStateBuilder::default().build();
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            Arc::clone(&cycles_account_manager),
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(mock_time(), vec![], user_test_id(24).get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log.clone(),
        );
        let mut inst = embedder
            .new_instance(
                canister_test_id(1),
                &embedder.compile(PersistenceType::Sigsegv, wasm).unwrap(),
                &[],
                NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");

        // Initial read, the globals should have a value of 0.0 and 42.42 respectively.
        let res = inst
            .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
            .unwrap();
        assert_eq!(
            res.exported_globals[..],
            [Global::F64(0.0), Global::F32(42.42)]
        );

        // Change the value of globals and verify we can get them back.
        let system_state = SystemStateBuilder::default().build();
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            cycles_account_manager,
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(mock_time(), vec![], user_test_id(24).get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log,
        );
        let mut inst = embedder
            .new_instance(
                canister_test_id(1),
                &embedder.compile(PersistenceType::Sigsegv, wasm).unwrap(),
                &[Global::F64(5.3), Global::F32(12.37)],
                NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
        let res = inst
            .run(FuncRef::Method(WasmMethod::Update("test".to_string())))
            .unwrap();
        assert_eq!(
            res.exported_globals[..],
            [Global::F64(5.3), Global::F32(12.37)]
        );
    }

    #[test]
    #[should_panic(expected = "global of type I32 cannot be set to I64")]
    fn try_to_set_globals_with_wrong_types() {
        let log = logger();
        let wasm = &wat2wasm(
            r#"
                    (module
                      (global (export "g1") (mut i64) (i64.const 0))
                      (global (export "g2") (mut i32) (i32.const 42))
                    )"#,
        )
        .unwrap();
        let system_state = SystemStateBuilder::default().build();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            cycles_account_manager,
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(mock_time(), vec![], user_test_id(24).get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log.clone(),
        );
        let embedder = WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log);
        // Should fail because of not correct type of the second one.
        embedder
            .new_instance(
                canister_test_id(1),
                &embedder.compile(PersistenceType::Sigsegv, wasm).unwrap(),
                &[Global::I64(5), Global::I64(12)],
                NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
    }

    #[test]
    #[should_panic(
        expected = "Given exported globals length 513 is more than instance exported globals length 1"
    )]
    fn try_to_set_globals_that_are_more_than_the_instace_globals() {
        // Globals take up a single 4K byte page and they are represented by 64 bits
        // each, so by default there are 4096 * 8 bits / 64 bits = 512 globals.
        const DEFAULT_GLOBALS_LENGTH: usize = 512;

        let wasm = &wat2wasm(
            r#"
                (module
                    (global (export "g") (mut i64) (i64.const 42))
                )"#,
        )
        .unwrap();

        let log = logger();
        let embedder = WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log.clone());
        let system_state = SystemStateBuilder::default().build();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(
            system_state,
            cycles_account_manager,
            &Memory::default(),
        );
        let api = ic_system_api::SystemApiImpl::new(
            system_state_accessor.canister_id(),
            ic_system_api::ApiType::init(mock_time(), vec![], user_test_id(24).get()),
            system_state_accessor,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            log,
        );
        embedder
            .new_instance(
                canister_test_id(1),
                &embedder.compile(PersistenceType::Sigsegv, wasm).unwrap(),
                &[Global::I64(0); DEFAULT_GLOBALS_LENGTH + 1].to_vec(),
                NumWasmPages::from(0),
                None,
                None,
                DirtyPageTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
    }
}
