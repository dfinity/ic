#[macro_export]
macro_rules! embedders_tests {
    ( $TestEmbedder:path ) => {
        use ic_replicated_state::{Global, NumWasmPages};
        use ic_test_utilities::{
            cycles_account_manager::CyclesAccountManagerBuilder,
            state::SystemStateBuilder, types::ids::user_test_id, with_test_replica_logger, mock_time,
            system_api::dummy_pause_handler,
        };
        use ic_types::{methods::{FuncRef,WasmMethod}, NumInstructions, NumBytes};
        use ic_wasm_types::BinaryEncodedWasm;
        use ic_config::embedders::{PersistenceType};
        use ic_interfaces::execution_environment::SubnetAvailableMemory;
        use lazy_static::lazy_static;
        use std::sync::Arc;

        use $TestEmbedder as TestEmbedder;

        fn wat2wasm(wat: &str) -> Result<BinaryEncodedWasm, wabt::Error> {
            wabt::wat2wasm(wat).map(BinaryEncodedWasm::new)
        }

        use ic_embedders::Embedder;

        lazy_static! {
            static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
                SubnetAvailableMemory::new(NumBytes::new(std::u64::MAX));
        }

        #[test]
        // takes a Wasm with two mutable globals and checks whether we can set and get
        // their values.
        fn can_set_and_get_global() {
            with_test_replica_logger(|log| {
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
                let embedder = TestEmbedder::new(ic_config::embedders::Config::default(), log);
                let mut inst = embedder.new_instance(
                    &embedder.compile(PersistenceType::Sigsegv,wasm).unwrap(),
                    &[],
                    NumWasmPages::from(0),
                    None,
                    None,
                );

                let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
                let system_state = SystemStateBuilder::default().build();
                let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(system_state, Arc::clone(&cycles_account_manager));
                // Initial read, the globals should have a value of 0 and 42 respectively.
                let res = inst
                    .run(
                        &mut ic_system_api::SystemApiImpl::new(
                            ic_system_api::ApiType::init(
                                mock_time(),
                                vec![],
                                user_test_id(24).get(),
                            ),
                            system_state_accessor,
                            NumInstructions::from(1),
                            NumBytes::from(4 << 30),
                            NumBytes::from(0),
                            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                            ComputeAllocation::default(),
                            dummy_pause_handler(),
                        ),
                        FuncRef::Method(WasmMethod::Update("test".to_string())),
                    )
                    .unwrap();
                assert_eq!(
                    res.exported_globals[..],
                    [
                        Global::I64(0),
                        Global::I32(42)
                    ]
                );

                // Change the value of globals and verify we can get them back.
                let mut inst = embedder.new_instance(
                    &embedder.compile(PersistenceType::Sigsegv,wasm).unwrap(),
                    &[
                        Global::I64(5),
                        Global::I32(12),
                    ],
                    NumWasmPages::from(0),
                    None,
                    None,
                );
                let system_state = SystemStateBuilder::default().build();
                let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(system_state, cycles_account_manager);
                let res = inst
                    .run(
                        &mut ic_system_api::SystemApiImpl::new(
                            ic_system_api::ApiType::init(
                                mock_time(),
                                vec![],
                                user_test_id(24).get(),
                            ),
                            system_state_accessor,
                            NumInstructions::from(1),
                            NumBytes::from(4 << 30),
                            NumBytes::from(0),
                            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                            ComputeAllocation::default(),
                            dummy_pause_handler(),
                        ),
                        FuncRef::Method(WasmMethod::Update("test".to_string())),
                    )
                    .unwrap();
                assert_eq!(
                    res.exported_globals[..],
                    [
                        Global::I64(5),
                        Global::I32(12)
                    ]
                );
            });
        }

        #[test]
        // Takes a Wasm with two mutable float globals and checks whether we can set and
        // get their values.
        fn can_set_and_get_float_globals() {
            with_test_replica_logger(|log| {
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
                let embedder = TestEmbedder::new(ic_config::embedders::Config::default(), log);
                let mut inst = embedder.new_instance(
                    &embedder.compile(PersistenceType::Sigsegv,wasm).unwrap(),
                    &[],
                    NumWasmPages::from(0),
                    None,
                    None,
                );

                let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
                let system_state = SystemStateBuilder::default().build();
                let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(system_state, Arc::clone(&cycles_account_manager));
                // Initial read, the globals should have a value of 0.0 and 42.42 respectively.
                let res = inst
                    .run(
                        &mut ic_system_api::SystemApiImpl::new(
                            ic_system_api::ApiType::init(
                                mock_time(),
                                vec![],
                                user_test_id(24).get(),
                            ),
                            system_state_accessor,
                            NumInstructions::from(1),
                            NumBytes::from(4 << 30),
                            NumBytes::from(0),
                            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                            ComputeAllocation::default(),
                            dummy_pause_handler(),
                        ),
                        FuncRef::Method(WasmMethod::Update("test".to_string())),
                    )
                    .unwrap();
                assert_eq!(
                    res.exported_globals[..],
                    [
                        Global::F64(0.0),
                        Global::F32(42.42)
                    ]
                );

                // Change the value of globals and verify we can get them back.
                let mut inst = embedder.new_instance(
                    &embedder.compile(PersistenceType::Sigsegv,wasm).unwrap(),
                    &[
                        Global::F64(5.3),
                        Global::F32(12.37),
                    ],
                    NumWasmPages::from(0),
                    None,
                    None,
                );
                let system_state = SystemStateBuilder::default().build();
                let system_state_accessor = ic_system_api::SystemStateAccessorDirect::new(system_state, cycles_account_manager);
                let res = inst
                    .run(
                        &mut ic_system_api::SystemApiImpl::new(
                            ic_system_api::ApiType::init(
                                mock_time(),
                                vec![],
                                user_test_id(24).get(),
                            ),
                            system_state_accessor,
                            NumInstructions::from(1),
                            NumBytes::from(4 << 30),
                            NumBytes::from(0),
                            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                            ComputeAllocation::default(),
                            dummy_pause_handler(),
                        ),
                        FuncRef::Method(WasmMethod::Update("test".to_string())),
                    )
                    .unwrap();
                assert_eq!(
                    res.exported_globals[..],
                    [
                        Global::F64(5.3),
                        Global::F32(12.37)
                    ]
                );
            });
        }

        #[test]
        #[should_panic(expected = "global of type I32 cannot be set to I64")]
        fn try_to_set_globals_with_wrong_types() {
            with_test_replica_logger(|log| {
                let wasm = &wat2wasm(
                    r#"
                    (module
                      (global (export "g1") (mut i64) (i64.const 0))
                      (global (export "g2") (mut i32) (i32.const 42))
                    )"#,
                )
                .unwrap();
                let embedder = TestEmbedder::new(ic_config::embedders::Config::default(), log);
                // Should fail because of not correct type of the second one.
                embedder.new_instance(
                    &embedder.compile(PersistenceType::Sigsegv,wasm).unwrap(),
                    &[
                        Global::I64(5),
                        Global::I64(12),
                    ],
                    NumWasmPages::from(0),
                    None,
                    None,
                );
            });
        }

        #[test]
        #[should_panic(expected = "Given exported globals length 513 is more than instance exported globals length 1")]
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

            with_test_replica_logger(|log| {
                let embedder = TestEmbedder::new(ic_config::embedders::Config::default(), log);
                // Should fail because we are passing in a slice that is longer than the default
                // instance globals length for Lucet.
                embedder.new_instance(
                    &embedder.compile(PersistenceType::Sigsegv,wasm).unwrap(),
                    &[Global::I64(0); DEFAULT_GLOBALS_LENGTH + 1]
                        .iter()
                        .cloned()
                        .collect::<Vec<Global>>(),
                    NumWasmPages::from(0),
                    None,
                    None,
                );
            });
        }
    };
}
