use ic_config::embedders::EmbedderType;

pub mod embedder_tests;
mod execution_tests;
use execution_tests::tests as et;
use ic_types::ComputeAllocation;

embedders_tests! {ic_embedders::WasmtimeEmbedder}

#[test]
fn wasmtime_can_top_up_num_instructions_test() {
    et::can_top_up_num_instructions_test(EmbedderType::Wasmtime);
}

#[test]
fn wasmtime_interleaved_computation() {
    et::interleaved_computation_test(EmbedderType::Wasmtime);
}

#[test]
#[ignore] // ICSUP-133 meant to be tested manually and in nightly runs.
fn wasmtime_many_globals_test() {
    et::many_globals_test(EmbedderType::Wasmtime);
}

#[test]
#[ignore] // ICSUP-133 meant to be tested manually and in nightly runs.
fn wasmtime_many_args_test() {
    et::many_args_test(EmbedderType::Wasmtime);
}

#[test]
fn wasmtime_select_smoke_test() {
    et::select_smoke_test(EmbedderType::Wasmtime);
}

#[test]
fn wasmtime_select_test() {
    et::select_test(EmbedderType::Wasmtime);
}

fn logger() -> ic_logger::ReplicaLogger {
    use slog::Drain;

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!()).into()
}

#[test]
fn syscall_missing_memory() {
    let log = logger();
    let wasm = wabt::wat2wasm(
        r#"
          (module

            (import "ic0" "msg_arg_data_copy"
              (func $ic0_msg_arg_data_copy (param i32 i32 i32)))

            (func (export "canister_update should_fail_with_contract_violation")
              (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 0))
            )

            (memory 0)
          )
        "#,
    )
    .expect("wat");

    let embedder =
        ic_embedders::WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log);

    let compiled = embedder
        .compile(
            PersistenceType::Sigsegv,
            &ic_wasm_types::BinaryEncodedWasm::new(wasm),
        )
        .expect("compiled");

    let mut instance = embedder.new_instance(
        &compiled,
        &[],
        ic_replicated_state::NumWasmPages::from(0),
        None,
        None,
    );

    let user_id = ic_test_utilities::types::ids::user_test_id(24);

    let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
    let system_state = ic_test_utilities::state::SystemStateBuilder::default().build();
    let system_state_accessor =
        ic_system_api::SystemStateAccessorDirect::new(system_state, cycles_account_manager);
    let mut api = ic_system_api::SystemApiImpl::new(
        ic_system_api::ApiType::init(ic_test_utilities::mock_time(), vec![], user_id.get()),
        system_state_accessor,
        ic_types::NumInstructions::from(10_000_000),
        ic_types::NumBytes::from(4 << 30),
        ic_types::NumBytes::from(0),
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        ComputeAllocation::default(),
        dummy_pause_handler(),
    );

    let result = instance.run(
        &mut api,
        ic_types::methods::FuncRef::Method(ic_types::methods::WasmMethod::Update(
            "should_fail_with_contract_violation".to_string(),
        )),
    );

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

    let embedder =
        ic_embedders::WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log);

    let compiled = embedder
        .compile(
            PersistenceType::Sigsegv,
            &ic_wasm_types::BinaryEncodedWasm::new(wasm),
        )
        .expect("compiled");

    let mut instance = embedder.new_instance(
        &compiled,
        &[],
        ic_replicated_state::NumWasmPages::from(0),
        None,
        None,
    );

    let user_id = ic_test_utilities::types::ids::user_test_id(24);

    let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
    let system_state = ic_test_utilities::state::SystemStateBuilder::default().build();
    let system_state_accessor =
        ic_system_api::SystemStateAccessorDirect::new(system_state, cycles_account_manager);
    let mut api = ic_system_api::SystemApiImpl::new(
        ic_system_api::ApiType::init(ic_test_utilities::mock_time(), vec![], user_id.get()),
        system_state_accessor,
        ic_types::NumInstructions::from(10_000_000),
        ic_types::NumBytes::from(4 << 30),
        ic_types::NumBytes::from(0),
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        ComputeAllocation::default(),
        dummy_pause_handler(),
    );

    let result = instance.run(
        &mut api,
        ic_types::methods::FuncRef::Method(ic_types::methods::WasmMethod::Update("f".to_string())),
    );

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
