#![no_main]
use ic_config::{
    embedders::{Config, FeatureFlags},
    flag_status::FlagStatus,
    subnet_config::SchedulerConfig,
};
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::{
    wasm_executor::{WasmExecutor, WasmExecutorImpl},
    CompilationCache, WasmExecutionInput, WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::execution_state::{WasmBinary, WasmMetadata},
    page_map::TestPageAllocatorFileDescriptorImpl,
    ExecutionState, ExportedFunctions, Global, Memory, NetworkTopology,
};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, ExecutionParameters,
    InstructionLimits,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_embedders::DEFAULT_NUM_INSTRUCTIONS;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{
    messages::RequestMetadata,
    methods::{FuncRef, WasmMethod},
    time::UNIX_EPOCH,
    ComputeAllocation, MemoryAllocation, NumBytes,
};
use ic_wasm_types::CanisterModule;
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
mod ic_wasm;
use ic_wasm::ICWasmModule;
// The fuzzer creates valid wasms and tries to execute a query method via WasmExecutor.
// The fuzzing success rate directly depends upon the IC valid wasm corpus provided.
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// libfuzzer: bazel run --config=fuzzing //rs/embedders/fuzz:execute_with_wasm_executor_libfuzzer -- corpus/
// afl:  bazel run --config=afl //rs/embedders/fuzz:execute_with_wasm_executor_afl -- corpus/

fuzz_target!(|module: ICWasmModule| {
    let wasm = module.module.to_bytes();

    let persisted_globals: Vec<Global> = module.exoported_globals;

    let canister_module = CanisterModule::new(wasm);
    let wasm_binary = WasmBinary::new(canister_module);

    let wasm_methods: BTreeSet<WasmMethod> = module.exported_functions;

    let log = no_op_logger();
    let embedder_config = Config {
        feature_flags: FeatureFlags {
            write_barrier: FlagStatus::Enabled,
            ..Default::default()
        },
        ..Default::default()
    };
    let metrics_registry = MetricsRegistry::new();
    let fd_factory = Arc::new(TestPageAllocatorFileDescriptorImpl::new());

    let wasm_executor = Arc::new(WasmExecutorImpl::new(
        WasmtimeEmbedder::new(embedder_config.clone(), log.clone()),
        &metrics_registry,
        log,
        fd_factory,
    ));
    let execution_state =
        setup_execution_state(wasm_binary, wasm_methods.clone(), persisted_globals);

    if wasm_methods.is_empty() {
        return;
    }

    // For determinism, all methods are executed
    for wasm_method in wasm_methods.iter() {
        let func_ref = FuncRef::Method(wasm_method.clone());
        let wasm_execution_input = setup_wasm_execution_input(func_ref);
        let (_compilation_result, _execution_result) = &wasm_executor
            .clone()
            .execute(wasm_execution_input, &execution_state);
    }
});

fn setup_wasm_execution_input(func_ref: FuncRef) -> WasmExecutionInput {
    let time = UNIX_EPOCH;
    let api_type = ApiType::init(time, vec![], user_test_id(24).get());

    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let dirty_page_overhead = SchedulerConfig::application_subnet().dirty_page_overhead;
    let network_topology = NetworkTopology::default();

    let sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        cycles_account_manager,
        &network_topology,
        dirty_page_overhead,
        ComputeAllocation::default(),
        RequestMetadata::new(0, UNIX_EPOCH),
        api_type.caller(),
    );

    let canister_current_memory_usage = NumBytes::new(0);
    let canister_current_message_memory_usage = NumBytes::new(0);

    let subnet_memory_capacity = i64::MAX / 2;

    let execution_parameters = ExecutionParameters {
        instruction_limits: InstructionLimits::new(
            FlagStatus::Disabled,
            DEFAULT_NUM_INSTRUCTIONS,
            DEFAULT_NUM_INSTRUCTIONS,
        ),
        canister_memory_limit: NumBytes::from(4 << 30),
        wasm_memory_limit: None,
        memory_allocation: MemoryAllocation::default(),
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
        subnet_memory_saturation: ResourceSaturation::default(),
    };

    let subnet_available_memory = SubnetAvailableMemory::new(
        subnet_memory_capacity,
        subnet_memory_capacity,
        subnet_memory_capacity,
    );

    let compilation_cache = Arc::new(CompilationCache::new(NumBytes::new(0)));

    WasmExecutionInput {
        api_type,
        sandbox_safe_system_state,
        canister_current_memory_usage,
        canister_current_message_memory_usage,
        execution_parameters,
        subnet_available_memory,
        func_ref,
        compilation_cache,
    }
}

fn setup_execution_state(
    wasm_binary: Arc<WasmBinary>,
    wasm_methods: BTreeSet<WasmMethod>,
    persisted_globals: Vec<Global>,
) -> ExecutionState {
    ExecutionState::new(
        PathBuf::new(),
        wasm_binary,
        ExportedFunctions::new(wasm_methods),
        Memory::new_for_testing(),
        Memory::new_for_testing(),
        persisted_globals,
        WasmMetadata::default(),
    )
}
