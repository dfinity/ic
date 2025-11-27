use crate::ic_wasm::ICWasmModule;
use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as HypervisorConfig,
    subnet_config::SchedulerConfig,
};
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::{
    CompilationCacheBuilder, WasmExecutionInput, WasmtimeEmbedder,
    wasm_executor::{WasmExecutor, WasmExecutorImpl},
    wasmtime_embedder::system_api::{
        ApiType, ExecutionParameters, InstructionLimits,
        sandbox_safe_system_state::SandboxSafeSystemState,
    },
};
use ic_interfaces::execution_environment::{
    ExecutionMode, MessageMemoryUsage, SubnetAvailableMemory,
};
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::Global;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    ExecutionState, ExportedFunctions, Memory, NetworkTopology,
    canister_state::execution_state::{WasmBinary, WasmMetadata},
    page_map::TestPageAllocatorFileDescriptorImpl,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_embedders::DEFAULT_NUM_INSTRUCTIONS;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::ids::user_test_id;
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::{
    ComputeAllocation, MemoryAllocation, NumBytes,
    methods::{FuncRef, WasmMethod},
    time::UNIX_EPOCH,
};
use ic_wasm_types::CanisterModule;
use lazy_static::lazy_static;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

const SUBNET_MEMORY_CAPACITY: i64 = i64::MAX / 2;

lazy_static! {
    pub(crate) static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new_for_testing(
            SUBNET_MEMORY_CAPACITY,
            SUBNET_MEMORY_CAPACITY,
            SUBNET_MEMORY_CAPACITY
        );
}

#[inline(always)]
pub fn run_fuzzer(module: ICWasmModule) {
    let wasm = module.module.to_bytes();

    let persisted_globals: Vec<Global> = module.exported_globals;

    let canister_module = CanisterModule::new(wasm);
    let wasm_binary = WasmBinary::new(canister_module);

    let wasm_methods: BTreeSet<WasmMethod> = module.exported_functions;

    let log = no_op_logger();
    let embedder_config = EmbeddersConfig::default();
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
}

#[inline(always)]
fn setup_wasm_execution_input(func_ref: FuncRef) -> WasmExecutionInput {
    let api_type = ApiType::init(UNIX_EPOCH, vec![], user_test_id(24).get());
    let canister_current_memory_usage = NumBytes::new(0);
    let canister_current_message_memory_usage = MessageMemoryUsage::ZERO;
    let compilation_cache = Arc::new(CompilationCacheBuilder::new().build());
    WasmExecutionInput {
        api_type: api_type.clone(),
        sandbox_safe_system_state: get_system_state(api_type),
        canister_current_memory_usage,
        canister_current_message_memory_usage,
        execution_parameters: get_execution_parameters(),
        subnet_available_memory: *MAX_SUBNET_AVAILABLE_MEMORY,
        func_ref,
        compilation_cache,
    }
}

#[inline(always)]
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

pub(crate) fn get_system_state(api_type: ApiType) -> SandboxSafeSystemState {
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let dirty_page_overhead = SchedulerConfig::application_subnet().dirty_page_overhead;
    let network_topology = NetworkTopology::default();

    SandboxSafeSystemState::new_for_testing(
        &system_state,
        cycles_account_manager,
        &network_topology,
        dirty_page_overhead,
        ComputeAllocation::default(),
        HypervisorConfig::default().subnet_callback_soft_limit as u64,
        Default::default(),
        api_type.caller(),
        api_type.call_context_id(),
        CanisterCyclesCostSchedule::Normal,
    )
}

pub(crate) fn get_execution_parameters() -> ExecutionParameters {
    ExecutionParameters {
        instruction_limits: InstructionLimits::new(
            DEFAULT_NUM_INSTRUCTIONS,
            DEFAULT_NUM_INSTRUCTIONS,
        ),
        wasm_memory_limit: None,
        memory_allocation: MemoryAllocation::default(),
        canister_guaranteed_callback_quota: HypervisorConfig::default()
            .canister_guaranteed_callback_quota as u64,
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
        subnet_memory_saturation: ResourceSaturation::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    #[test]
    fn test_execute_with_wasm_executor_single_run() {
        let arbitrary_str: &str = "this is a test string";
        let unstrucutred = Unstructured::new(arbitrary_str.as_bytes());
        let module = <crate::ic_wasm::ICWasmModule as Arbitrary>::arbitrary_take_rest(unstrucutred)
            .expect("Unable to extract wasm from Unstructured data");
        run_fuzzer(module);
    }
}
