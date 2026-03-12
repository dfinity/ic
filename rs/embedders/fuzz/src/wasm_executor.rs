use crate::ic_wasm::{ICWasmModule, get_system_api_type_for_wasm_method};
use ic_config::{
    embedders::Config as EmbeddersConfig, execution_environment::Config as HypervisorConfig,
    subnet_config::SchedulerConfig,
};
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::{
    CompilationCache, CompilationCacheBuilder, WasmExecutionInput, WasmtimeEmbedder,
    wasm_executor::{WasmExecutionResult, WasmExecutor, WasmExecutorImpl},
    wasmtime_embedder::system_api::{
        ApiType, ExecutionParameters, InstructionLimits,
        sandbox_safe_system_state::SandboxSafeSystemState,
    },
};
use ic_interfaces::execution_environment::{
    ExecutionMode, MessageMemoryUsage, SubnetAvailableMemory,
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallOrigin, NetworkTopology, SystemState, page_map::TestPageAllocatorFileDescriptorImpl,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_embedders::DEFAULT_NUM_INSTRUCTIONS;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{
    CanisterId,
    batch::CanisterCyclesCostSchedule,
    messages::{CallbackId, NO_DEADLINE, RequestMetadata},
    time::UNIX_EPOCH,
};
use ic_types::{
    ComputeAllocation, Cycles, MemoryAllocation, NumBytes,
    methods::{FuncRef, WasmMethod},
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
    let canister_module = CanisterModule::new(wasm);
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

    let compilation_cache = Arc::new(CompilationCacheBuilder::new().build());
    let mut system_state = SystemStateBuilder::default()
        .initial_cycles(Cycles::from(5_000_000_000_000_u64))
        .canister_id(CanisterId::from_u64(1))
        .build();

    let result = wasm_executor.create_execution_state(
        canister_module,
        PathBuf::new(),
        CanisterId::from_u64(1),
        compilation_cache.clone(),
    );

    if wasm_methods.is_empty() || result.is_err() {
        // Compilation can fail!
        return;
    }
    let mut execution_state = result.unwrap().0;

    // For determinism, all methods are executed
    for wasm_method in wasm_methods.iter() {
        let wasm_execution_input =
            setup_wasm_execution_input(wasm_method, &mut system_state, compilation_cache.clone());
        let (_compilation_result, execution_result) = &wasm_executor
            .clone()
            .execute(wasm_execution_input, &execution_state);

        match execution_result {
            WasmExecutionResult::Finished(
                _slice_execution_output,
                _wasm_execution_output,
                canister_state_changes,
            ) => {
                if let Some(execution_state_changes) =
                    &canister_state_changes.execution_state_changes
                {
                    execution_state.exported_globals = execution_state_changes.globals.clone();
                    execution_state.wasm_memory = execution_state_changes.wasm_memory.clone();
                    execution_state.stable_memory = execution_state_changes.stable_memory.clone();
                }
                canister_state_changes
                    .system_state_modifications
                    .apply_balance_changes(&mut system_state);
            }
            WasmExecutionResult::Paused(_, _) => (), // Only possible via execute_dts
        }
    }
}

#[inline(always)]
fn setup_wasm_execution_input(
    wasm_method: &WasmMethod,
    system_state: &mut SystemState,
    compilation_cache: Arc<CompilationCache>,
) -> WasmExecutionInput {
    let func_ref = FuncRef::Method(wasm_method.clone());
    let api_type = get_system_api_type_for_wasm_method(wasm_method.clone());
    let canister_current_memory_usage = NumBytes::new(0);
    let canister_current_message_memory_usage = MessageMemoryUsage::ZERO;
    let _call_context_id = system_state.new_call_context(
        get_call_orign_for_wasm_method(wasm_method.clone()),
        Cycles::new(1_000_000_000),
        UNIX_EPOCH,
        RequestMetadata::default(),
    );

    WasmExecutionInput {
        api_type: api_type.clone(),
        sandbox_safe_system_state: get_sandbox_safe_system_state(system_state, api_type),
        canister_current_memory_usage,
        canister_current_message_memory_usage,
        execution_parameters: get_execution_parameters(),
        subnet_available_memory: *MAX_SUBNET_AVAILABLE_MEMORY,
        func_ref,
        compilation_cache,
    }
}

pub(crate) fn get_sandbox_safe_system_state(
    system_state: &SystemState,
    api_type: ApiType,
) -> SandboxSafeSystemState {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let dirty_page_overhead = SchedulerConfig::application_subnet().dirty_page_overhead;
    let network_topology = NetworkTopology::default();

    SandboxSafeSystemState::new_for_testing(
        system_state,
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

pub fn get_call_orign_for_wasm_method(wasm_method: WasmMethod) -> CallOrigin {
    match wasm_method {
        WasmMethod::Update(_) => CallOrigin::CanisterUpdate(
            CanisterId::from_u64(2),
            CallbackId::from(5),
            NO_DEADLINE,
            String::from(""),
        ),
        WasmMethod::Query(_) => CallOrigin::Query(user_test_id(1), String::from("")),
        WasmMethod::CompositeQuery(_) => CallOrigin::CanisterQuery(
            CanisterId::from_u64(2),
            CallbackId::from(5),
            String::from(""),
        ),
        WasmMethod::System(_) => unimplemented!(),
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
