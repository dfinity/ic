use ic_interfaces::execution_environment::{ExecutionParameters, HypervisorResult, InstanceStats};
use ic_replicated_state::{page_map::PageSerialization, Global, NumWasmPages};
use ic_system_api::{ApiType, StaticSystemState};
use ic_types::{ingress::WasmResult, methods::FuncRef, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Round(pub u64);

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecInput {
    pub func_ref: FuncRef,
    pub api_type: ApiType,
    pub globals: Vec<Global>,
    pub canister_current_memory_usage: NumBytes,
    pub execution_parameters: ExecutionParameters,

    /// System state that won't change over the course of executing a single
    /// message.
    pub static_system_state: StaticSystemState,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StateModifications {
    /// The state of the global variables after execution.
    pub globals: Vec<Global>,

    /// Wasm memory page delta produced by this execution.
    pub wasm_memory_page_delta: Vec<PageSerialization>,

    /// Size of wasm memory.
    pub wasm_memory_size: NumWasmPages,

    /// Stable memory page delta produced by this execution.
    pub stable_memory_page_delta: Vec<PageSerialization>,

    /// Size of stable memory.
    pub stable_memory_size: NumWasmPages,

    /// The number of free bytes of memory left on the subnet after executing
    /// the message.
    pub subnet_available_memory: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecOutput {
    pub wasm_result: HypervisorResult<Option<WasmResult>>,
    pub num_instructions_left: NumInstructions,
    pub instance_stats: InstanceStats,
    pub state_modifications: Option<StateModifications>,
}
