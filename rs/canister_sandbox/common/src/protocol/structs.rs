use ic_interfaces::execution_environment::{ExecutionParameters, HypervisorResult, InstanceStats};
use ic_replicated_state::{page_map::PageDeltaSerialization, Global, NumWasmPages};
use ic_system_api::{ApiType, StaticSystemState};
use ic_types::{ingress::WasmResult, methods::FuncRef, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};

use super::id::MemoryId;
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Round(pub u64);

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecInput {
    pub func_ref: FuncRef,
    pub api_type: ApiType,
    pub globals: Vec<Global>,
    pub canister_current_memory_usage: NumBytes,
    pub execution_parameters: ExecutionParameters,
    pub next_wasm_memory_id: MemoryId,
    pub next_stable_memory_id: MemoryId,
    /// System state that won't change over the course of executing a single
    /// message.
    pub static_system_state: StaticSystemState,
}

/// Describes the memory changes performed by execution.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemoryModifications {
    pub page_delta: PageDeltaSerialization,
    pub size: NumWasmPages,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StateModifications {
    /// The state of the global variables after execution.
    pub globals: Vec<Global>,

    /// Modifications in the Wasm memory.
    pub wasm_memory: MemoryModifications,

    /// Modifications in the stable memory.
    pub stable_memory: MemoryModifications,

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
