use ic_interfaces::execution_environment::ExecutionParameters;
use ic_replicated_state::{
    page_map::PageDeltaSerialization, Global, Memory, NumWasmPages, PageIndex,
};
use ic_system_api::{ApiType, StaticSystemState};
use ic_types::{methods::FuncRef, NumBytes};
use serde::{Deserialize, Serialize};

use super::id::MemoryId;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Round(pub u64);

#[derive(Serialize, Deserialize, Clone)]
pub struct SandboxExecInput {
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

impl StateModifications {
    pub fn new(
        globals: Vec<Global>,
        wasm_memory: &Memory,
        stable_memory: &Memory,
        wasm_memory_delta: &[PageIndex],
        stable_memory_delta: &[PageIndex],
        subnet_available_memory: i64,
    ) -> Self {
        let wasm_memory = MemoryModifications {
            page_delta: wasm_memory.page_map.serialize_delta(wasm_memory_delta),
            size: wasm_memory.size,
        };

        let stable_memory = MemoryModifications {
            page_delta: stable_memory.page_map.serialize_delta(stable_memory_delta),
            size: stable_memory.size,
        };

        StateModifications {
            globals,
            wasm_memory,
            stable_memory,
            subnet_available_memory,
        }
    }
}
