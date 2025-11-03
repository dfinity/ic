use ic_embedders::{
    wasm_executor::SliceExecutionOutput,
    wasmtime_embedder::system_api::{
        ApiType, ExecutionParameters,
        sandbox_safe_system_state::{SandboxSafeSystemState, SystemStateModifications},
    },
};
use ic_interfaces::execution_environment::{
    MessageMemoryUsage, SubnetAvailableMemory, WasmExecutionOutput,
};
use ic_management_canister_types_private::Global;
use ic_replicated_state::{Memory, NumWasmPages, PageIndex, page_map::PageDeltaSerialization};
use ic_types::{NumBytes, methods::FuncRef};
use serde::{Deserialize, Serialize};

use super::id::MemoryId;

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct Round(pub u64);

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SandboxExecInput {
    pub func_ref: FuncRef,
    pub api_type: ApiType,
    pub globals: Vec<Global>,
    pub canister_current_memory_usage: NumBytes,
    pub canister_current_message_memory_usage: MessageMemoryUsage,
    pub execution_parameters: ExecutionParameters,
    pub subnet_available_memory: SubnetAvailableMemory,
    pub next_wasm_memory_id: MemoryId,
    pub next_stable_memory_id: MemoryId,
    // View of the system_state that is safe for the sandboxed process to
    // access.
    pub sandbox_safe_system_state: SandboxSafeSystemState,
    pub wasm_reserved_pages: NumWasmPages,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SandboxExecOutput {
    pub slice: SliceExecutionOutput,
    pub wasm: WasmExecutionOutput,
    pub state: StateModifications,
    pub execute_total_duration: std::time::Duration,
    pub execute_run_duration: std::time::Duration,
}

impl SandboxExecOutput {
    pub fn take_state_modifications(&mut self) -> StateModifications {
        std::mem::take(&mut self.state)
    }
}

/// Describes the memory changes performed by execution.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct MemoryModifications {
    pub page_delta: PageDeltaSerialization,
    pub size: NumWasmPages,
}

#[derive(Serialize, Default, Debug, Deserialize, Clone, PartialEq)]
pub struct StateModifications {
    /// Modifications in the execution state of the canister.
    ///
    /// This field is optional because the state changes might or might not
    /// be applied depending on the method executed.
    pub execution_state_modifications: Option<ExecutionStateModifications>,

    /// Modifications in the system state of the canister.
    ///
    /// The system state changes contain parts that are always applied
    /// and parts that are only applied depending on the method executed
    /// (similarly to `execution_state_modifications`).
    pub system_state_modifications: SystemStateModifications,
}

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq)]
pub struct ExecutionStateModifications {
    /// The state of the global variables after execution.
    pub globals: Vec<Global>,

    /// Modifications in the Wasm memory.
    pub wasm_memory: MemoryModifications,

    /// Modifications in the stable memory.
    pub stable_memory: MemoryModifications,
}

impl ExecutionStateModifications {
    pub fn new(
        globals: Vec<Global>,
        wasm_memory: &Memory,
        stable_memory: &Memory,
        wasm_memory_delta: &[PageIndex],
        stable_memory_delta: &[PageIndex],
    ) -> Self {
        let wasm_memory = MemoryModifications {
            page_delta: wasm_memory.page_map.serialize_delta(wasm_memory_delta),
            size: wasm_memory.size,
        };

        let stable_memory = MemoryModifications {
            page_delta: stable_memory.page_map.serialize_delta(stable_memory_delta),
            size: stable_memory.size,
        };

        ExecutionStateModifications {
            globals,
            wasm_memory,
            stable_memory,
        }
    }
}
