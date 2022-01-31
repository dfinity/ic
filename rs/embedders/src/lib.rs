mod signal_handler;
pub mod wasm_executor;
pub mod wasm_utils;
pub mod wasmtime_embedder;

use ic_interfaces::execution_environment::{ExecutionParameters, HypervisorError, InstanceStats};
use ic_replicated_state::{ExecutionState, Global, NumWasmPages, PageIndex};
use ic_sys::PageBytes;
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType};
use ic_types::{ingress::WasmResult, methods::FuncRef, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};
use std::fmt;
pub use wasmtime_embedder::{WasmtimeEmbedder, WasmtimeMemoryCreator};

pub struct WasmExecutionInput {
    pub api_type: ApiType,
    pub sandbox_safe_system_state: SandboxSafeSystemState,
    pub canister_current_memory_usage: NumBytes,
    pub execution_parameters: ExecutionParameters,
    pub func_ref: FuncRef,
    pub execution_state: ExecutionState,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WasmExecutionOutput {
    pub wasm_result: Result<Option<WasmResult>, HypervisorError>,
    pub num_instructions_left: NumInstructions,
    pub instance_stats: InstanceStats,
}

impl fmt::Display for WasmExecutionOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wasm_result_str = match &self.wasm_result {
            Ok(result) => match result {
                None => "None".to_string(),
                Some(wasm_result) => format!("{}", wasm_result),
            },
            Err(err) => format!("{}", err),
        };
        write!(f, "wasm_result => [{}], instructions left => {}, instace_stats => [ accessed pages => {}, dirty pages => {}]",
               wasm_result_str,
               self.num_instructions_left,
               self.instance_stats.accessed_pages,
               self.instance_stats.dirty_pages
        )
    }
}

pub struct InstanceRunResult {
    pub dirty_pages: Vec<PageIndex>,
    pub stable_memory_size: NumWasmPages,
    pub stable_memory_dirty_pages: Vec<(PageIndex, PageBytes)>,
    pub exported_globals: Vec<Global>,
}

pub trait LinearMemory {
    fn as_ptr(&self) -> *mut libc::c_void;
}

pub trait ICMemoryCreator {
    type Mem: LinearMemory;

    fn new_memory(
        &self,
        mem_size: usize,
        guard_size: usize,
        instance_heap_offset: usize,
        min_pages: usize,
        max_pages: Option<usize>,
    ) -> Self::Mem;
}
