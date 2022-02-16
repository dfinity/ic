mod signal_handler;
pub mod wasm_executor;
pub mod wasm_utils;
pub mod wasmtime_embedder;

use ic_interfaces::execution_environment::ExecutionParameters;
use ic_replicated_state::{ExecutionState, Global, NumWasmPages, PageIndex};
use ic_sys::PageBytes;
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType};
use ic_types::{methods::FuncRef, NumBytes};
pub use wasmtime_embedder::{WasmtimeEmbedder, WasmtimeMemoryCreator};

pub struct WasmExecutionInput {
    pub api_type: ApiType,
    pub sandbox_safe_system_state: SandboxSafeSystemState,
    pub canister_current_memory_usage: NumBytes,
    pub execution_parameters: ExecutionParameters,
    pub func_ref: FuncRef,
    pub execution_state: ExecutionState,
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
