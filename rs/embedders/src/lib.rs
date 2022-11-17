mod compilation_cache;
mod serialized_module;
mod signal_handler;
pub mod wasm_executor;
pub mod wasm_utils;
pub mod wasmtime_embedder;

use std::{sync::Arc, time::Duration};

pub use compilation_cache::CompilationCache;
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_replicated_state::{Global, NumWasmPages, PageIndex};
use ic_sys::PageBytes;
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, ExecutionParameters,
};
use ic_types::{methods::FuncRef, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};
pub use serialized_module::{SerializedModule, SerializedModuleBytes};
pub use wasmtime_embedder::{WasmtimeEmbedder, WasmtimeMemoryCreator};

pub struct WasmExecutionInput {
    pub api_type: ApiType,
    pub sandbox_safe_system_state: SandboxSafeSystemState,
    pub canister_current_memory_usage: NumBytes,
    pub execution_parameters: ExecutionParameters,
    pub subnet_available_memory: SubnetAvailableMemory,
    pub func_ref: FuncRef,
    pub compilation_cache: Arc<CompilationCache>,
}

#[derive(Debug)]
pub struct InstanceRunResult {
    pub dirty_pages: Vec<PageIndex>,
    pub stable_memory_size: NumWasmPages,
    pub stable_memory_dirty_pages: Vec<(PageIndex, PageBytes)>,
    pub exported_globals: Vec<Global>,
}

pub trait LinearMemory {
    fn as_ptr(&self) -> *mut libc::c_void;
}

/// The results of compiling a Canister which need to be passed back to the main
/// replica process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompilationResult {
    /// The number of instructions in the canister's largest function.
    pub largest_function_instruction_count: NumInstructions,
    /// Time to compile canister (including instrumentation and validation).
    pub compilation_time: Duration,
}

impl CompilationResult {
    pub fn empty_for_testing() -> Self {
        Self {
            largest_function_instruction_count: NumInstructions::new(0),
            compilation_time: Duration::from_millis(1),
        }
    }
}
