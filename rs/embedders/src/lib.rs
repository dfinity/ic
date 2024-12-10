mod compilation_cache;
mod serialized_module;
mod signal_handler;
pub mod wasm_executor;
pub mod wasm_utils;
pub mod wasmtime_embedder;

use std::{sync::Arc, time::Duration};

pub use compilation_cache::{CompilationCache, StoredCompilation};
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_replicated_state::{Global, PageIndex};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, ExecutionParameters,
};
use ic_types::{methods::FuncRef, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};
pub use serialized_module::{
    InitialStateData, OnDiskSerializedModule, SerializedModule, SerializedModuleBytes,
};
pub use wasmtime_embedder::{WasmtimeEmbedder, WasmtimeMemoryCreator};

/// The minimal required guard region for correctness is 2GiB. We use 8GiB as a
/// safety measure since the allocation happens in the virtual memory and its
/// overhead is negligible.
pub(crate) const MIN_GUARD_REGION_SIZE: usize = 8 * 1024 * 1024 * 1024;

/// The maximum Wasm stack size as configured by Wasmtime.
pub(crate) const MAX_WASM_STACK_SIZE: usize = 5 * 1024 * 1024;

pub struct WasmExecutionInput {
    pub api_type: ApiType,
    pub sandbox_safe_system_state: SandboxSafeSystemState,
    pub canister_current_memory_usage: NumBytes,
    pub canister_current_message_memory_usage: NumBytes,
    pub execution_parameters: ExecutionParameters,
    pub subnet_available_memory: SubnetAvailableMemory,
    pub func_ref: FuncRef,
    pub compilation_cache: Arc<CompilationCache>,
}

#[derive(Clone, Debug)]
pub struct InstanceRunResult {
    pub wasm_dirty_pages: Vec<PageIndex>,
    pub stable_memory_dirty_pages: Vec<PageIndex>,
    pub exported_globals: Vec<Global>,
}

/// The results of compiling a Canister which need to be passed back to the main
/// replica process.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CompilationResult {
    /// The number of instructions in the canister's largest function.
    pub largest_function_instruction_count: NumInstructions,
    /// Time to compile canister (including instrumentation and validation).
    pub compilation_time: Duration,
    /// The maximum function complexity found in the canister's wasm module.
    pub max_complexity: u64,
}

impl CompilationResult {
    pub fn empty_for_testing() -> Self {
        Self {
            largest_function_instruction_count: NumInstructions::new(0),
            compilation_time: Duration::from_millis(1),
            max_complexity: 0,
        }
    }
}

pub(crate) enum InternalErrorCode {
    Unknown = 0,
    HeapOutOfBounds = 1,
    StableMemoryOutOfBounds = 2,
    StableMemoryTooBigFor32Bit = 3,
    MemoryWriteLimitExceeded = 4,
    MemoryAccessLimitExceeded = 5,
    StableGrowFailed = 6,
}

impl InternalErrorCode {
    fn from_i32(code: i32) -> Self {
        match code {
            code if code == Self::HeapOutOfBounds as i32 => Self::HeapOutOfBounds,
            code if code == Self::StableMemoryOutOfBounds as i32 => Self::StableMemoryOutOfBounds,
            code if code == Self::StableMemoryTooBigFor32Bit as i32 => {
                Self::StableMemoryTooBigFor32Bit
            }
            code if code == Self::MemoryWriteLimitExceeded as i32 => Self::MemoryWriteLimitExceeded,
            code if code == Self::MemoryAccessLimitExceeded as i32 => {
                Self::MemoryAccessLimitExceeded
            }
            code if code == Self::StableGrowFailed as i32 => Self::StableGrowFailed,
            _ => Self::Unknown,
        }
    }
}
