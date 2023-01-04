use std::time::Duration;

use ic_base_types::NumBytes;
use ic_sys::PAGE_SIZE;
use ic_types::{NumInstructions, NumPages};
use serde::{Deserialize, Serialize};

use crate::flag_status::FlagStatus;

// Defining 100000 globals in a module can result in significant overhead in
// each message's execution time (about 40x), so set a limit 3 orders of
// magnitude lower which should still allow for reasonable canisters to be
// written (current max number of globals on the Alpha network is 7).
pub(crate) const MAX_GLOBALS: usize = 300;
// The maximum number of functions allowed in a Wasm module.
pub(crate) const MAX_FUNCTIONS: usize = 50000;
// The maximum number of custom sections allowed in a Wasm module.
pub(crate) const MAX_CUSTOM_SECTIONS: usize = 16;
// The total size of the exported custom sections in bytes.
// The size should not exceed 1MiB.
pub(crate) const MAX_CUSTOM_SECTIONS_SIZE: NumBytes = NumBytes::new(1048576);
/// The number of threads to use for query execution.
pub(crate) const QUERY_EXECUTION_THREADS: usize = 2;

/// In terms of execution time, compiling 1 WASM instructions takes as much time
/// as actually executing 6_000 instructions. Only public for use in tests.
#[doc(hidden)]
pub(crate) const DEFAULT_COST_TO_COMPILE_WASM_INSTRUCTION: NumInstructions =
    NumInstructions::new(6_000);

/// The number of rayon threads used by wasmtime to compile wasm binaries
const DEFAULT_WASMTIME_RAYON_COMPILATION_THREADS: usize = 10;

/// Sandbox process eviction does not activate if the number of sandbox
/// processes is below this threshold.
pub(crate) const DEFAULT_MIN_SANDBOX_COUNT: usize = 500;

/// Sandbox process eviction ensures that the number of sandbox processes is
/// always below this threshold.
pub(crate) const DEFAULT_MAX_SANDBOX_COUNT: usize = 2_000;

/// A sandbox process may be evicted after it has been idle for this
/// duration and sandbox process eviction is activated.
pub(crate) const DEFAULT_MAX_SANDBOX_IDLE_TIME: Duration = Duration::from_secs(30 * 60);

#[allow(non_upper_case_globals)]
const KiB: u64 = 1024;
#[allow(non_upper_case_globals)]
const GiB: u64 = KiB * KiB * KiB;
// Maximum number of stable memory dirty pages that a single message execution
// is allowed to produce.
const STABLE_MEMORY_DIRTY_PAGE_LIMIT: u64 = 8 * GiB / (PAGE_SIZE as u64);

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeatureFlags {
    pub rate_limiting_of_debug_prints: FlagStatus,
    /// Track dirty pages with a write barrier instead of the signal handler.
    pub write_barrier: FlagStatus,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            rate_limiting_of_debug_prints: FlagStatus::Enabled,
            write_barrier: FlagStatus::Disabled,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub max_wasm_stack_size: usize,
    pub query_execution_threads: usize,

    /// Maximum number of globals allowed in a Wasm module.
    pub max_globals: usize,

    /// Maximum number of functions allowed in a Wasm module.
    pub max_functions: usize,

    /// Maximum number of custom sections allowed in a Wasm module.
    pub max_custom_sections: usize,

    /// Maximum size of the custom sections in bytes.
    pub max_custom_sections_size: NumBytes,

    /// Compiling a single WASM instruction should cost as much as executing
    /// this many instructions.
    pub cost_to_compile_wasm_instruction: NumInstructions,

    /// The number of rayon threads used by wasmtime to compile wasm binaries
    pub num_rayon_compilation_threads: usize,

    /// Flags to enable or disable features that are still experimental.
    pub feature_flags: FeatureFlags,

    // Maximum number of stable memory dirty pages that a single message execution
    // is allowed to produce.
    pub stable_memory_dirty_page_limit: NumPages,

    /// Sandbox process eviction does not activate if the number of sandbox
    /// processes is below this threshold.
    pub min_sandbox_count: usize,

    /// Sandbox process eviction ensures that the number of sandbox processes is
    /// always below this threshold.
    pub max_sandbox_count: usize,

    /// A sandbox process may be evicted after it has been idle for this
    /// duration and sandbox process eviction is activated.
    pub max_sandbox_idle_time: Duration,
}

impl Config {
    pub fn new() -> Self {
        Config {
            max_wasm_stack_size: 5 * 1024 * 1024,
            query_execution_threads: QUERY_EXECUTION_THREADS,
            max_globals: MAX_GLOBALS,
            max_functions: MAX_FUNCTIONS,
            max_custom_sections: MAX_CUSTOM_SECTIONS,
            max_custom_sections_size: MAX_CUSTOM_SECTIONS_SIZE,
            cost_to_compile_wasm_instruction: DEFAULT_COST_TO_COMPILE_WASM_INSTRUCTION,
            num_rayon_compilation_threads: DEFAULT_WASMTIME_RAYON_COMPILATION_THREADS,
            feature_flags: FeatureFlags::default(),
            stable_memory_dirty_page_limit: NumPages::from(STABLE_MEMORY_DIRTY_PAGE_LIMIT),
            min_sandbox_count: DEFAULT_MIN_SANDBOX_COUNT,
            max_sandbox_count: DEFAULT_MAX_SANDBOX_COUNT,
            max_sandbox_idle_time: DEFAULT_MAX_SANDBOX_IDLE_TIME,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}
