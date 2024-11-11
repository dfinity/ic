use std::time::Duration;

use ic_base_types::NumBytes;
use ic_registry_subnet_type::SubnetType;
use ic_sys::PAGE_SIZE;
use ic_types::{NumInstructions, NumOsPages, MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES};
use serde::{Deserialize, Serialize};

use crate::flag_status::FlagStatus;

// Defining 100000 globals in a module can result in significant overhead in
// each message's execution time (about 40x), so set a limit 3 orders of
// magnitude lower which should still allow for reasonable canisters to be
// written (current max number of globals on the Alpha network is 7).
pub(crate) const MAX_GLOBALS: usize = 1000;
// The maximum number of functions allowed in a Wasm module.
pub(crate) const MAX_FUNCTIONS: usize = 50000;
// The maximum number of custom sections allowed in a Wasm module.
pub(crate) const MAX_CUSTOM_SECTIONS: usize = 16;
// The total size of the exported custom sections in bytes.
// The size should not exceed 1MiB.
pub(crate) const MAX_CUSTOM_SECTIONS_SIZE: NumBytes = NumBytes::new(1048576);
// The maximum number of exported functions called `canister_update <name>`,
// `canister_query <name>`, or `canister_composite_query <name>`.
pub(crate) const MAX_NUMBER_EXPORTED_FUNCTIONS: usize = 1000;
// The maximum sum of `<name>` lengths in exported functions called `canister_update <name>`,
// `canister_query <name>`, or `canister_composite_query <name>`.
pub(crate) const MAX_SUM_EXPORTED_FUNCTION_NAME_LENGTHS: usize = 20000;
/// The number of threads to use for query execution per canister.
/// See also `QUERY_EXECUTION_THREADS_TOTAL`.
pub(crate) const QUERY_EXECUTION_THREADS_PER_CANISTER: usize = 2;

/// In terms of execution time, compiling 1 WASM instructions takes as much time
/// as actually executing 6_000 instructions. Only public for use in tests.
#[doc(hidden)]
pub(crate) const DEFAULT_COST_TO_COMPILE_WASM_INSTRUCTION: NumInstructions =
    NumInstructions::new(6_000);

/// The number of rayon threads used by wasmtime to compile wasm binaries
const DEFAULT_WASMTIME_RAYON_COMPILATION_THREADS: usize = 10;

/// The number of rayon threads use for the parallel page copying optimization.
const DEFAULT_PAGE_ALLOCATOR_THREADS: usize = 8;

/// Sandbox process eviction does not activate if the number of sandbox
/// processes is below this threshold.
pub(crate) const DEFAULT_MIN_SANDBOX_COUNT: usize = 500;

/// Sandbox process eviction ensures that the number of sandbox processes is
/// always below this threshold.
pub(crate) const DEFAULT_MAX_SANDBOX_COUNT: usize = 1_000;

/// A sandbox process may be evicted after it has been idle for this
/// duration and sandbox process eviction is activated.
pub(crate) const DEFAULT_MAX_SANDBOX_IDLE_TIME: Duration = Duration::from_secs(30 * 60);

/// The maximum number of pages that a message dirties without optimizing dirty
/// page copying by triggering a new execution slice for copying pages.
/// This default is 1 GiB.
pub(crate) const DEFAULT_MAX_DIRTY_PAGES_WITHOUT_OPTIMIZATION: usize = (GiB as usize) / PAGE_SIZE;

/// Scheduling overhead for copying dirty pages, in instructions.
pub(crate) const DIRTY_PAGE_COPY_OVERHEAD: NumInstructions = NumInstructions::new(3_000);

#[allow(non_upper_case_globals)]
const KiB: u64 = 1024;
#[allow(non_upper_case_globals)]
const GiB: u64 = KiB * KiB * KiB;

// Maximum number of stable memory dirty OS pages (4KiB) that an upgrade/install message execution
// is allowed to produce.
const STABLE_MEMORY_DIRTY_PAGE_LIMIT_UPGRADE: NumOsPages =
    NumOsPages::new(8 * GiB / (PAGE_SIZE as u64));
// Maximum number of stable memory dirty OS pages (4KiB) that a regular message (update) execution
// is allowed to produce.
const STABLE_MEMORY_DIRTY_PAGE_LIMIT_MESSAGE: NumOsPages =
    NumOsPages::new(2 * GiB / (PAGE_SIZE as u64));
// Maximum number of stable memory dirty OS pages (4KiB) that a non-replicated query is allowed to produce.
const STABLE_MEMORY_DIRTY_PAGE_LIMIT_QUERY: NumOsPages = NumOsPages::new(GiB / (PAGE_SIZE as u64));

// Maximum number of stable memory OS pages (4KiB) that that an upgrade/install message execution
// is allowed to access.
const STABLE_MEMORY_ACCESSED_PAGE_LIMIT_UPGRADE: NumOsPages =
    NumOsPages::new(8 * GiB / (PAGE_SIZE as u64));
// Maximum number of stable memory OS pages (4KiB) that a that a regular message (update) execution
// is allowed to access.
const STABLE_MEMORY_ACCESSED_PAGE_LIMIT_MESSAGE: NumOsPages =
    NumOsPages::new(2 * GiB / (PAGE_SIZE as u64));
// Maximum number of stable memory OS pages (4KiB) that a single non-replicated query execution
// is allowed to access.
const STABLE_MEMORY_ACCESSED_PAGE_LIMIT_QUERY: NumOsPages =
    NumOsPages::new(GiB / (PAGE_SIZE as u64));

/// The maximum size in bytes for an uncompressed Wasm module. This value is
/// also used as the maximum size for the Wasm chunk store of each canister.
pub const WASM_MAX_SIZE: NumBytes = NumBytes::new(100 * 1024 * 1024); // 100 MiB

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct FeatureFlags {
    /// If this flag is enabled, then the output of the `debug_print` system-api
    /// call will be skipped based on heuristics.
    pub rate_limiting_of_debug_prints: FlagStatus,
    /// Track dirty pages with a write barrier instead of the signal handler.
    pub write_barrier: FlagStatus,
    pub wasm_native_stable_memory: FlagStatus,
    /// Indicates whether the support for 64 bit main memory is enabled
    pub wasm64: FlagStatus,
    // TODO(IC-1674): remove this flag once the feature is enabled by default.
    /// Indicates whether the best-effort responses feature is enabled.
    pub best_effort_responses: FlagStatus,
    /// Collect a backtrace from the canister when it panics.
    pub canister_backtrace: FlagStatus,
}

impl FeatureFlags {
    const fn const_default() -> Self {
        Self {
            rate_limiting_of_debug_prints: FlagStatus::Enabled,
            write_barrier: FlagStatus::Disabled,
            wasm_native_stable_memory: FlagStatus::Enabled,
            wasm64: FlagStatus::Disabled,
            best_effort_responses: FlagStatus::Disabled,
            canister_backtrace: FlagStatus::Disabled,
        }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self::const_default()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum MeteringType {
    New,
    /// for testing and benchmarking
    None,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct StableMemoryPageLimit {
    // Regular message (e.g., update) execution dirty/accessed page limit.
    pub message: NumOsPages,
    // Longer message (e.g., upgrade) execution dirty/accessed page limit.
    pub upgrade: NumOsPages,
    // Query (replicated and non-replicated, as well as composite) execution dirty/accessed page limit.
    pub query: NumOsPages,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Config {
    /// The number of threads to use for query execution per canister.
    pub query_execution_threads_per_canister: usize,

    /// Maximum number of globals allowed in a Wasm module.
    pub max_globals: usize,

    /// Maximum number of functions allowed in a Wasm module.
    pub max_functions: usize,

    /// Maximum number of custom sections allowed in a Wasm module.
    pub max_custom_sections: usize,

    /// Maximum size of the custom sections in bytes.
    pub max_custom_sections_size: NumBytes,

    /// The maximum number of exported functions called `canister_update <name>`,
    /// `canister_query <name>`, or `canister_composite_query <name>`.
    pub max_number_exported_functions: usize,

    /// The maximum sum of `<name>` lengths in exported functions called `canister_update <name>`,
    /// `canister_query <name>`, or `canister_composite_query <name>`.
    pub max_sum_exported_function_name_lengths: usize,

    /// Compiling a single WASM instruction should cost as much as executing
    /// this many instructions.
    pub cost_to_compile_wasm_instruction: NumInstructions,

    /// The number of rayon threads used by wasmtime to compile wasm binaries
    pub num_rayon_compilation_threads: usize,

    /// The number of the rayon threads used for the parallel page copying optimization.
    pub num_rayon_page_allocator_threads: usize,

    /// Flags to enable or disable features that are still experimental.
    pub feature_flags: FeatureFlags,

    /// Instruction counting strategy
    pub metering_type: MeteringType,

    // Maximum number of stable memory pages that a single message execution
    // can access.
    pub stable_memory_accessed_page_limit: StableMemoryPageLimit,

    /// Maximum number of stable memory dirty pages that a single message
    /// execution is allowed to produce.
    pub stable_memory_dirty_page_limit: StableMemoryPageLimit,

    /// Sandbox process eviction does not activate if the number of sandbox
    /// processes is below this threshold.
    pub min_sandbox_count: usize,

    /// Sandbox process eviction ensures that the number of sandbox processes is
    /// always below this threshold.
    pub max_sandbox_count: usize,

    /// A sandbox process may be evicted after it has been idle for this
    /// duration and sandbox process eviction is activated.
    pub max_sandbox_idle_time: Duration,

    /// The type of the local subnet. The default value here should be replaced
    /// with the correct value at runtime when the hypervisor is created.
    pub subnet_type: SubnetType,

    /// Dirty page overhead. The number of instructions to charge for each dirty
    /// page created by a write to stable memory. The default value should be
    /// replaced with the correct value at runtime when the hypervisor is
    /// created.
    pub dirty_page_overhead: NumInstructions,

    /// If this flag is enabled, then execution of a slice will produce a log
    /// entry with the number of executed instructions and the duration.
    pub trace_execution: FlagStatus,

    /// The maximum number of pages that a message dirties without optimizing dirty
    /// page copying by triggering a new execution slice for copying and using prefaulting.
    pub max_dirty_pages_without_optimization: usize,

    /// The dirty page copying overhead, in instructions.
    pub dirty_page_copy_overhead: NumInstructions,

    /// The maximum allowed size for an uncompressed canister Wasm module.
    pub wasm_max_size: NumBytes,

    /// The maximum size of the wasm heap memory.
    pub max_wasm_memory_size: NumBytes,

    /// The maximum size of the stable memory.
    pub max_stable_memory_size: NumBytes,
}

impl Config {
    pub const fn new() -> Self {
        Config {
            query_execution_threads_per_canister: QUERY_EXECUTION_THREADS_PER_CANISTER,
            max_globals: MAX_GLOBALS,
            max_functions: MAX_FUNCTIONS,
            max_custom_sections: MAX_CUSTOM_SECTIONS,
            max_custom_sections_size: MAX_CUSTOM_SECTIONS_SIZE,
            max_number_exported_functions: MAX_NUMBER_EXPORTED_FUNCTIONS,
            max_sum_exported_function_name_lengths: MAX_SUM_EXPORTED_FUNCTION_NAME_LENGTHS,
            cost_to_compile_wasm_instruction: DEFAULT_COST_TO_COMPILE_WASM_INSTRUCTION,
            num_rayon_compilation_threads: DEFAULT_WASMTIME_RAYON_COMPILATION_THREADS,
            num_rayon_page_allocator_threads: DEFAULT_PAGE_ALLOCATOR_THREADS,
            feature_flags: FeatureFlags::const_default(),
            metering_type: MeteringType::New,
            stable_memory_dirty_page_limit: StableMemoryPageLimit {
                message: STABLE_MEMORY_DIRTY_PAGE_LIMIT_MESSAGE,
                upgrade: STABLE_MEMORY_DIRTY_PAGE_LIMIT_UPGRADE,
                query: STABLE_MEMORY_DIRTY_PAGE_LIMIT_QUERY,
            },
            stable_memory_accessed_page_limit: StableMemoryPageLimit {
                message: STABLE_MEMORY_ACCESSED_PAGE_LIMIT_MESSAGE,
                upgrade: STABLE_MEMORY_ACCESSED_PAGE_LIMIT_UPGRADE,
                query: STABLE_MEMORY_ACCESSED_PAGE_LIMIT_QUERY,
            },
            min_sandbox_count: DEFAULT_MIN_SANDBOX_COUNT,
            max_sandbox_count: DEFAULT_MAX_SANDBOX_COUNT,
            max_sandbox_idle_time: DEFAULT_MAX_SANDBOX_IDLE_TIME,
            subnet_type: SubnetType::Application,
            dirty_page_overhead: NumInstructions::new(0),
            trace_execution: FlagStatus::Disabled,
            max_dirty_pages_without_optimization: DEFAULT_MAX_DIRTY_PAGES_WITHOUT_OPTIMIZATION,
            dirty_page_copy_overhead: DIRTY_PAGE_COPY_OVERHEAD,
            wasm_max_size: WASM_MAX_SIZE,
            max_wasm_memory_size: NumBytes::new(MAX_WASM_MEMORY_IN_BYTES),
            max_stable_memory_size: NumBytes::new(MAX_STABLE_MEMORY_IN_BYTES),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}
