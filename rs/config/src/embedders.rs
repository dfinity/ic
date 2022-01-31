use serde::{Deserialize, Serialize};

use crate::flag_status::FlagStatus;
use ic_base_types::NumBytes;

// Defining 100000 globals in a module can result in significant overhead in
// each message's execution time (about 40x), so set a limit 3 orders of
// magnitude lower which should still allow for reasonable canisters to be
// written (current max number of globals on the Alpha network is 7).
pub(crate) const MAX_GLOBALS: usize = 200;
// Current max number of functions used by a canister on the Alpha network is
// about 2800, so we set a limit at two times that.
pub(crate) const MAX_FUNCTIONS: usize = 6000;
// The maximum number of custom sections allowed in a wasm module.
pub(crate) const MAX_CUSTOM_SECTIONS: usize = 16;
// The maximum size of a custom section in bytes.
// Maximum 1 MiB is allowed per canister for the custom sections.
// Thus maximum size per custom section is 1 MiB / MAX_CUSTOM_SECTIONS.
pub(crate) const MAX_CUSTOM_SECTION_SIZE: NumBytes = NumBytes::new(65536);
/// The number of threads to use for query execution.
pub(crate) const QUERY_EXECUTION_THREADS: usize = 2;
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeatureFlags {
    pub api_cycles_u128_flag: FlagStatus,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            api_cycles_u128_flag: FlagStatus::Enabled,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub persistence_type: PersistenceType,
    pub max_wasm_stack_size: usize,
    pub query_execution_threads: usize,

    /// Maximum number of globals allowed in a Wasm module.
    pub max_globals: usize,

    /// Maximum number of functions allowed in a Wasm module.
    pub max_functions: usize,

    /// Maximum number of custom sections allowed in a Wasm module.
    pub max_custom_sections: usize,

    /// Maximum size of a custom section in bytes.
    pub max_custom_section_size: NumBytes,

    /// Flags to enable or disable features that are still experimental.
    pub feature_flags: FeatureFlags,
}

impl Config {
    pub fn new() -> Self {
        Config {
            persistence_type: PersistenceType::Sigsegv,
            max_wasm_stack_size: 5 * 1024 * 1024,
            query_execution_threads: QUERY_EXECUTION_THREADS,
            max_globals: MAX_GLOBALS,
            max_functions: MAX_FUNCTIONS,
            max_custom_sections: MAX_CUSTOM_SECTIONS,
            max_custom_section_size: MAX_CUSTOM_SECTION_SIZE,
            feature_flags: FeatureFlags::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceType {
    Sigsegv,
    Pagemap,
}
