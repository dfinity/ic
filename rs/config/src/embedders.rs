use serde::{Deserialize, Serialize};

// Defining 100000 globals in a module can result in significant overhead in
// each message's execution time (about 40x), so set a limit 3 orders of
// magnitude lower which should still allow for reasonable canisters to be
// written (current max number of globals on the Alpha network is 7).
pub(crate) const MAX_GLOBALS: usize = 200;
// Current max number of functions used by a canister on the Alpha network is
// about 2800, so we set a limit at two times that.
pub(crate) const MAX_FUNCTIONS: usize = 6000;

#[derive(Clone, Debug)]
pub struct Config {
    pub persistence_type: PersistenceType,
    pub max_wasm_stack_size: usize,
    pub num_runtime_generic_threads: usize,
    pub num_runtime_query_threads: usize,
    pub max_globals: usize,
    pub max_functions: usize,
}

impl Config {
    pub fn new() -> Self {
        Config {
            persistence_type: PersistenceType::Sigsegv,
            max_wasm_stack_size: 5 * 1024 * 1024,
            num_runtime_generic_threads: 1,
            num_runtime_query_threads: 4,
            max_globals: MAX_GLOBALS,
            max_functions: MAX_FUNCTIONS,
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
