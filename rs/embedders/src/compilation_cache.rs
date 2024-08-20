use std::sync::{Arc, Mutex};

use crate::SerializedModule;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_types::NumBytes;
use ic_utils_lru_cache::LruCache;
use ic_wasm_types::{CanisterModule, WasmHash};

/// Stores the serialized modules of wasm code that has already been compiled so
/// that it can be used again without recompiling.
pub struct CompilationCache {
    cache: Mutex<LruCache<WasmHash, HypervisorResult<Arc<SerializedModule>>>>,
}

impl CompilationCache {
    pub fn new(capacity: NumBytes) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub fn insert(
        &self,
        canister_module: &CanisterModule,
        serialized_module: HypervisorResult<Arc<SerializedModule>>,
    ) {
        self.cache
            .lock()
            .unwrap()
            .push(WasmHash::from(canister_module), serialized_module);
    }

    pub fn get(
        &self,
        canister_module: &CanisterModule,
    ) -> Option<HypervisorResult<Arc<SerializedModule>>> {
        self.cache
            .lock()
            .unwrap()
            .get(&WasmHash::from(canister_module))
            .map(|o| o.clone().map_err(|e| e.clone()))
    }

    #[doc(hidden)]
    pub fn clear_for_testing(&self) {
        self.cache.lock().unwrap().clear()
    }
}
