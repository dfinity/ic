use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::SerializedModule;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_wasm_types::{CanisterModule, WasmHash};

/// Stores the serialized modules of wasm code that has already been compiled so
/// that it can be used again without recompiling.
#[derive(Default)]
pub struct CompilationCache {
    cache: RwLock<HashMap<WasmHash, HypervisorResult<Arc<SerializedModule>>>>,
}

impl CompilationCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &self,
        canister_module: &CanisterModule,
        serialized_module: HypervisorResult<Arc<SerializedModule>>,
    ) {
        self.cache
            .write()
            .unwrap()
            .insert(WasmHash::from(canister_module), serialized_module);
    }

    pub fn get(
        &self,
        canister_module: &CanisterModule,
    ) -> Option<HypervisorResult<Arc<SerializedModule>>> {
        self.cache
            .read()
            .unwrap()
            .get(&WasmHash::from(canister_module))
            .map(|o| o.as_ref().map(Arc::clone).map_err(|e| e.clone()))
    }

    #[doc(hidden)]
    pub fn clear_for_testing(&self) {
        self.cache.write().unwrap().clear()
    }
}
