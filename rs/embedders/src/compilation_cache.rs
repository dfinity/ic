use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::SerializedModule;
use ic_config::flag_status::FlagStatus;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_wasm_types::{CanisterModule, WasmHash};

/// Stores the serialized modules of wasm code that has already been compiled so
/// that it can be used again without recompiling.
pub struct CompilationCache {
    enabled: FlagStatus,
    cache: RwLock<HashMap<WasmHash, HypervisorResult<Arc<SerializedModule>>>>,
}

impl CompilationCache {
    pub fn new(enabled: FlagStatus) -> Self {
        Self {
            enabled,
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(
        &self,
        canister_module: &CanisterModule,
        serialized_module: HypervisorResult<Arc<SerializedModule>>,
    ) {
        if self.enabled == FlagStatus::Enabled {
            self.cache
                .write()
                .unwrap()
                .insert(WasmHash::from(canister_module), serialized_module);
        }
    }

    pub fn get(
        &self,
        canister_module: &CanisterModule,
    ) -> Option<HypervisorResult<Arc<SerializedModule>>> {
        if self.enabled == FlagStatus::Enabled {
            self.cache
                .read()
                .unwrap()
                .get(&WasmHash::from(canister_module))
                .map(|o| o.as_ref().map(Arc::clone).map_err(|e| e.clone()))
        } else {
            None
        }
    }

    #[doc(hidden)]
    pub fn clear_for_testing(&self) {
        self.cache.write().unwrap().clear()
    }
}
