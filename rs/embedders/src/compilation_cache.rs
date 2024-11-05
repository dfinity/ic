use std::{
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::{OnDiskSerializedModule, SerializedModule};
use ic_interfaces::execution_environment::HypervisorResult;
use ic_types::NumBytes;
use ic_utils_lru_cache::LruCache;
use ic_wasm_types::{CanisterModule, WasmHash};

/// Stores the serialized modules of wasm code that has already been compiled so
/// that it can be used again without recompiling.
pub enum CompilationCache {
    Memory {
        cache: Mutex<LruCache<WasmHash, HypervisorResult<Arc<SerializedModule>>>>,
    },
    Disk {
        dir: PathBuf,
        /// Map from wasm hash to an open fd with the serialized Module result.
        cache: Mutex<LruCache<WasmHash, HypervisorResult<OnDiskSerializedModule>>>,
    },
}

impl CompilationCache {
    pub fn new(capacity: NumBytes) -> Self {
        Self::Memory {
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub fn new_on_disk(dir: PathBuf, capacity: NumBytes) -> Self {
        Self::Disk {
            dir,
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub fn insert(
        &self,
        canister_module: &CanisterModule,
        serialized_module: HypervisorResult<Arc<SerializedModule>>,
    ) {
        match self {
            Self::Memory { cache } => {
                cache
                    .lock()
                    .unwrap()
                    .push(WasmHash::from(canister_module), serialized_module);
            }
            Self::Disk { dir, cache } => match serialized_module {
                Ok(serialized_module) => {
                    let hash = WasmHash::from(canister_module);
                    let mut bytes_path = dir.clone();
                    bytes_path.push(format!("{}.bytes", hash));
                    let bytes_file = File::create(bytes_path).unwrap();
                    let mut initial_data_path = dir.clone();
                    initial_data_path.push(format!("{}.initial_data", hash));
                    let initial_data_file = File::create(initial_data_path).unwrap();

                    let on_disk = OnDiskSerializedModule::from_serialized_module(
                        &serialized_module,
                        bytes_file,
                        initial_data_file,
                    );
                    cache.lock().unwrap().push(hash, Ok(on_disk));
                }
                Err(e) => {
                    cache
                        .lock()
                        .unwrap()
                        .push(WasmHash::from(canister_module), Err(e));
                }
            },
        }
    }

    pub fn get(
        &self,
        canister_module: &CanisterModule,
    ) -> Option<HypervisorResult<Arc<SerializedModule>>> {
        match self {
            Self::Memory { cache } => cache
                .lock()
                .unwrap()
                .get(&WasmHash::from(canister_module))
                .map(|o| o.clone().map_err(|e| e.clone())),
            Self::Disk { dir: _, cache } => cache
                .lock()
                .unwrap()
                .get(&WasmHash::from(canister_module))
                .map(|o| {
                    o.as_ref()
                        .map_err(|e| e.clone())
                        .map(|s| Arc::new(s.into_serialized_module()))
                }),
        }
    }

    #[doc(hidden)]
    pub fn clear_for_testing(&self) {
        match self {
            Self::Memory { cache } => cache.lock().unwrap().clear(),
            Self::Disk { dir: _, cache } => cache.lock().unwrap().clear(),
        }
    }
}
