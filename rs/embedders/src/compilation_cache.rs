use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use tempfile::TempDir;

use crate::{
    wasm_utils::{Segments, WasmImportsDetails},
    OnDiskSerializedModule, SerializedModule,
};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_replicated_state::canister_state::execution_state::WasmMetadata;
use ic_types::{methods::WasmMethod, NumBytes, NumInstructions};
use ic_utils_lru_cache::LruCache;
use ic_wasm_types::{CanisterModule, WasmHash};

/// Stores the serialized modules of wasm code that has already been compiled so
/// that it can be used again without recompiling.
pub enum CompilationCache {
    Memory {
        cache: Mutex<LruCache<WasmHash, HypervisorResult<Arc<SerializedModule>>>>,
    },
    Disk {
        /// Directory holding all the temporary files. It will be deleted on
        /// drop.
        dir: TempDir,
        /// Map from wasm hash to an open fd with the serialized Module result.
        cache: Mutex<LruCache<WasmHash, HypervisorResult<Arc<OnDiskSerializedModule>>>>,
    },
}

impl CompilationCache {
    pub fn new(capacity: NumBytes) -> Self {
        // TODO: switch back to memory before merging.
        Self::Disk {
            dir: tempfile::tempdir().unwrap(),
            cache: Mutex::new(LruCache::new(capacity)),
        }
        // Self::Memory {
        //     cache: Mutex::new(LruCache::new(capacity)),
        // }
    }

    pub fn insert_err(&self, canister_module: &CanisterModule, err: HypervisorError) {
        match self {
            Self::Memory { cache } => {
                cache
                    .lock()
                    .unwrap()
                    .push(WasmHash::from(canister_module), Err(err));
            }
            Self::Disk { cache, .. } => {
                let _ = cache
                    .lock()
                    .unwrap()
                    .push(WasmHash::from(canister_module), Err(err));
            }
        }
    }

    pub fn insert_ok(
        &self,
        canister_module: &CanisterModule,
        serialized_module: SerializedModule,
    ) -> StoredCompilation {
        match self {
            Self::Memory { cache } => {
                let serialized_module = Arc::new(serialized_module);
                let copy = Arc::clone(&serialized_module);
                cache
                    .lock()
                    .unwrap()
                    .push(WasmHash::from(canister_module), Ok(serialized_module));
                StoredCompilation::Memory(copy)
            }
            Self::Disk { dir, cache, .. } => {
                let hash = WasmHash::from(canister_module);
                let mut bytes_path: PathBuf = dir.path().into();
                bytes_path.push(format!("{}.module_bytes", hash));
                let mut initial_state_path: PathBuf = dir.path().into();
                initial_state_path.push(format!("{}.initial_data", hash));

                let on_disk = Arc::new(OnDiskSerializedModule::from_serialized_module(
                    serialized_module,
                    &bytes_path,
                    &initial_state_path,
                ));

                let _ = cache.lock().unwrap().push(hash, Ok(Arc::clone(&on_disk)));
                StoredCompilation::Disk(on_disk)
            }
        }
    }

    pub fn get(
        &self,
        canister_module: &CanisterModule,
    ) -> Option<HypervisorResult<StoredCompilation>> {
        match self {
            Self::Memory { cache } => cache
                .lock()
                .unwrap()
                .get(&WasmHash::from(canister_module))
                .map(|o| match o {
                    Ok(m) => Ok(StoredCompilation::Memory(Arc::clone(m))),
                    Err(e) => Err(e.clone()),
                }),
            Self::Disk { cache, .. } => cache
                .lock()
                .unwrap()
                .get(&WasmHash::from(canister_module))
                .map(|o| match o {
                    Ok(m) => Ok(StoredCompilation::Disk(Arc::clone(m))),
                    Err(e) => Err(e.clone()),
                }),
        }
    }

    #[doc(hidden)]
    pub fn clear_for_testing(&self) {
        match self {
            Self::Memory { cache } => cache.lock().unwrap().clear(),
            Self::Disk { cache, .. } => cache.lock().unwrap().clear(),
        }
    }
}

pub enum StoredCompilation {
    Memory(Arc<SerializedModule>),
    Disk(Arc<OnDiskSerializedModule>),
}

impl StoredCompilation {
    pub fn imports_details(&self) -> WasmImportsDetails {
        match self {
            Self::Memory(module) => module.imports_details,
            Self::Disk(module) => module.imports_details,
        }
    }

    pub fn compilation_cost(&self) -> NumInstructions {
        match self {
            Self::Memory(module) => module.compilation_cost,
            Self::Disk(module) => module.compilation_cost,
        }
    }

    pub fn is_wasm64(&self) -> bool {
        match self {
            Self::Memory(module) => module.is_wasm64,
            Self::Disk(module) => module.is_wasm64,
        }
    }

    /// Reads data from disk if needed.
    pub fn exports_and_metadata(&self) -> (BTreeSet<WasmMethod>, WasmMetadata) {
        match self {
            Self::Memory(module) => (
                module.exported_functions.clone(),
                module.wasm_metadata.clone(),
            ),
            Self::Disk(module) => {
                let initial_state_data = module.initial_state_data();
                (
                    initial_state_data.exported_functions,
                    initial_state_data.wasm_metadata,
                )
            }
        }
    }

    /// Reads data from disk if needed.
    pub fn data_segments(&self) -> Segments {
        match self {
            Self::Memory(module) => module.data_segments.clone(),
            Self::Disk(module) => module.initial_state_data().data_segments,
        }
    }
}
