use std::{
    collections::BTreeSet,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::{
    wasm_utils::{InstrumentationOutput, Segments, WasmImportsDetails, WasmValidationDetails},
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

    pub fn insert_err(&self, canister_module: &CanisterModule, err: HypervisorError) {
        match self {
            Self::Memory { cache } => {
                cache
                    .lock()
                    .unwrap()
                    .push(WasmHash::from(canister_module), Err(err));
            }
            Self::Disk { dir: _, cache } => {
                cache
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
            Self::Disk { dir, cache } => {
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
                cache.lock().unwrap().push(hash, Ok(on_disk.clone()));
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
            Self::Disk { dir: _, cache } => cache
                .lock()
                .unwrap()
                .get(&WasmHash::from(canister_module))
                .map(|o| match o {
                    Ok(m) => Ok(StoredCompilation::Disk(m.clone())),
                    Err(e) => Err(e.clone()),
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

pub enum StoredCompilation {
    Memory(Arc<SerializedModule>),
    Disk(OnDiskSerializedModule),
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

    // TODO fix these so that we don't read the file many times (if we actually use them in prod).
    pub fn exported_functions(&self) -> BTreeSet<WasmMethod> {
        match self {
            Self::Memory(module) => module.exported_functions.clone(),
            Self::Disk(module) => module.into_serialized_module().exported_functions,
        }
    }

    pub fn data_segments(&self) -> Segments {
        match self {
            Self::Memory(module) => module.data_segments.clone(),
            Self::Disk(module) => module.into_serialized_module().data_segments,
        }
    }

    pub fn wasm_metadata(&self) -> WasmMetadata {
        match self {
            Self::Memory(module) => module.wasm_metadata.clone(),
            Self::Disk(module) => module.into_serialized_module().wasm_metadata,
        }
    }
}
