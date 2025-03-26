use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use tempfile::TempDir;

use crate::{
    wasm_utils::{Segments, WasmImportsDetails},
    OnDiskSerializedModule, SerializedModule,
};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_replicated_state::canister_state::execution_state::WasmMetadata;
use ic_types::{methods::WasmMethod, MemoryDiskBytes, NumBytes, NumInstructions};
use ic_utils_lru_cache::LruCache;
use ic_wasm_types::{CanisterModule, WasmHash};

const GB: u64 = 1024 * 1024 * 1024;

/// Each entry holds two file descriptors, so this will limit us to 1M total
/// descriptors used by the cache.
const DEFAULT_MAX_ENTRIES: usize = 500_000;

/// 100 GiB should be plenty. Otherwise a large portion of subnet memory would
/// be in Wasm code even though the x86 is a bit larger.
const DEFAULT_DISK_CAPACITY: NumBytes = NumBytes::new(100 * GB);

/// 10 GiB is already more than we can support with the entry count limit anyway.
const DEFAULT_MEMORY_CAPACITY: NumBytes = NumBytes::new(10 * GB);

/// Stores the serialized modules of wasm code that has already been compiled so
/// that it can be used again without recompiling.
pub enum CompilationCache {
    // TODO(EXC-1991): Deprecate in memory version.
    Memory {
        cache: Mutex<LruCache<WasmHash, HypervisorResult<Arc<SerializedModule>>>>,
    },
    Disk {
        /// Directory holding all the temporary files. It will be deleted on
        /// drop.
        dir: TempDir,
        /// Map from wasm hash to an open fd with the serialized Module result.
        cache: Mutex<LruCache<WasmHash, HypervisorResult<Arc<OnDiskSerializedModule>>>>,
        /// Atomic counter to deduplicate files in the case of concurrent compilations of the same module.
        counter: AtomicU64,
        /// Limit on the total number of entries in the cache.
        max_entries: usize,
    },
}

impl MemoryDiskBytes for CompilationCache {
    fn memory_bytes(&self) -> usize {
        match self {
            CompilationCache::Memory { cache } => cache.lock().unwrap().memory_bytes(),
            CompilationCache::Disk { cache, .. } => cache.lock().unwrap().memory_bytes(),
        }
    }

    fn disk_bytes(&self) -> usize {
        match self {
            CompilationCache::Memory { cache } => cache.lock().unwrap().disk_bytes(),
            CompilationCache::Disk { cache, .. } => cache.lock().unwrap().disk_bytes(),
        }
    }
}

pub struct CompilationCacheBuilder {
    memory_capacity: NumBytes,
    disk_capacity: NumBytes,
    dir: Option<TempDir>,
    max_entries: usize,
}

impl Default for CompilationCacheBuilder {
    fn default() -> Self {
        Self::new()
    }
}
impl CompilationCacheBuilder {
    pub fn new() -> Self {
        Self {
            memory_capacity: DEFAULT_MEMORY_CAPACITY,
            disk_capacity: DEFAULT_DISK_CAPACITY,
            dir: None,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    pub fn with_memory_capacity(mut self, memory_capacity: NumBytes) -> Self {
        self.memory_capacity = memory_capacity;
        self
    }

    pub fn with_disk_capacity(mut self, disk_capacity: NumBytes) -> Self {
        self.disk_capacity = disk_capacity;
        self
    }

    pub fn with_dir(mut self, dir: TempDir) -> Self {
        self.dir = Some(dir);
        self
    }

    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    pub fn build(self) -> CompilationCache {
        let dir = self.dir.unwrap_or_else(|| tempfile::tempdir().unwrap());
        CompilationCache::Disk {
            dir,
            cache: Mutex::new(LruCache::new(self.memory_capacity, self.disk_capacity)),
            counter: AtomicU64::new(0),
            max_entries: self.max_entries,
        }
    }
}

impl CompilationCache {
    pub fn insert_err(&self, canister_module: &CanisterModule, err: HypervisorError) {
        match self {
            Self::Memory { cache } => {
                let _ = cache
                    .lock()
                    .unwrap()
                    .push(WasmHash::from(canister_module), Err(err));
            }
            Self::Disk {
                cache, max_entries, ..
            } => {
                let mut cache = cache.lock().unwrap();
                if cache.len() >= *max_entries {
                    let _ = cache.pop_lru();
                }
                let _ = cache.push(WasmHash::from(canister_module), Err(err));
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
                let _ = cache
                    .lock()
                    .unwrap()
                    .push(WasmHash::from(canister_module), Ok(serialized_module));
                StoredCompilation::Memory(copy)
            }
            Self::Disk {
                dir,
                cache,
                counter,
                max_entries,
                ..
            } => {
                // The file paths must not have existing files. To ensure this
                // we add a unique counter - otherwise concurent insertions for
                // the same Wasm would use the same file.
                let hash = WasmHash::from(canister_module);
                let id = counter.fetch_add(1, Ordering::SeqCst);
                let mut bytes_path: PathBuf = dir.path().into();
                bytes_path.push(format!("{}-{}.module_bytes", hash, id));
                let mut initial_state_path: PathBuf = dir.path().into();
                initial_state_path.push(format!("{}-{}.initial_data", hash, id));

                let on_disk = Arc::new(OnDiskSerializedModule::from_serialized_module(
                    serialized_module,
                    &bytes_path,
                    &initial_state_path,
                ));

                let mut cache = cache.lock().unwrap();
                if cache.len() >= *max_entries {
                    let _ = cache.pop_lru();
                }
                let _ = cache.push(hash, Ok(Arc::clone(&on_disk)));
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

/// Check that multiple threads compiling the same wasm won't interfere with
/// each other if they all try to insert in the cache at the same time.
#[test]
fn concurrent_insertions() {
    let cache = CompilationCacheBuilder::new().build();
    let wasm = wat::parse_str("(module)").unwrap();
    let canister_module = CanisterModule::new(wasm.clone());
    let binary = ic_wasm_types::BinaryEncodedWasm::new(wasm.clone());
    let config = ic_config::embedders::Config::default();
    let embedder = crate::WasmtimeEmbedder::new(config, ic_logger::no_op_logger());
    let (_, result) = crate::wasm_utils::compile(&embedder, &binary);
    let serialized_module = result.unwrap().1;

    std::thread::scope(|s| {
        let mut threads = vec![];
        for _ in 0..100 {
            let serialized_module = serialized_module.clone();
            threads.push(s.spawn(|| {
                let _ = cache.insert_ok(&canister_module, serialized_module);
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
    })
}
