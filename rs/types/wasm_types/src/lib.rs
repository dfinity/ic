//! A crate containing types useful for working with Wasm modules on the
//! Internet Computer.
mod errors;

pub use errors::{
    doc_ref, AsErrorHelp, ErrorHelp, WasmEngineError, WasmError, WasmInstrumentationError,
    WasmValidationError,
};
use ic_types::MemoryDiskBytes;
use ic_utils::byte_slice_fmt::truncate_and_format;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::{fmt, path::Path, sync::Arc};

const WASM_HASH_LENGTH: usize = 32;

/// A newtype for
/// [BinaryEncoded](https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md)
/// Wasm modules used for execution.
#[derive(Clone)]
pub struct BinaryEncodedWasm(Arc<Vec<u8>>);

impl std::fmt::Debug for BinaryEncodedWasm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ignore the actual binary contents when debug formatting.
        f.debug_tuple("BinaryEncodedWasm").finish()
    }
}

impl BinaryEncodedWasm {
    pub fn new(wasm: Vec<u8>) -> Self {
        Self::new_shared(Arc::new(wasm))
    }

    pub fn new_shared(wasm: Arc<Vec<u8>>) -> Self {
        debug_assert!(wasm.starts_with(b"\x00asm"), "Invalid binary encoded wasm");
        Self(wasm)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Canister module stored by the replica.
/// Currently, we support two kinds of modules:
///   * Raw Wasm modules (magic number \0asm)
///   * Gzip-compressed Wasm modules (magic number \1f\8b\08)
// We don't derive `Serialize` and `Deserialize` because this is a binary that is serialized by
// writing it to a file when creating checkpoints.
#[derive(Clone, ValidateEq)]
pub struct CanisterModule {
    // The Wasm binary.
    #[validate_eq(Ignore)]
    module: ModuleStorage,
    // The Sha256 hash of the binary.
    module_hash: [u8; WASM_HASH_LENGTH],
}

impl CanisterModule {
    pub fn new(bytes: Vec<u8>) -> Self {
        let module = ModuleStorage::Memory(Arc::new(bytes));
        let module_hash = ic_crypto_sha2::Sha256::hash(module.as_slice());
        Self {
            module,
            module_hash,
        }
    }

    pub fn new_from_file(
        wasm_file_layout: Box<dyn MemoryMappableWasmFile + Send + Sync>,
        module_hash: WasmHash,
    ) -> Self {
        let module = ModuleStorage::from_file(wasm_file_layout);
        Self {
            module,
            module_hash: module_hash.0,
        }
    }

    /// If this module is backed by a file, return the path to that file.
    pub fn file(&self) -> Option<&Path> {
        match &self.module {
            ModuleStorage::Memory(_) => None,
            ModuleStorage::File(storage) => Some(&storage.path),
        }
    }

    /// If this module is backed by a file, return the path to that file.
    pub fn is_file(&self) -> bool {
        matches!(self.module, ModuleStorage::File(_))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.module.as_slice()
    }

    pub fn len(&self) -> usize {
        self.module.len()
    }

    pub fn is_empty(&self) -> bool {
        self.module.len() == 0
    }

    pub fn to_shared_vec(&self) -> Arc<Vec<u8>> {
        match &self.module {
            ModuleStorage::Memory(shared) => Arc::clone(shared),
            ModuleStorage::File(_) => Arc::new(self.as_slice().to_vec()),
        }
    }

    /// Returns the Sha256 hash of this Wasm module.
    pub fn module_hash(&self) -> [u8; WASM_HASH_LENGTH] {
        self.module_hash
    }

    pub fn file_loading_status(&self) -> Option<bool> {
        match &self.module {
            ModuleStorage::Memory(_) => None,
            ModuleStorage::File(storage) => Some(storage.is_loaded()),
        }
    }
}

impl fmt::Debug for CanisterModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "CanisterModule{{{}}}",
            truncate_and_format(self.as_slice(), 40_usize)
        ))
    }
}

impl PartialEq for CanisterModule {
    fn eq(&self, other: &Self) -> bool {
        self.module_hash() == other.module_hash()
    }
}

impl Eq for CanisterModule {}

impl std::hash::Hash for CanisterModule {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

/// The hash of an __uninstrumented__ canister wasm.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct WasmHash([u8; WASM_HASH_LENGTH]);

impl WasmHash {
    pub fn to_slice(&self) -> [u8; WASM_HASH_LENGTH] {
        self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<&CanisterModule> for WasmHash {
    fn from(item: &CanisterModule) -> Self {
        Self(item.module_hash())
    }
}

impl From<[u8; WASM_HASH_LENGTH]> for WasmHash {
    fn from(item: [u8; WASM_HASH_LENGTH]) -> Self {
        Self(item)
    }
}

impl TryFrom<Vec<u8>> for WasmHash {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let array: [u8; WASM_HASH_LENGTH] = value.try_into()?;
        Ok(Self::from(array))
    }
}

impl MemoryDiskBytes for WasmHash {
    fn memory_bytes(&self) -> usize {
        self.0.len()
    }

    fn disk_bytes(&self) -> usize {
        0
    }
}

impl std::fmt::Display for WasmHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        for byte in self.0 {
            write!(f, "{:2x}", byte)?;
        }
        Ok(())
    }
}

#[test]
fn wasmhash_display() {
    let hash = WasmHash([0; WASM_HASH_LENGTH]);
    let expected: String = "00".repeat(WASM_HASH_LENGTH);
    assert_eq!(expected, format!("{}", hash));
    let hash = WasmHash([11; WASM_HASH_LENGTH]);
    let expected: String = "0b".repeat(WASM_HASH_LENGTH);
    assert_eq!(expected, format!("{}", hash));
    let hash = WasmHash([255; WASM_HASH_LENGTH]);
    let expected: String = "ff".repeat(WASM_HASH_LENGTH);
    assert_eq!(expected, format!("{}", hash));
}

/// Trait representing a Wasm file that can be memory-mapped.
///
/// Implementors **must guarantee** that the path returned by `path()`
/// always points to a valid and accessible file whenever `mmap_file()` is called.
pub trait MemoryMappableWasmFile {
    fn mmap_file(&self) -> std::io::Result<ic_sys::mmap::ScopedMmap>;

    fn path(&self) -> &Path;
}

// We introduce another enum instead of making `BinaryEncodedWasm` an enum to
// keep constructors private. We want `BinaryEncodedWasm` to be visible, but not
// its structure.
#[derive(Clone)]
enum ModuleStorage {
    Memory(Arc<Vec<u8>>),
    File(WasmFileStorage),
}

/// Lazily loaded memory-mapped representation of a wasm file.
///
/// The `file` field points to a wasm file on disk. The file is memory-mapped
/// on first access and the resulting `mmap` is stored in a `OnceLock`, which is
/// never cleared until the struct is dropped. After initialization, the `file`
/// field is no longer accessed.
///
/// The only constructor, `lazy_load`, guarantees that the `file` field is
/// populated when the first access occurs.
#[derive(Clone)]
pub struct WasmFileStorage {
    path: PathBuf,
    file: Arc<Mutex<Option<Box<dyn MemoryMappableWasmFile + Send + Sync>>>>,
    mmap: Arc<OnceLock<ic_sys::mmap::ScopedMmap>>,
}

impl WasmFileStorage {
    /// The only constructor to creates a new `WasmFileStorage`
    /// that will lazily load the provided wasm file.
    pub fn lazy_load(wasm_file: Box<dyn MemoryMappableWasmFile + Send + Sync>) -> Self {
        Self {
            path: wasm_file.path().to_path_buf(),
            file: Arc::new(Mutex::new(Some(wasm_file))),
            mmap: Arc::new(OnceLock::new()),
        }
    }

    /// Returns a reference to the mmap, initializing it on first access.
    ///
    /// This method memory-maps the file the first time it's called, which
    /// consumes the 'file' field and stores the result in a `OnceLock`.
    ///
    /// Panics if the `file` has already been taken or if mapping the file fails.
    fn init_or_die(&self) -> &ic_sys::mmap::ScopedMmap {
        self.mmap.get_or_init(|| {
            let mut file = self.file.lock().expect("Failed to lock wasm file layout");
            // We need to take the file out of the mutex to drop `CheckpointLayout` it holds and avoiding keeping the checkpoint for too long.
            let file = file
                .deref_mut()
                .take()
                .expect("WasmFileStorage::init_or_die: file already taken");
            file.mmap_file().expect("Failed to mmap file")
        })
    }

    pub fn is_loaded(&self) -> bool {
        self.mmap.get().is_some()
    }

    fn as_slice(&self) -> &[u8] {
        self.init_or_die().as_slice()
    }

    fn len(&self) -> usize {
        self.init_or_die().len()
    }
}

impl ModuleStorage {
    fn from_file(file: Box<dyn MemoryMappableWasmFile + Send + Sync>) -> Self {
        Self::File(WasmFileStorage::lazy_load(file))
    }

    fn as_slice(&self) -> &[u8] {
        match &self {
            Self::Memory(arc) => arc.as_slice(),
            // This is safe because the file is read-only.
            Self::File(file) => file.as_slice(),
        }
    }

    fn len(&self) -> usize {
        match &self {
            ModuleStorage::Memory(arc) => arc.len(),
            ModuleStorage::File(file) => file.len(),
        }
    }
}
