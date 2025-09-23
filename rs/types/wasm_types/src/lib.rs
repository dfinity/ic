//! A crate containing types useful for working with Wasm modules on the
//! Internet Computer.
mod errors;

pub use errors::{
    AsErrorHelp, ErrorHelp, WasmEngineError, WasmError, WasmInstrumentationError,
    WasmValidationError, doc_ref,
};
use ic_heap_bytes::DeterministicHeapBytes;
use ic_types::DiskBytes;
use ic_utils::byte_slice_fmt::truncate_and_format;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::ops::DerefMut;
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

/// Represents the current loading state of the canister module storage.
#[derive(Debug, PartialEq, Eq)]
pub enum ModuleLoadingStatus {
    /// The module is stored in memory.
    InMemory,
    /// The module is backed by a file but has been loaded.
    FileLoaded,
    /// The module is backed by a file but has not been loaded yet.
    FileNotLoaded,
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
        len: Option<usize>,
    ) -> std::io::Result<Self> {
        let module = ModuleStorage::from_file(wasm_file_layout, len)?;
        Ok(Self {
            module,
            module_hash: module_hash.0,
        })
    }

    /// Returns if this module is backed by a file
    pub fn is_file(&self) -> bool {
        matches!(self.module, ModuleStorage::File(_))
    }

    /// Overwrite the module at `offset` with `buf`. This may invalidate the
    /// module, and will change its hash. It's useful for uploading a module
    /// chunk by chunk.
    /// Returns an error if `offset` + `buf.len()` > `module.len()`.
    pub fn write(&mut self, buf: &[u8], offset: usize) -> Result<(), String> {
        match self.module.write(buf, offset) {
            Ok(()) => {
                self.module_hash = ic_crypto_sha2::Sha256::hash(self.module.as_slice());
                Ok(())
            }
            Err(e) => Err(e),
        }
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

    /// Returns the loading status of the module storage.
    pub fn module_loading_status(&self) -> ModuleLoadingStatus {
        match &self.module {
            ModuleStorage::Memory(_) => ModuleLoadingStatus::InMemory,
            ModuleStorage::File(file) => {
                if file.is_loaded() {
                    ModuleLoadingStatus::FileLoaded
                } else {
                    ModuleLoadingStatus::FileNotLoaded
                }
            }
        }
    }

    /// Returns `false` if the module is stored in memory, if the file's path does not match,
    /// or if the backing file has already been loaded.
    ///
    /// Note that this method is intended for testing purposes only.
    pub fn wasm_file_not_loaded_and_path_matches(&self, expected_path: &Path) -> bool {
        match &self.module {
            ModuleStorage::Memory(_) => false,
            ModuleStorage::File(file) => file.wasm_file_not_loaded_and_path_matches(expected_path),
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
#[derive(Clone, DeterministicHeapBytes, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
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

impl DiskBytes for WasmHash {}

impl std::fmt::Display for WasmHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Trait representing a Wasm file that can be memory-mapped.
///
/// Implementors **must guarantee** that the path returned by `path()`
/// always points to a valid and accessible file whenever `mmap_file()` is called.
pub trait MemoryMappableWasmFile {
    fn path(&self) -> &Path;

    fn mmap_file(&self) -> std::io::Result<ic_sys::mmap::ScopedMmap> {
        use std::io;
        let f = std::fs::File::open(self.path())?;
        let len = f.metadata()?.len();
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: Wasm file must not be empty", self.path().display()),
            ));
        }
        match ic_sys::mmap::ScopedMmap::from_readonly_file(&f, len as usize) {
            Ok(mmap) => Ok(mmap),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }
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
struct WasmFileStorage {
    len: usize,
    file: Arc<Mutex<Option<Box<dyn MemoryMappableWasmFile + Send + Sync>>>>,
    mmap: Arc<OnceLock<ic_sys::mmap::ScopedMmap>>,
}

impl WasmFileStorage {
    /// The only constructor to creates a new `WasmFileStorage`
    /// that will lazily load the provided wasm file.
    fn lazy_load(
        wasm_file: Box<dyn MemoryMappableWasmFile + Send + Sync>,
        len: Option<usize>,
    ) -> std::io::Result<Self> {
        let len = if let Some(len) = len {
            debug_assert_eq!(
                len,
                std::fs::metadata(wasm_file.path())
                    .expect("Failed to read metadata")
                    .len() as usize,
                "Wasm file length mismatch"
            );
            len
        } else {
            std::fs::metadata(wasm_file.path())?.len() as usize
        };
        Ok(Self {
            len,
            file: Arc::new(Mutex::new(Some(wasm_file))),
            mmap: Arc::new(OnceLock::new()),
        })
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
            let mmap = file.mmap_file().expect("Failed to mmap file");
            debug_assert_eq!(mmap.len(), self.len);
            mmap
        })
    }

    fn is_loaded(&self) -> bool {
        self.mmap.get().is_some()
    }

    fn as_slice(&self) -> &[u8] {
        self.init_or_die().as_slice()
    }

    /// Returns whether the file path backing this storage matches the expected path.
    /// This method avoids exposing the internal path directly and is intended for testing purposes only.
    ///
    /// Returns `false` if the path does not match or if the `file` has been taken out of the mutex,
    /// (i.e., the file has been loaded, and its path is no longer visible).
    fn wasm_file_not_loaded_and_path_matches(&self, expected_path: &Path) -> bool {
        let guard = self.file.lock().unwrap();
        match &*guard {
            Some(file) => file.path() == expected_path,
            None => false,
        }
    }
}

impl ModuleStorage {
    fn from_file(
        file: Box<dyn MemoryMappableWasmFile + Send + Sync>,
        len: Option<usize>,
    ) -> std::io::Result<Self> {
        Ok(Self::File(WasmFileStorage::lazy_load(file, len)?))
    }

    fn as_slice(&self) -> &[u8] {
        match &self {
            Self::Memory(arc) => arc.as_slice(),
            // This is safe because the file is read-only.
            Self::File(file) => file.as_slice(),
        }
    }

    /// Overwrites the module bytes from `offset` with `buf`.
    /// Returns the original module if `offset` + `buf.len()` exceeds the
    /// length of the module.
    ///
    /// This may invalidate the module, but is useful for uploading a
    /// module chunk by chunk.
    fn write(&mut self, buf: &[u8], offset: usize) -> Result<(), String> {
        let end = offset.saturating_add(buf.len());
        if self.len() < end {
            return Err(format!(
                "Offset {} + slice length {} exceeds module length {}.",
                offset,
                buf.len(),
                self.len()
            ));
        }
        let mut arc = match self {
            ModuleStorage::Memory(bytes) => Arc::clone(bytes),
            ModuleStorage::File(file) => Arc::new(file.as_slice().to_vec()),
        };
        let inner = Arc::make_mut(&mut arc);
        inner[offset..end].copy_from_slice(buf);
        *self = ModuleStorage::Memory(arc);
        Ok(())
    }

    fn len(&self) -> usize {
        match &self {
            ModuleStorage::Memory(arc) => arc.len(),
            ModuleStorage::File(file) => file.len,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{CanisterModule, MemoryMappableWasmFile, WASM_HASH_LENGTH, WasmHash};
    use std::path::{Path, PathBuf};
    struct TestWasmFile(PathBuf);
    impl MemoryMappableWasmFile for TestWasmFile {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    #[test]
    fn wasmhash_display() {
        let hash = WasmHash([0; WASM_HASH_LENGTH]);
        let expected: String = "00".repeat(WASM_HASH_LENGTH);
        assert_eq!(expected, format!("{hash}"));
        let hash = WasmHash([11; WASM_HASH_LENGTH]);
        let expected: String = "0b".repeat(WASM_HASH_LENGTH);
        assert_eq!(expected, format!("{hash}"));
        let hash = WasmHash([255; WASM_HASH_LENGTH]);
        let expected: String = "ff".repeat(WASM_HASH_LENGTH);
        assert_eq!(expected, format!("{hash}"));
    }

    #[test]
    fn test_chunk_write_to_module() {
        let original_module = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let original_hash = ic_crypto_sha2::Sha256::hash(original_module.as_slice());
        let chunk_size = 4;
        let mut module = CanisterModule::new(original_module.clone());
        assert_eq!(original_hash, module.module_hash());

        let mut offset = 0;
        for chunk in original_module.chunks(chunk_size) {
            module.write(chunk, offset).unwrap();
            offset += chunk.len();
        }
        assert_eq!(&original_module, module.as_slice());
        assert_eq!(original_hash, module.module_hash());

        module.write(&[1, 2, 3], 999).unwrap_err();
        module
            .write(&[1, 2, 3], original_module.len() - 1)
            .unwrap_err();
        module
            .write(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0)
            .unwrap_err();
    }

    #[test]
    fn test_write_module_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0x00, 0x61, 0x73, 0x6d, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
        let test_wasm_file = TestWasmFile(tmp.path().to_path_buf());
        let mut module =
            CanisterModule::new_from_file(Box::new(test_wasm_file), WasmHash([0; 32]), None)
                .unwrap();
        module.write(&[9], 5).unwrap();
        assert_eq!(
            &[0x00, 0x61, 0x73, 0x6d, 0x00, 0x09, 0x00, 0x00],
            module.as_slice()
        );
    }
}
