//! A crate containing types useful for working with Wasm modules on the
//! Internet Computer.
mod errors;

pub use errors::{
    AsErrorHelp, ErrorHelp, WasmEngineError, WasmError, WasmInstrumentationError,
    WasmValidationError,
};
use ic_types::CountBytes;
use ic_utils::byte_slice_fmt::truncate_and_format;
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

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
#[derive(Clone)]
pub struct CanisterModule {
    // The Wasm binary.
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

    pub fn new_from_file(path: PathBuf, module_hash: Option<WasmHash>) -> std::io::Result<Self> {
        let module = ModuleStorage::mmap_file(path)?;
        // It should only be necessary to compute the hash here when
        // loading checkpoints written by older replica versions
        let module_hash =
            module_hash.map_or_else(|| ic_crypto_sha2::Sha256::hash(module.as_slice()), |h| h.0);
        Ok(Self {
            module,
            module_hash,
        })
    }

    /// If this module is backed by a file, return the path to that file.
    pub fn file(&self) -> Option<&Path> {
        match &self.module {
            ModuleStorage::Memory(_) => None,
            ModuleStorage::File(path, _) => Some(path),
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
            ModuleStorage::File(_, _) => Arc::new(self.as_slice().to_vec()),
        }
    }

    /// Returns the Sha256 hash of this Wasm module.
    pub fn module_hash(&self) -> [u8; WASM_HASH_LENGTH] {
        self.module_hash
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

impl CountBytes for WasmHash {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

// We introduce another enum instead of making `BinaryEncodedWasm` an enum to
// keep constructors private. We want `BinaryEncodedWasm` to be visible, but not
// its structure.
#[derive(Clone)]
enum ModuleStorage {
    Memory(Arc<Vec<u8>>),
    File(PathBuf, Arc<ic_sys::mmap::ScopedMmap>),
}

impl ModuleStorage {
    fn mmap_file(path: PathBuf) -> std::io::Result<Self> {
        use std::io;

        let f = std::fs::File::open(&path)?;
        let len = f.metadata()?.len();
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: Wasm file must not be empty", path.display()),
            ));
        }
        match ic_sys::mmap::ScopedMmap::from_readonly_file(&f, len as usize) {
            Ok(mmap) => Ok(Self::File(path, Arc::new(mmap))),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match &self {
            Self::Memory(arc) => arc.as_slice(),
            // This is safe because the file is read-only.
            Self::File(_, mmap) => mmap.as_slice(),
        }
    }

    fn len(&self) -> usize {
        match &self {
            ModuleStorage::Memory(arc) => arc.len(),
            ModuleStorage::File(_, mmap) => mmap.len(),
        }
    }
}
