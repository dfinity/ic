//! A crate containing types useful for working with Wasm modules on the
//! Internet Computer.
mod errors;

pub use errors::{ParityWasmError, WasmInstrumentationError, WasmValidationError};
use ic_utils::byte_slice_fmt::truncate_and_format;
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

/// A newtype for
/// [BinaryEncoded](https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md)
/// Wasm modules.
//
// We don't derive `Serialize` and `Deserialize` because this is a binary that is serialized by
// writing it to a file when creating checkpoints.
#[derive(Clone)]
pub struct BinaryEncodedWasm {
    // The Wasm binary.
    wasm: WasmStorage,
    // The Sha256 hash of the binary.
    wasm_hash: [u8; 32],
}

impl BinaryEncodedWasm {
    pub fn new(bytes: Vec<u8>) -> Self {
        let wasm = WasmStorage::Memory(Arc::new(bytes));
        let wasm_hash = ic_crypto_sha256::Sha256::hash(wasm.as_slice());
        Self { wasm, wasm_hash }
    }

    pub fn new_from_file(path: PathBuf) -> std::io::Result<Self> {
        let wasm = WasmStorage::mmap_file(path)?;
        let wasm_hash = ic_crypto_sha256::Sha256::hash(wasm.as_slice());
        Ok(Self { wasm, wasm_hash })
    }

    pub fn file(&self) -> Option<&Path> {
        match &self.wasm {
            WasmStorage::Memory(_) => None,
            WasmStorage::File(path, _) => Some(path),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.wasm.as_slice()
    }

    pub fn len(&self) -> usize {
        self.wasm.len()
    }

    pub fn is_empty(&self) -> bool {
        self.wasm.len() == 0
    }

    /// Returns the Sha256 hash of this Wasm module.
    pub fn hash_sha256(&self) -> [u8; 32] {
        self.wasm_hash
    }
}

impl fmt::Debug for BinaryEncodedWasm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "BinaryEncodedWasm{{{}}}",
            truncate_and_format(self.as_slice(), 40_usize)
        ))
    }
}

impl PartialEq for BinaryEncodedWasm {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for BinaryEncodedWasm {}

impl std::hash::Hash for BinaryEncodedWasm {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

// We introduce another enum instead of making `BinaryEncodedWasm` an enum to
// keep constructors private. We want `BinaryEncodedWasm` to be visible, but not
// its structure.
#[derive(Clone)]
enum WasmStorage {
    Memory(Arc<Vec<u8>>),
    File(PathBuf, Arc<ic_sys::mmap::ScopedMmap>),
}

impl WasmStorage {
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
        match ic_sys::mmap::ScopedMmap::from_readonly_file(f, len as usize) {
            Ok(mmap) => Ok(Self::File(path, Arc::new(mmap))),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match &self {
            WasmStorage::Memory(arc) => arc.as_slice(),
            // This is safe because the file is read-only.
            WasmStorage::File(_, mmap) => mmap.as_slice(),
        }
    }

    fn len(&self) -> usize {
        match &self {
            WasmStorage::Memory(arc) => arc.len(),
            WasmStorage::File(_, mmap) => mmap.len(),
        }
    }
}
