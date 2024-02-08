use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    sync::atomic::{AtomicUsize, Ordering},
};

/// The identifier of a message execution. It must be unique per sandbox
/// process. The current implementation provides stronger guarantee:
/// it is unique across all canisters.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecId(usize);

impl ExecId {
    /// Only the replica process is supposed to create new `ExecId`.
    pub fn new() -> Self {
        static MONOTONICALLY_INCREASING_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = MONOTONICALLY_INCREASING_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self(id)
    }
}

impl Default for ExecId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for ExecId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exec-id-{}", self.0)
    }
}

/// The identifier of a memory. It must be unique per sandbox process.
/// The current implementation provides stronger guarantee: it is unique across
/// all canisters.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryId(usize);

impl MemoryId {
    /// Only the replica process is supposed to create new `StateId`.
    pub fn new() -> Self {
        static MONOTONICALLY_INCREASING_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = MONOTONICALLY_INCREASING_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self(id)
    }

    /// The conversion from and to `usize` is necessary because `Memory` needs
    /// to refer to the sandbox state without actually depending on the sandbox
    /// crate and on `MemoryId`.
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl From<usize> for MemoryId {
    fn from(id: usize) -> Self {
        Self(id)
    }
}

impl Default for MemoryId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for MemoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "memory-id-{}", self.0)
    }
}

/// The identifier of a compiled Wasm binary. It must be unique per sandbox
/// process. The current implementation provides stronger guarantee: it is
/// unique across all canisters.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmId(usize);

impl WasmId {
    /// Only the replica process is supposed to create new `WasmId`.
    pub fn new() -> Self {
        static MONOTONICALLY_INCREASING_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = MONOTONICALLY_INCREASING_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self(id)
    }
}

impl Default for WasmId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for WasmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wasm-id-{}", self.0)
    }
}
