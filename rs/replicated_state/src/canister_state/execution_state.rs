use super::SessionNonce;
use crate::{num_bytes_from, NumWasmPages, PageIndex, PageMap};
use ic_config::embedders::PersistenceType;
use ic_cow_state::{CowMemoryManager, CowMemoryManagerImpl, MappedState, MappedStateImpl};
use ic_interfaces::execution_environment::HypervisorResult;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::canister_state_bits::v1 as pb,
};
use ic_sys::PageBytes;
use ic_types::{methods::WasmMethod, ExecutionRound, NumBytes};
use ic_utils::ic_features::cow_state_feature;
use ic_wasm_types::BinaryEncodedWasm;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, convert::TryFrom, iter::FromIterator, path::PathBuf, sync::Arc};

/// An arbitrary piece of data that an embedder can store between module
/// instantiations.
/// Arc is for cheap cloning.
//
/// We don't derive `Serialize` and `Deserialize` because this is a binary that
/// is serialized by writing it to a file when creating checkpoints.
#[derive(Clone)]
pub struct EmbedderCache(Arc<dyn std::any::Any + Send + Sync + 'static>);

impl EmbedderCache {
    pub fn new<T>(cache: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        Self(Arc::new(cache))
    }

    pub fn downcast<T>(&self) -> Option<&T>
    where
        T: 'static,
    {
        <dyn std::any::Any>::downcast_ref::<T>(&*self.0)
    }
}

impl std::fmt::Debug for EmbedderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmbedderCache")
    }
}

/// An enum representing the possible values of a global variable.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum Global {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl Global {
    pub fn type_name(&self) -> &'static str {
        match self {
            Global::I32(_) => "i32",
            Global::I64(_) => "i64",
            Global::F32(_) => "f32",
            Global::F64(_) => "f64",
        }
    }
}

impl From<&Global> for pb::Global {
    fn from(item: &Global) -> Self {
        match item {
            Global::I32(value) => Self {
                global: Some(pb::global::Global::I32(*value)),
            },
            Global::I64(value) => Self {
                global: Some(pb::global::Global::I64(*value)),
            },
            Global::F32(value) => Self {
                global: Some(pb::global::Global::F32(*value)),
            },
            Global::F64(value) => Self {
                global: Some(pb::global::Global::F64(*value)),
            },
        }
    }
}

impl TryFrom<pb::Global> for Global {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::Global) -> Result<Self, Self::Error> {
        match try_from_option_field(value.global, "Global::global")? {
            pb::global::Global::I32(value) => Ok(Self::I32(value)),
            pb::global::Global::I64(value) => Ok(Self::I64(value)),
            pb::global::Global::F32(value) => Ok(Self::F32(value)),
            pb::global::Global::F64(value) => Ok(Self::F64(value)),
        }
    }
}

/// A set of the functions that a Wasm module exports.
///
/// Arc is used to make cheap clones of this during snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedFunctions(Arc<BTreeSet<WasmMethod>>);

impl ExportedFunctions {
    pub fn new(exported_functions: BTreeSet<WasmMethod>) -> Self {
        Self(Arc::new(exported_functions))
    }

    pub fn has_method(&self, method: &WasmMethod) -> bool {
        self.0.contains(method)
    }
}

impl FromIterator<WasmMethod> for ExportedFunctions {
    fn from_iter<T>(iter: T) -> ExportedFunctions
    where
        T: IntoIterator<Item = WasmMethod>,
    {
        Self(Arc::new(BTreeSet::from_iter(iter)))
    }
}

impl From<&ExportedFunctions> for Vec<pb::WasmMethod> {
    fn from(item: &ExportedFunctions) -> Self {
        item.0.iter().map(From::from).collect()
    }
}

impl TryFrom<Vec<pb::WasmMethod>> for ExportedFunctions {
    type Error = ProxyDecodeError;
    fn try_from(value: Vec<pb::WasmMethod>) -> Result<Self, Self::Error> {
        Ok(ExportedFunctions::new(
            value
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
        ))
    }
}

/// Represent a wasm binary.
#[derive(debug_stub_derive::DebugStub)]
pub struct WasmBinary {
    /// The raw wasm binary (after validation). Remains immutable after
    /// creating a WasmBinary object.
    pub binary: BinaryEncodedWasm,

    /// Cached compiled representation of the binary. Lower layers will assign
    /// to this field to create a compiled representation of the wasm, and
    /// ensure that this happens only once.
    pub embedder_cache: std::sync::Mutex<Option<EmbedderCache>>,
}

impl WasmBinary {
    pub fn new(binary: BinaryEncodedWasm) -> Arc<Self> {
        Arc::new(WasmBinary {
            binary,
            embedder_cache: std::sync::Mutex::new(None),
        })
    }

    pub fn clear_compilation_cache(&self) {
        *self.embedder_cache.lock().unwrap() = None;
    }
}

/// The part of the canister state that can be accessed during execution
///
/// Note that execution state is used to track ephemeral information.
/// In particular, `ExecutionState` as processed by runtime is
/// reconstructed at points to represent the execution state in the
/// sandbox process. Therefore, there is no guarantee that equality
/// and ordering of a value are going to be preserved. That is the
/// execution state value might differ even if nothing has been
/// executed.
///
/// For that reason we do NOT want to derive any ordering relations or
/// persist `ExecutionState`.
// Do ***NOT*** derive PartialEq, Eq, Serialization or
// Deserialization for `ExecutionState`.
#[derive(Clone, debug_stub_derive::DebugStub)]
pub struct ExecutionState {
    /// The path where Canister memory is located. Needs to be stored in
    /// ExecutionState in order to perform the exec system call.
    pub canister_root: std::path::PathBuf,

    /// Session state Nonce. If occupied, runtime is already
    /// processing this execution state. This is being used to refer
    /// to mutated `MappedState` and globals that reside in the
    /// sandbox execution process (and not necessarily in memory) and
    /// enable continuations.
    pub session_nonce: Option<SessionNonce>,

    /// The wasm executable associated with this state. It represented here as
    /// a reference-counted object such that:
    /// - it is "shallow-copied" when cloning the execution state
    /// - all execution states cloned from each other (and also having the same
    ///   wasm_binary) share the same compilation cache object
    /// The latter property ensures that compilation for queries is cached
    /// properly when loading a state from checkpoint.
    pub wasm_binary: Arc<WasmBinary>,

    /// The persistent heap of the module.
    #[debug_stub = "PageMap"]
    pub page_map: PageMap,

    /// The state of exported globals. Internal globals are not accessible.
    pub exported_globals: Vec<Global>,

    /// The current size of Wasm heap. It can change when canister
    /// calls `memory.grow`.
    pub heap_size: NumWasmPages,

    /// A set of the functions that a Wasm module exports.
    pub exports: ExportedFunctions,

    /// Round number at which canister executed
    /// update type operation.
    pub last_executed_round: ExecutionRound,

    /// The persistent cow memory of the canister.
    pub cow_mem_mgr: Arc<CowMemoryManagerImpl>,

    /// Mapped state of the current execution
    pub mapped_state: Option<Arc<MappedStateImpl>>,
}

// We have to implement it by hand as embedder_cache can not be compared for
// equality (and doesn't need to be).
impl PartialEq for ExecutionState {
    fn eq(&self, rhs: &Self) -> bool {
        (
            &self.wasm_binary.binary,
            &self.page_map,
            &self.exported_globals,
            &self.exports,
            self.heap_size,
        ) == (
            &rhs.wasm_binary.binary,
            &rhs.page_map,
            &rhs.exported_globals,
            &rhs.exports,
            rhs.heap_size,
        )
    }
}

impl ExecutionState {
    /// Initializes a new execution state for a canister.
    pub fn new(
        wasm_binary: BinaryEncodedWasm,
        canister_root: PathBuf,
        exports: ExportedFunctions,
        pages: &[(PageIndex, Box<PageBytes>)],
    ) -> HypervisorResult<Self> {
        let mut page_map = PageMap::default();
        page_map.update(
            &pages
                .iter()
                .map(|(index, bytes)| (*index, bytes as &PageBytes))
                .collect::<Vec<(PageIndex, &PageBytes)>>(),
        );

        let cow_mem_mgr = Arc::new(CowMemoryManagerImpl::open_readwrite(canister_root.clone()));
        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            let mapped_state = cow_mem_mgr.get_map();
            let mut updated_pages = Vec::new();

            for i in page_map.host_pages_iter() {
                let page_idx = i.0;
                updated_pages.push(page_idx.get());
                mapped_state.update_heap_page(page_idx.get(), page_map.get_page(page_idx));
            }
            mapped_state.soft_commit(&updated_pages);
        }
        let session_nonce = None;

        let wasm_binary = WasmBinary::new(wasm_binary);

        let execution_state = ExecutionState {
            canister_root,
            session_nonce,
            wasm_binary,
            exports,
            page_map,
            exported_globals: vec![],
            heap_size: NumWasmPages::from(0),
            last_executed_round: ExecutionRound::from(0),
            cow_mem_mgr,
            mapped_state: None,
        };

        Ok(execution_state)
    }

    // Checks whether the given method is exported by the Wasm module or not.
    pub fn exports_method(&self, method: &WasmMethod) -> bool {
        self.exports.has_method(method)
    }

    /// Returns the memory currently used by the `ExecutionState`.
    pub fn memory_usage(&self) -> NumBytes {
        // We use 8 bytes per global.
        let globals_size_bytes = 8 * self.exported_globals.len() as u64;
        let wasm_binary_size_bytes = self.wasm_binary.binary.len() as u64;
        num_bytes_from(self.heap_size)
            + NumBytes::from(globals_size_bytes)
            + NumBytes::from(wasm_binary_size_bytes)
    }

    /// Returns the number of global variables in the Wasm module.
    pub fn num_wasm_globals(&self) -> usize {
        self.exported_globals.len()
    }

    /// Returns the persistence type associated with this state.
    pub fn persistence_type(&self) -> PersistenceType {
        if self.cow_mem_mgr.is_valid() {
            PersistenceType::Pagemap
        } else {
            PersistenceType::Sigsegv
        }
    }
}
