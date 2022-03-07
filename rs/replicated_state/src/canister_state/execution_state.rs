use super::SessionNonce;
use crate::{num_bytes_try_from, NumWasmPages, PageMap};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::canister_state_bits::v1 as pb,
};
use ic_types::{methods::WasmMethod, ExecutionRound, NumBytes};
use ic_wasm_types::BinaryEncodedWasm;
use maplit::btreemap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::{
    collections::BTreeSet,
    convert::{From, TryFrom},
    iter::FromIterator,
    path::PathBuf,
    sync::{Arc, Mutex},
};

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
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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

impl Hash for Global {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let bytes = match self {
            Global::I32(val) => val.to_le_bytes().to_vec(),
            Global::I64(val) => val.to_le_bytes().to_vec(),
            Global::F32(val) => val.to_le_bytes().to_vec(),
            Global::F64(val) => val.to_le_bytes().to_vec(),
        };
        bytes.hash(state)
    }
}

impl PartialEq<Global> for Global {
    fn eq(&self, other: &Global) -> bool {
        match (self, other) {
            (Global::I32(val), Global::I32(other_val)) => val == other_val,
            (Global::I64(val), Global::I64(other_val)) => val == other_val,
            (Global::F32(val), Global::F32(other_val)) => val == other_val,
            (Global::F64(val), Global::F64(other_val)) => val == other_val,
            _ => false,
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
pub struct ExportedFunctions(
    /// Since the value is only shared when taking a snapshot, there is no
    /// problem with serializing this field.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    Arc<BTreeSet<WasmMethod>>,
);

impl ExportedFunctions {
    pub fn new(exported_functions: BTreeSet<WasmMethod>) -> Self {
        Self(Arc::new(exported_functions))
    }

    pub fn has_method(&self, method: &WasmMethod) -> bool {
        self.0.contains(method)
    }
}

impl std::convert::AsRef<BTreeSet<WasmMethod>> for ExportedFunctions {
    fn as_ref(&self) -> &BTreeSet<WasmMethod> {
        &self.0
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
    pub embedder_cache: Arc<std::sync::Mutex<Option<EmbedderCache>>>,
}

impl WasmBinary {
    pub fn new(binary: BinaryEncodedWasm) -> Arc<Self> {
        Arc::new(WasmBinary {
            binary,
            embedder_cache: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    pub fn clear_compilation_cache(&self) {
        *self.embedder_cache.lock().unwrap() = None;
    }
}

/// Represents a canister's wasm or stable memory.
#[derive(Debug, Clone)]
pub struct Memory {
    /// The contents of this memory.
    pub page_map: PageMap,
    /// The size of the memory in wasm pages. This does not indicate how much
    /// data is stored in the `page_map`, only the number of pages the memory
    /// has access to. For example, if a canister grows it's memory to N pages
    /// that will be reflected in this field, but the `page_map` will remain
    /// empty until data is written to the memory.
    pub size: NumWasmPages,

    /// Contains either a handle to the execution state in the sandbox process
    /// or information that is necessary to constructs the state remotely.
    pub sandbox_memory: Arc<Mutex<SandboxMemory>>,
}

impl Memory {
    pub fn new(page_map: PageMap, size: NumWasmPages) -> Self {
        Memory {
            page_map,
            size,
            sandbox_memory: SandboxMemory::new(),
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            page_map: PageMap::default(),
            size: NumWasmPages::from(0),
            sandbox_memory: SandboxMemory::new(),
        }
    }
}

impl PartialEq for Memory {
    fn eq(&self, other: &Self) -> bool {
        // Skip the sandbox memory since it is not relevant for equality.
        self.page_map == other.page_map && self.size == other.size
    }
}

/// Represents the synchronisation status of the local execution state
/// in the replica process and the remote execution state in the sandbox
/// process. If the states are in sync, then it stores the id of the
/// state in the sandbox process. Otherwise, it indicates that the snapshot
/// of the state needs to be sent to the sandbox process.
#[derive(Debug)]
pub enum SandboxMemory {
    Synced(SandboxMemoryHandle),
    Unsynced,
}

impl SandboxMemory {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(SandboxMemory::Unsynced))
    }

    pub fn synced(handle: SandboxMemoryHandle) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(SandboxMemory::Synced(handle)))
    }
}

/// The owner of the sandbox memory. It's destructor must close the
/// corresponding memory in the sandbox process.
pub trait SandboxMemoryOwner: std::fmt::Debug + Send + Sync {
    fn get_id(&self) -> usize;
}

/// A handle to the sandbox memory that keeps the corresponding memory in the
/// sandbox process open. It is cloneable and may be shared between multiple
/// copies of memory.
#[derive(Debug)]
pub struct SandboxMemoryHandle(Arc<dyn SandboxMemoryOwner>);

impl Clone for SandboxMemoryHandle {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl SandboxMemoryHandle {
    pub fn new(id: Arc<dyn SandboxMemoryOwner>) -> Self {
        Self(id)
    }

    /// Returns a raw id of the memory in the sandbox process, which can be
    /// converted to sandbox `MemoryId` using `MemoryId::from()`.
    pub fn get_id(&self) -> usize {
        self.0.get_id()
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

    /// The persistent heap of the module. The size of this memory is expected
    /// to fit in a `u32`.
    #[debug_stub = "PageMap"]
    pub wasm_memory: Memory,

    /// The canister stable memory which is persisted across canister upgrades.
    pub stable_memory: Memory,

    /// The state of exported globals. Internal globals are not accessible.
    pub exported_globals: Vec<Global>,

    /// A set of the functions that a Wasm module exports.
    pub exports: ExportedFunctions,

    /// Metadata extracted from the Wasm module.
    pub metadata: WasmMetadata,

    /// Round number at which canister executed
    /// update type operation.
    pub last_executed_round: ExecutionRound,
}

// We have to implement it by hand as embedder_cache can not be compared for
// equality (and doesn't need to be).
impl PartialEq for ExecutionState {
    fn eq(&self, rhs: &Self) -> bool {
        (
            &self.wasm_binary.binary,
            &self.wasm_memory,
            &self.exported_globals,
            &self.exports,
        ) == (
            &rhs.wasm_binary.binary,
            &rhs.wasm_memory,
            &rhs.exported_globals,
            &rhs.exports,
        )
    }
}

impl ExecutionState {
    /// Initializes a new execution state for a canister.
    /// The state will be created with empty stable memory, but may have wasm
    /// memory from data sections in the wasm module.
    pub fn new(
        canister_root: PathBuf,
        wasm_binary: Arc<WasmBinary>,
        exports: ExportedFunctions,
        wasm_memory: Memory,
        stable_memory: Memory,
        exported_globals: Vec<Global>,
        wasm_metadata: WasmMetadata,
    ) -> Self {
        Self {
            canister_root,
            session_nonce: None,
            wasm_binary,
            exports,
            wasm_memory,
            stable_memory,
            exported_globals,
            metadata: wasm_metadata,
            last_executed_round: ExecutionRound::from(0),
        }
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
        num_bytes_try_from(self.wasm_memory.size)
            .expect("could not convert from wasm memory number of pages to bytes")
            + num_bytes_try_from(self.stable_memory.size)
                .expect("could not convert from stable memory number of pages to bytes")
            + NumBytes::from(globals_size_bytes)
            + NumBytes::from(wasm_binary_size_bytes)
    }

    /// Returns the number of global variables in the Wasm module.
    pub fn num_wasm_globals(&self) -> usize {
        self.exported_globals.len()
    }
}

/// An enum that represents the possible visibility levels a custom section
/// defined in the wasm module can have.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CustomSectionType {
    Public,
    Private,
}

impl From<&CustomSectionType> for pb::CustomSectionType {
    fn from(item: &CustomSectionType) -> Self {
        match item {
            CustomSectionType::Public => pb::CustomSectionType::Public,
            CustomSectionType::Private => pb::CustomSectionType::Private,
        }
    }
}

impl TryFrom<pb::CustomSectionType> for CustomSectionType {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::CustomSectionType) -> Result<Self, Self::Error> {
        match item {
            pb::CustomSectionType::Public => Ok(CustomSectionType::Public),
            pb::CustomSectionType::Private => Ok(CustomSectionType::Private),
            pb::CustomSectionType::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "CustomSectionType::Unspecified",
                err: "Encountered error while decoding CustomSection type".to_string(),
            }),
        }
    }
}

/// Represents the data a custom section holds.
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomSection {
    pub visibility: CustomSectionType,
    pub content: Vec<u8>,
}

impl CustomSection {
    pub fn new(visibility: CustomSectionType, content: Vec<u8>) -> Self {
        Self {
            visibility,
            content,
        }
    }
}

impl From<&CustomSection> for pb::WasmCustomSection {
    fn from(item: &CustomSection) -> Self {
        Self {
            visibility: pb::CustomSectionType::from(&item.visibility).into(),
            content: item.content.clone(),
        }
    }
}

impl TryFrom<pb::WasmCustomSection> for CustomSection {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::WasmCustomSection) -> Result<Self, Self::Error> {
        let visibility = CustomSectionType::try_from(
            pb::CustomSectionType::from_i32(item.visibility).unwrap_or_default(),
        )?;
        Ok(Self {
            visibility,
            content: item.content,
        })
    }
}

/// A struct that holds all the custom sections exported by the Wasm module.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WasmMetadata {
    /// Arc is used to make cheap clones of this during snapshots.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    custom_sections: Arc<BTreeMap<String, CustomSection>>,
}

impl WasmMetadata {
    pub fn new(custom_sections: BTreeMap<String, CustomSection>) -> Self {
        Self {
            custom_sections: Arc::new(custom_sections),
        }
    }

    /// Get the custom sections exported by the Wasm module.
    pub fn custom_sections(&self) -> &BTreeMap<String, CustomSection> {
        &self.custom_sections
    }

    /// Returns the custom section associated with the provided name.
    pub fn get_custom_section(&self, custom_section_name: &str) -> Option<&CustomSection> {
        self.custom_sections.get(custom_section_name)
    }
}

impl Default for WasmMetadata {
    fn default() -> Self {
        Self {
            custom_sections: Arc::new(btreemap![]),
        }
    }
}

impl From<&WasmMetadata> for pb::WasmMetadata {
    fn from(item: &WasmMetadata) -> Self {
        let custom_sections = item
            .custom_sections
            .iter()
            .map(|(name, custom_section)| {
                (name.clone(), pb::WasmCustomSection::from(custom_section))
            })
            .collect();
        Self { custom_sections }
    }
}

impl FromIterator<(std::string::String, CustomSection)> for WasmMetadata {
    fn from_iter<T>(iter: T) -> WasmMetadata
    where
        T: IntoIterator<Item = (String, CustomSection)>,
    {
        WasmMetadata {
            custom_sections: Arc::new(BTreeMap::from_iter(iter)),
        }
    }
}

impl TryFrom<pb::WasmMetadata> for WasmMetadata {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::WasmMetadata) -> Result<Self, Self::Error> {
        let custom_sections = item
            .custom_sections
            .into_iter()
            .map(
                |(name, custom_section)| match CustomSection::try_from(custom_section) {
                    Ok(custom_section) => Ok((name, custom_section)),
                    Err(err) => Err(err),
                },
            )
            .collect::<Result<_, _>>()?;
        Ok(WasmMetadata {
            custom_sections: Arc::new(custom_sections),
        })
    }
}
