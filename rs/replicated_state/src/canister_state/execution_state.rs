pub mod proto;

use crate::canister_state::system_state::log_memory_store::LogMemoryStore;
use crate::hash::ic_hashtree_leaf_hash;
use crate::{NumWasmPages, PageMap, canister_state::WASM_PAGE_SIZE_IN_BYTES, num_bytes_try_from};
use ic_management_canister_types_private::Global;
use ic_sys::PAGE_SIZE;
use ic_types::{
    CountBytes, ExecutionRound, NumBytes,
    methods::{SystemMethod, WasmMethod},
};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use ic_wasm_types::CanisterModule;
use maplit::btreemap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::mem::size_of_val;
use std::{
    collections::BTreeSet,
    convert::{From, TryFrom},
    iter::FromIterator,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use strum_macros::EnumIter;

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

/// A set of the functions that a Wasm module exports.
///
/// Arc is used to make cheap clones of this during snapshots.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExportedFunctions {
    /// Since the value is only shared when taking a snapshot, there is no
    /// problem with serializing this field.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    exported_functions: Arc<BTreeSet<WasmMethod>>,

    /// Cached info about exporting a heartbeat method to skip expensive BTreeSet lookup.
    exports_heartbeat: bool,

    /// Cached info about exporting a global timer method to skip expensive BTreeSet lookup.
    exports_global_timer: bool,

    /// Cached info about exporting a on low Wasm memory to skip expensive BTreeSet lookup.
    exports_on_low_wasm_memory: bool,
}

impl ExportedFunctions {
    pub fn new(exported_functions: BTreeSet<WasmMethod>) -> Self {
        let exports_heartbeat =
            exported_functions.contains(&WasmMethod::System(SystemMethod::CanisterHeartbeat));
        let exports_global_timer =
            exported_functions.contains(&WasmMethod::System(SystemMethod::CanisterGlobalTimer));
        let exports_on_low_wasm_memory =
            exported_functions.contains(&WasmMethod::System(SystemMethod::CanisterOnLowWasmMemory));
        Self {
            exported_functions: Arc::new(exported_functions),
            exports_heartbeat,
            exports_global_timer,
            exports_on_low_wasm_memory,
        }
    }

    pub fn has_method(&self, method: &WasmMethod) -> bool {
        match method {
            // Cached values.
            WasmMethod::System(SystemMethod::CanisterHeartbeat) => self.exports_heartbeat,
            WasmMethod::System(SystemMethod::CanisterGlobalTimer) => self.exports_global_timer,
            WasmMethod::System(SystemMethod::CanisterOnLowWasmMemory) => {
                self.exports_on_low_wasm_memory
            }
            // Expensive lookup.
            _ => self.exported_functions.contains(method),
        }
    }
}

impl std::convert::AsRef<BTreeSet<WasmMethod>> for ExportedFunctions {
    fn as_ref(&self) -> &BTreeSet<WasmMethod> {
        &self.exported_functions
    }
}

impl FromIterator<WasmMethod> for ExportedFunctions {
    fn from_iter<T>(iter: T) -> ExportedFunctions
    where
        T: IntoIterator<Item = WasmMethod>,
    {
        Self::new(BTreeSet::from_iter(iter))
    }
}

/// Represent a wasm binary.
#[derive(Debug, ValidateEq)]
pub struct WasmBinary {
    /// The raw canister module provided by the user. Remains immutable after
    /// creating a WasmBinary object.
    #[validate_eq(CompareWithValidateEq)]
    pub binary: CanisterModule,

    /// Cached compiled representation of the binary. Lower layers will assign
    /// to this field to create a compiled representation of the wasm, and
    /// ensure that this happens only once.
    #[validate_eq(Ignore)]
    pub embedder_cache: Arc<std::sync::Mutex<Option<EmbedderCache>>>,
}

impl WasmBinary {
    pub fn new(binary: CanisterModule) -> Arc<Self> {
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
#[derive(Clone, Debug, ValidateEq)]
pub struct Memory {
    /// The contents of this memory.
    #[validate_eq(CompareWithValidateEq)]
    pub page_map: PageMap,
    /// The size of the memory in wasm pages. This does not indicate how much
    /// data is stored in the `page_map`, only the number of pages the memory
    /// has access to. For example, if a canister grows it's memory to N pages
    /// that will be reflected in this field, but the `page_map` will remain
    /// empty until data is written to the memory.
    pub size: NumWasmPages,

    /// Contains either a handle to the execution state in the sandbox process
    /// or information that is necessary to constructs the state remotely.
    #[validate_eq(Ignore)]
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
    /// New method for testing, overriding the default trait.
    pub fn new_for_testing() -> Self {
        Self {
            page_map: PageMap::new_for_testing(),
            size: NumWasmPages::from(0),
            sandbox_memory: SandboxMemory::new(),
        }
    }

    /// Returns an error if `self.size` is less than the modified prefix of
    /// `self.page_map`. The impact of such case:
    ///  - if the canister tries to access pages above `self.size`, then
    ///    it will crash.
    ///  - otherwise, charging for storage will be inaccurate.
    pub fn verify_size(&self) -> Result<(), String> {
        let page_map_bytes = self.page_map.num_host_pages() * PAGE_SIZE;
        let memory_bytes = self.size.get() * WASM_PAGE_SIZE_IN_BYTES;
        if page_map_bytes <= memory_bytes {
            Ok(())
        } else {
            Err(format!(
                "The page map size {page_map_bytes} exceeds the memory size {memory_bytes}"
            ))
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
    fn get_sandbox_memory_id(&self) -> usize;
    fn get_sandbox_process_id(&self) -> Option<usize>;
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
    pub fn get_sandbox_memory_id(&self) -> usize {
        self.0.get_sandbox_memory_id()
    }

    /// Returns the id of the sandbox process if the process is still running.
    /// Returns `None` if the sandbox process has exited.
    pub fn get_sandbox_process_id(&self) -> Option<usize> {
        self.0.get_sandbox_process_id()
    }
}

/// Next scheduled method: round-robin across GlobalTimer; Heartbeat; and Message.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default, EnumIter)]
pub enum NextScheduledMethod {
    #[default]
    GlobalTimer = 1,
    Heartbeat = 2,
    Message = 3,
}

impl NextScheduledMethod {
    /// Round-robin across methods.
    pub fn inc(&mut self) {
        *self = match self {
            Self::GlobalTimer => Self::Heartbeat,
            Self::Heartbeat => Self::Message,
            Self::Message => Self::GlobalTimer,
        }
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
#[derive(Clone, Debug, ValidateEq)]
pub struct ExecutionState {
    /// The path where Canister memory is located. Needs to be stored in
    /// ExecutionState in order to perform the exec system call.
    #[validate_eq(Ignore)]
    pub canister_root: std::path::PathBuf,

    /// The wasm executable associated with this state. It represented here as
    /// a reference-counted object such that:
    /// - it is "shallow-copied" when cloning the execution state
    /// - all execution states cloned from each other (and also having the same
    ///   wasm_binary) share the same compilation cache object
    ///
    /// The latter property ensures that compilation for queries is cached
    /// properly when loading a state from checkpoint.
    #[validate_eq(CompareWithValidateEq)]
    pub wasm_binary: Arc<WasmBinary>,

    /// The persistent heap of the module. The size of this memory is expected
    /// to fit in a `u32`.
    #[validate_eq(CompareWithValidateEq)]
    pub wasm_memory: Memory,

    /// The canister stable memory which is persisted across canister upgrades.
    #[validate_eq(CompareWithValidateEq)]
    pub stable_memory: Memory,

    /// The memory used for storing log entries.
    #[validate_eq(CompareWithValidateEq)]
    pub log_memory_store: LogMemoryStore,

    /// The state of exported globals. Internal globals are not accessible.
    #[validate_eq(Ignore)]
    pub exported_globals: Vec<Global>,

    /// A set of the functions that a Wasm module exports.
    #[validate_eq(Ignore)]
    pub exports: ExportedFunctions,

    /// Metadata extracted from the Wasm module.
    #[validate_eq(Ignore)]
    pub metadata: WasmMetadata,

    /// Round number at which canister executed
    /// update type operation.
    pub last_executed_round: ExecutionRound,

    /// Round-robin across canister method types.
    pub next_scheduled_method: NextScheduledMethod,

    /// Checks if execution is in Wasm64 mode.
    pub wasm_execution_mode: WasmExecutionMode,
}

// We have to implement it by hand as embedder_cache can not be compared for
// equality (and doesn't need to be).
impl PartialEq for ExecutionState {
    fn eq(&self, rhs: &Self) -> bool {
        // Destruction is done on purpose, to ensure if the new
        // field is added to 'ExecutionState' compiler will throw
        // an error. Hence pointing to appropriate change here.
        let ExecutionState {
            canister_root: _,
            wasm_binary,
            wasm_memory,
            stable_memory,
            log_memory_store,
            exported_globals,
            exports,
            metadata,
            last_executed_round,
            next_scheduled_method,
            wasm_execution_mode,
        } = rhs;

        (
            &self.wasm_binary.binary,
            &self.wasm_memory,
            &self.stable_memory,
            &self.log_memory_store,
            &self.exported_globals,
            &self.exports,
            &self.metadata,
            &self.last_executed_round,
            &self.next_scheduled_method,
            &self.wasm_execution_mode,
        ) == (
            &wasm_binary.binary,
            wasm_memory,
            stable_memory,
            log_memory_store,
            exported_globals,
            exports,
            metadata,
            last_executed_round,
            next_scheduled_method,
            wasm_execution_mode,
        )
    }
}

impl ExecutionState {
    /// Initializes a new execution state for a canister.
    /// The state will be created with empty stable memory, but may have wasm
    /// memory from data sections in the wasm module.
    /// The state will be created with last_executed_round = 0, a
    /// default next_scheduled_method, and wasm_execution_mode = WasmExecutionMode::Wasm32.
    /// Be sure to change these if needed.
    pub fn new(
        canister_root: PathBuf,
        wasm_binary: Arc<WasmBinary>,
        exports: ExportedFunctions,
        wasm_memory: Memory,
        stable_memory: Memory,
        log_memory_store: LogMemoryStore,
        exported_globals: Vec<Global>,
        wasm_metadata: WasmMetadata,
    ) -> Self {
        Self {
            canister_root,
            wasm_binary,
            exports,
            wasm_memory,
            stable_memory,
            log_memory_store,
            exported_globals,
            metadata: wasm_metadata,
            last_executed_round: ExecutionRound::from(0),
            next_scheduled_method: NextScheduledMethod::default(),
            wasm_execution_mode: WasmExecutionMode::Wasm32,
        }
    }

    // Checks whether the given method is exported by the Wasm module or not.
    pub fn exports_method(&self, method: &WasmMethod) -> bool {
        self.exports.has_method(method)
    }

    /// Returns the Wasm memory currently used by the `ExecutionState`.
    pub fn wasm_memory_usage(&self) -> NumBytes {
        num_bytes_try_from(self.wasm_memory.size)
            .expect("could not convert from wasm memory number of pages to bytes")
    }

    /// Returns the stable memory currently used by the `ExecutionState`.
    pub fn stable_memory_usage(&self) -> NumBytes {
        num_bytes_try_from(self.stable_memory.size)
            .expect("could not convert from stable memory number of pages to bytes")
    }

    // Returns the global memory currently used by the `ExecutionState`.
    pub fn global_memory_usage(&self) -> NumBytes {
        let globals_size_bytes = size_of::<Global>() as u64 * self.exported_globals.len() as u64;
        NumBytes::from(globals_size_bytes)
    }

    // Returns the memory size of the Wasm binary currently used by the `ExecutionState`.
    pub fn wasm_binary_memory_usage(&self) -> NumBytes {
        let wasm_binary_size_bytes = self.wasm_binary.binary.len() as u64;
        NumBytes::from(wasm_binary_size_bytes)
    }

    // Returns the memory size of the custom sections currently used by the `ExecutionState`.
    pub fn custom_sections_memory_size(&self) -> NumBytes {
        self.metadata.memory_usage()
    }

    /// Returns the memory currently used by the `ExecutionState`.
    pub fn memory_usage(&self) -> NumBytes {
        self.wasm_memory_usage()
            + self.stable_memory_usage()
            + self.global_memory_usage()
            + self.wasm_binary_memory_usage()
            + self.custom_sections_memory_size()
    }

    /// Returns the `ExecutionState`'s contribution to the memory of a snapshot.
    /// The difference to `memory_usage` is that the custom wasm section is not
    /// stored explicitly in a snapshot, only implicitly in the wasm module,
    /// whereas for the running canister, it's explicit and takes additional
    /// memory.
    pub fn memory_usage_in_snapshot(&self) -> NumBytes {
        self.wasm_memory_usage()
            + self.stable_memory_usage()
            + self.global_memory_usage()
            + self.wasm_binary_memory_usage()
    }

    /// Returns the number of global variables in the Wasm module.
    pub fn num_wasm_globals(&self) -> usize {
        self.exported_globals.len()
    }

    /// Returns the amount of heap delta represented by this canister's execution state.
    /// See also comment on `CanisterState::heap_delta`.
    pub(crate) fn heap_delta(&self) -> NumBytes {
        let delta_pages = self.wasm_memory.page_map.num_delta_pages()
            + self.stable_memory.page_map.num_delta_pages();
        NumBytes::from((delta_pages * PAGE_SIZE) as u64)
    }

    pub(crate) fn wasm_execution_mode(&self) -> WasmExecutionMode {
        self.wasm_execution_mode
    }
}

/// An enum that represents the possible visibility levels a custom section
/// defined in the wasm module can have.
#[derive(Copy, Clone, Eq, PartialEq, Debug, EnumIter, serde::Deserialize, serde::Serialize)]
pub enum CustomSectionType {
    Public = 1,
    Private = 2,
}

/// Represents the data a custom section holds.
#[derive(Clone, Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub struct CustomSection {
    visibility: CustomSectionType,
    content: Vec<u8>,
    hash: [u8; 32],
}

impl CustomSection {
    pub fn new(visibility: CustomSectionType, content: Vec<u8>) -> Self {
        Self {
            visibility,
            hash: ic_hashtree_leaf_hash(&content),
            content,
        }
    }

    pub fn visibility(&self) -> CustomSectionType {
        self.visibility
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

impl CountBytes for CustomSection {
    fn count_bytes(&self) -> usize {
        size_of_val(&self.visibility) + self.content.len()
    }
}

/// A struct that holds all the custom sections exported by the Wasm module.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct WasmMetadata {
    /// Arc is used to make cheap clones of this during snapshots.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    custom_sections: Arc<BTreeMap<String, CustomSection>>,
    /// Memory usage that the Wasm custom sections contribute.
    ///
    /// This field is computed at the struct's construction time as it shouldn't
    /// change except for when a new Wasm module is installed and then create
    /// a fresh instance of `WasmMetadata` which lives until the next change.
    memory_usage: NumBytes,
}

impl WasmMetadata {
    pub fn new(custom_sections: BTreeMap<String, CustomSection>) -> Self {
        Self {
            memory_usage: NumBytes::from(
                custom_sections
                    .iter()
                    .map(|(k, v)| k.len() + v.count_bytes())
                    .sum::<usize>() as u64,
            ),
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

    /// Returns the memory used by Wasm custom sections in bytes.
    pub fn memory_usage(&self) -> NumBytes {
        // Pre-computed memory usage at struct initialization should be equal to
        // the sum of memory used by all custom sections.
        debug_assert_eq!(
            self.memory_usage,
            NumBytes::from(
                self.custom_sections
                    .iter()
                    .map(|(k, v)| k.len() + v.count_bytes())
                    .sum::<usize>() as u64,
            )
        );
        self.memory_usage
    }
}

impl Default for WasmMetadata {
    fn default() -> Self {
        Self {
            custom_sections: Arc::new(btreemap![]),
            memory_usage: NumBytes::from(0),
        }
    }
}

impl FromIterator<(std::string::String, CustomSection)> for WasmMetadata {
    fn from_iter<T>(iter: T) -> WasmMetadata
    where
        T: IntoIterator<Item = (String, CustomSection)>,
    {
        WasmMetadata::new(BTreeMap::from_iter(iter))
    }
}

/// Keeps track of how a canister is executing.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum WasmExecutionMode {
    Wasm32,
    Wasm64,
}

impl WasmExecutionMode {
    pub fn is_wasm64(&self) -> bool {
        match self {
            WasmExecutionMode::Wasm32 => false,
            WasmExecutionMode::Wasm64 => true,
        }
    }
    pub fn from_is_wasm64(is_wasm64: bool) -> Self {
        if is_wasm64 {
            WasmExecutionMode::Wasm64
        } else {
            WasmExecutionMode::Wasm32
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            WasmExecutionMode::Wasm32 => "wasm32",
            WasmExecutionMode::Wasm64 => "wasm64",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_protobuf::state::canister_state_bits::v1 as pb;
    use std::collections::BTreeSet;
    use strum::IntoEnumIterator;

    #[test]
    fn global_exhaustive() {
        for global in ic_management_canister_types_private::Global::iter() {
            let _other: Global = global;
        }
    }

    #[test]
    fn test_next_scheduled_method() {
        let mut values: BTreeSet<u8> = BTreeSet::new();
        let mut next_method = NextScheduledMethod::GlobalTimer;
        let initial_scheduled_method = NextScheduledMethod::GlobalTimer;

        for _ in 0..NextScheduledMethod::iter().count() {
            values.insert(next_method as u8);
            next_method.inc();
        }

        // Check that after calling method 'inc()' 'NextScheduledMethod::iter().count()'
        // times we are back at the initial method.
        assert_eq!(next_method, initial_scheduled_method);

        // Check that we loop over all possible variants of
        // the 'NextScheduledMethod'.
        assert_eq!(values.len(), NextScheduledMethod::iter().count());
    }

    #[test]
    fn custom_section_type_proto_round_trip() {
        for initial in CustomSectionType::iter() {
            let encoded = pb::CustomSectionType::from(&initial);
            let round_trip = CustomSectionType::try_from(encoded).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn compatibility_for_custom_section_type() {
        // If this fails, you are making a potentially incompatible change to `CustomSectionType`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            CustomSectionType::iter()
                .map(|x| x as i32)
                .collect::<Vec<i32>>(),
            [1, 2]
        );
    }

    #[test]
    fn next_scheduled_method_proto_round_trip() {
        for initial in NextScheduledMethod::iter() {
            let encoded = pb::NextScheduledMethod::from(initial);
            let round_trip = NextScheduledMethod::from(encoded);

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn compatibility_for_next_scheduled_method() {
        // If this fails, you are making a potentially incompatible change to `NextScheduledMethod`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            NextScheduledMethod::iter()
                .map(|x| x as i32)
                .collect::<Vec<i32>>(),
            [1, 2, 3]
        );
    }
}
