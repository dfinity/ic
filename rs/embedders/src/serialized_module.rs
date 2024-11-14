use std::{
    collections::BTreeSet,
    convert::TryFrom,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    sync::Arc,
};

use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_replicated_state::canister_state::execution_state::WasmMetadata;
use ic_types::{methods::WasmMethod, CountBytes, NumInstructions};
use ic_wasm_types::WasmEngineError;
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use serde::{Deserialize, Serialize};
use wasmtime::Module;

use crate::wasm_utils::{
    InstrumentationOutput, Segments, WasmImportsDetails, WasmValidationDetails,
};

/// A `wasmtime::Module` that has been serialized.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SerializedModuleBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl TryFrom<&Module> for SerializedModuleBytes {
    type Error = HypervisorError;

    fn try_from(module: &Module) -> Result<Self, Self::Error> {
        module.serialize().map(Self).map_err(|e| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToSerializeModule(format!(
                "{:?}",
                e
            )))
        })
    }
}

impl SerializedModuleBytes {
    pub fn empty() -> Self {
        Self(vec![])
    }

    /// It is guaranteed to be safe to deserialize this array into a `wasmtime::Module`.
    pub fn as_slice(&self) -> &[u8] {
        // Serializing a module always includes the header "wasmtime-aot", so
        // the array will be non-empty iff it was created by a call to
        // `wasmtime::Module::serialize` in the `TryFrom` impl. Otherwise it was
        // created by `empty` which should only happen when module sharing is
        // disabled.
        if self.0.is_empty() {
            panic!("Internal error: tried to deserialize Module from an empty arary.")
        } else {
            &self.0
        }
    }
}

/// Contains all data needed to construct a canister's execution state and
/// execute messages against it. If the execution state already exists, then
/// only the `bytes` field is needed to handle execution.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SerializedModule {
    /// The serialized `wasmtime::Module`. This field is wrapped in an `Arc` so
    /// that it can be cheaply moved out of the `SerializedModule` in the cases
    /// when the other fields aren't needed.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub bytes: Arc<SerializedModuleBytes>,
    /// List of functions exported by the canister.
    pub exported_functions: BTreeSet<WasmMethod>,
    /// The initial state of the wasm heap.
    pub data_segments: Segments,
    /// The contents of the metadata custom section.
    pub wasm_metadata: WasmMetadata,
    /// Compiling the canister is equivalent to executing this many instructions.
    pub compilation_cost: NumInstructions,
    /// Imported System API functions that are deprecated, should become deprecated, or should only be used by NNS canisters.
    pub imports_details: WasmImportsDetails,
    /// Boolean value that indicates whether this is a Wasm64 module or not.
    pub is_wasm64: bool,
}

impl CountBytes for SerializedModule {
    fn count_bytes(&self) -> usize {
        self.bytes.0.len()
    }
}

impl SerializedModule {
    pub(crate) fn new(
        module: &Module,
        instrumentation_output: InstrumentationOutput,
        validation_details: WasmValidationDetails,
        is_wasm64: bool,
    ) -> HypervisorResult<Self> {
        let bytes = SerializedModuleBytes::try_from(module)?;
        Ok(Self {
            bytes: Arc::new(bytes),
            exported_functions: instrumentation_output.exported_functions,
            data_segments: instrumentation_output.data,
            wasm_metadata: validation_details.wasm_metadata,
            compilation_cost: instrumentation_output.compilation_cost,
            imports_details: validation_details.imports_details,
            is_wasm64,
        })
    }

    pub fn take_data_segments(&mut self) -> Segments {
        std::mem::take(&mut self.data_segments)
    }
}

/// Parts of the serialized module which are only needed for creating the
/// initial state and can be stored together in a single file.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct InitialStateData {
    /// List of functions exported by the canister.
    pub exported_functions: BTreeSet<WasmMethod>,
    /// The initial state of the wasm heap.
    pub data_segments: Segments,
    /// The contents of the metadata custom section.
    pub wasm_metadata: WasmMetadata,
}

/// Contains all data needed to construct a canister's execution state and
/// execute messages against it. If the execution state already exists, then
/// only the `bytes` field is needed to handle execution.
///
/// All large fields should be stored in disk-backed files so this structure
/// doesn't take up much space in memory.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OnDiskSerializedModule {
    /// Bytes of the compilation artifact.
    pub bytes: RawFd,
    /// Serialization of the other fields required for creating the initial state.
    pub initial_state_data: RawFd,
    /// Compiling the canister is equivalent to executing this many instructions.
    pub compilation_cost: NumInstructions,
    /// Imported System API functions that are deprecated, should become deprecated, or should only be used by NNS canisters.
    pub imports_details: WasmImportsDetails,
    /// Boolean value that indicates whether this is a Wasm64 module or not.
    pub is_wasm64: bool,
}

impl CountBytes for OnDiskSerializedModule {
    fn count_bytes(&self) -> usize {
        0
    }
}

impl OnDiskSerializedModule {
    /// An `OnDiskSerializedModule` contains shared file descriptors, so they
    /// should not be closed unless this is the last copy. If that's the case
    /// the object should be explicitly destructed with this method.
    ///
    /// In the replica this should only happen when removing the module from the
    /// `CompilationCache`. In sandboxes this can happen when closing the
    /// associated `wasmtime::Module` because each new request to open a Wasm
    /// will come with a new `OnDiskSerializedModule` with freshly duplicated
    /// file descriptors.
    pub fn close(self) {
        // TODO unsafe
        unsafe {
            drop(File::from_raw_fd(self.bytes));
            drop(File::from_raw_fd(self.initial_state_data));
        }
    }

    pub(crate) fn from_serialized_module(
        serialized_module: &SerializedModule,
        bytes_path: &Path,
        initial_state_path: &Path,
    ) -> Self {
        let bytes = &serialized_module.bytes.0;
        // TODO don't clone here.
        let initial_state_data = InitialStateData {
            exported_functions: serialized_module.exported_functions.clone(),
            data_segments: serialized_module.data_segments.clone(),
            wasm_metadata: serialized_module.wasm_metadata.clone(),
        };
        // TODO handle unwrap
        let mut bytes_file = File::create(bytes_path).unwrap();
        bytes_file.write_all(&bytes).unwrap();
        // TODO handle unwrap
        // println!("creating initial state file: {:?}", initial_state_path);
        let mut initial_state_file = File::create(initial_state_path).unwrap();
        initial_state_file
            .write_all(&bincode::serialize(&initial_state_data).unwrap())
            .unwrap();

        // Set file permissions to readonly and reopen with new permissions.
        let mut permissions = bytes_file.metadata().unwrap().permissions();
        permissions.set_readonly(true);
        bytes_file.set_permissions(permissions.clone());
        initial_state_file.set_permissions(permissions);
        let bytes_file = File::open(bytes_path).unwrap();
        let initial_state_file = File::open(initial_state_path).unwrap();

        /// Delete the files so that they are automatically cleaned up
        /// when there are no more descriptors.
        std::fs::remove_file(bytes_path).unwrap();
        std::fs::remove_file(initial_state_path).unwrap();

        Self {
            bytes: bytes_file.into_raw_fd(),
            initial_state_data: initial_state_file.into_raw_fd(),
            compilation_cost: serialized_module.compilation_cost,
            imports_details: serialized_module.imports_details,
            is_wasm64: serialized_module.is_wasm64,
        }
    }

    pub(crate) fn into_serialized_module(&self) -> SerializedModule {
        // TODO map files, don't read to end because the fds are shared.
        let mut bytes_file = unsafe { File::from_raw_fd(self.bytes) };
        let mmap_size = bytes_file.metadata().unwrap().size() as usize;
        let mmap_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                mmap_size,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                bytes_file.as_raw_fd(),
                0,
            )
        }
        .unwrap_or_else(|err| panic!("Reading OnDiskSerializedModule bytes failed: {:?}", err))
            as *mut u8;
        // TODO: Safety
        let bytes = unsafe { std::slice::from_raw_parts(mmap_ptr, mmap_size) };
        let bytes = Arc::new(SerializedModuleBytes(bytes.to_vec()));

        let mut initial_state_file = unsafe { File::from_raw_fd(self.initial_state_data) };
        let mmap_size = initial_state_file.metadata().unwrap().size() as usize;
        let mmap_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                mmap_size,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                initial_state_file.as_raw_fd(),
                0,
            )
        }
        .unwrap_or_else(|err| {
            panic!(
                "Reading OnDiskSerializedModule initial_state failed: {:?}",
                err
            )
        }) as *mut u8;
        // TODO: Safety
        let data = unsafe { std::slice::from_raw_parts(mmap_ptr, mmap_size) };
        let initial_state_data = bincode::deserialize::<InitialStateData>(&data).unwrap();
        // Don't drop the files as they will close the fd in the cache.
        let _ = bytes_file.into_raw_fd();
        let _ = initial_state_file.into_raw_fd();

        SerializedModule {
            bytes,
            exported_functions: initial_state_data.exported_functions,
            data_segments: initial_state_data.data_segments,
            wasm_metadata: initial_state_data.wasm_metadata,
            compilation_cost: self.compilation_cost,
            imports_details: self.imports_details,
            is_wasm64: self.is_wasm64,
        }
    }
}
