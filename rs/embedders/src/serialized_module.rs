use std::{
    collections::BTreeSet,
    convert::TryFrom,
    fs::File,
    io::{Read, Write},
    os::fd::{FromRawFd, IntoRawFd, RawFd},
    sync::Arc,
};

use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_replicated_state::canister_state::execution_state::WasmMetadata;
use ic_types::{methods::WasmMethod, CountBytes, NumInstructions};
use ic_wasm_types::WasmEngineError;
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

impl Drop for OnDiskSerializedModule {
    fn drop(&mut self) {
        // TODO unsafe
        unsafe {
            drop(File::from_raw_fd(self.bytes));
            drop(File::from_raw_fd(self.initial_state_data));
        }
    }
}

impl CountBytes for OnDiskSerializedModule {
    fn count_bytes(&self) -> usize {
        0
    }
}

impl OnDiskSerializedModule {
    pub(crate) fn from_serialized_module(
        serialized_module: &SerializedModule,
        mut bytes_file: File,
        mut initial_state_file: File,
    ) -> Self {
        let bytes = &serialized_module.bytes.0;
        // TODO don't clone here.
        let initial_state_data = InitialStateData {
            exported_functions: serialized_module.exported_functions.clone(),
            data_segments: serialized_module.data_segments.clone(),
            wasm_metadata: serialized_module.wasm_metadata.clone(),
        };
        // TODO handle unwrap
        bytes_file.write_all(&bytes).unwrap();
        // TODO handle unwrap
        initial_state_file
            .write_all(&bincode::serialize(&initial_state_data).unwrap())
            .unwrap();
        Self {
            bytes: bytes_file.into_raw_fd(),
            initial_state_data: initial_state_file.into_raw_fd(),
            compilation_cost: serialized_module.compilation_cost,
            imports_details: serialized_module.imports_details,
            is_wasm64: serialized_module.is_wasm64,
        }
    }

    pub(crate) fn into_serialized_module(&self) -> SerializedModule {
        let mut bytes_file = unsafe { File::from_raw_fd(self.bytes) };
        let mut bytes = vec![];
        bytes_file.read_to_end(&mut bytes).unwrap();
        let bytes = Arc::new(SerializedModuleBytes(bytes));
        // Don't drop the file as it will close the fd in the cache.
        let _ = bytes_file.into_raw_fd();

        let mut initial_state_file = unsafe { File::from_raw_fd(self.initial_state_data) };
        let mut data = vec![];
        initial_state_file.read_to_end(&mut data).unwrap();
        let initial_state_data = bincode::deserialize::<InitialStateData>(&data).unwrap();
        // Don't drop the file as it will close the fd in the cache.
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

    // pub(crate) fn new(
    //     module: &Module,
    //     instrumentation_output: InstrumentationOutput,
    //     validation_details: WasmValidationDetails,
    //     is_wasm64: bool,
    //     bytes_file: File,
    //     initial_state_file: File,
    // ) -> HypervisorResult<Self> {
    //     let bytes = SerializedModuleBytes::try_from(module)?;
    //     let initial_state_data = InitialStateData {
    //         exported_functions: instrumentation_output.exported_functions,
    //         data_segments: instrumentation_output.data,
    //         wasm_metadata: validation_details.wasm_metadata,
    //     };
    //     // TODO handle unwrap
    //     bytes_file.write_all(bytes.0).unwrap();
    //     // TODO handle unwrap
    //     initial_state_file
    //         .write_all(bincode::serialize(initial_state_data).unwrap())
    //         .unwrap();
    //     Ok(Self {
    //         bytes: bytes_file.into_raw_fd(),
    //         initial_state_data: initial_state_file.into_raw_fd(),
    //         compilation_cost: instrumentation_output.compilation_cost,
    //         imports_details: validation_details.imports_details,
    //         is_wasm64,
    //     })
    // }
}
