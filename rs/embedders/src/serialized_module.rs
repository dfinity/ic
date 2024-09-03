use std::{collections::BTreeSet, convert::TryFrom, sync::Arc};

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
    ) -> HypervisorResult<Self> {
        let bytes = SerializedModuleBytes::try_from(module)?;
        Ok(Self {
            bytes: Arc::new(bytes),
            exported_functions: instrumentation_output.exported_functions,
            data_segments: instrumentation_output.data,
            wasm_metadata: validation_details.wasm_metadata,
            compilation_cost: instrumentation_output.compilation_cost,
            imports_details: validation_details.imports_details,
        })
    }

    pub fn take_data_segments(&mut self) -> Segments {
        std::mem::take(&mut self.data_segments)
    }
}
