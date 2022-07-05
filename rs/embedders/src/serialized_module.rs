use std::collections::BTreeSet;

use ic_config::flag_status::FlagStatus;
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_replicated_state::canister_state::execution_state::WasmMetadata;
use ic_types::methods::WasmMethod;
use ic_wasm_types::WasmEngineError;
use serde::{Deserialize, Serialize};
use wasmtime::Module;

use crate::wasm_utils::{
    instrumentation::{InstrumentationOutput, Segments},
    validation::WasmValidationDetails,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedModule {
    #[serde(with = "serde_bytes")]
    serialized_module: Vec<u8>,
    exported_functions: BTreeSet<WasmMethod>,
    data_segments: Segments,
    wasm_metadata: WasmMetadata,
}

impl SerializedModule {
    pub(crate) fn new(
        module_sharing: FlagStatus,
        module: &Module,
        instrumentation_output: InstrumentationOutput,
        validation_details: WasmValidationDetails,
    ) -> HypervisorResult<Self> {
        let serialized_module = if module_sharing == FlagStatus::Enabled {
            module.serialize().map_err(|e| {
                HypervisorError::WasmEngineError(WasmEngineError::FailedToSerializeModule(format!(
                    "{:?}",
                    e
                )))
            })?
        } else {
            vec![]
        };
        Ok(Self {
            serialized_module,
            exported_functions: instrumentation_output.exported_functions,
            data_segments: instrumentation_output.data,
            wasm_metadata: validation_details.wasm_metadata,
        })
    }

    pub fn exported_functions(&self) -> &BTreeSet<WasmMethod> {
        &self.exported_functions
    }

    pub fn data_segments(&self) -> &Segments {
        &self.data_segments
    }

    pub fn take_data_segments(&mut self) -> Segments {
        std::mem::take(&mut self.data_segments)
    }

    pub fn wasm_metadata(&self) -> &WasmMetadata {
        &self.wasm_metadata
    }

    #[doc(hidden)]
    pub fn empty_for_testing() -> Self {
        Self {
            serialized_module: vec![],
            exported_functions: BTreeSet::new(),
            data_segments: Segments::default(),
            wasm_metadata: WasmMetadata::default(),
        }
    }
}
