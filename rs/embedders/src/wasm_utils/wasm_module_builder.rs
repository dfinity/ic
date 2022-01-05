use super::validation::RESERVED_SYMBOLS;
use ic_wasm_types::WasmInstrumentationError;
use parity_wasm::builder::{CodeLocation, FunctionDefinition, ModuleBuilder};
use parity_wasm::elements::{ExportEntry, GlobalEntry, Internal, Module};

pub(crate) struct WasmModuleBuilder {
    module_builder: ModuleBuilder,
}

/// A wasm module builder wrapper which validates the input before
/// forwarding it to the parity_wasm::ModuleBuilder.
impl WasmModuleBuilder {
    pub fn new(module_builder: ModuleBuilder) -> Self {
        Self { module_builder }
    }

    pub fn push_function(&mut self, function: FunctionDefinition) -> CodeLocation {
        self.module_builder.push_function(function)
    }

    pub fn push_export(
        &mut self,
        field: &str,
        internal: Internal,
    ) -> Result<u32, WasmInstrumentationError> {
        // Ensures that instrumentation does not accidentally
        // export non-reserved symbols.
        if !RESERVED_SYMBOLS.contains(&field) {
            return Err(WasmInstrumentationError::InvalidExport(format!(
                "Exporting non-reserved symbol {} is not allowed.",
                field
            )));
        }
        Ok(self
            .module_builder
            .push_export(ExportEntry::new(field.to_string(), internal)))
    }

    pub fn with_global(mut self, global: GlobalEntry) -> Self {
        self.module_builder = self.module_builder.with_global(global);
        self
    }

    pub fn build(self) -> Module {
        self.module_builder.build()
    }
}
