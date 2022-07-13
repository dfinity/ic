use std::time::Instant;

use ic_config::embedders::Config as EmbeddersConfig;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::EmbedderCache;
use ic_wasm_types::BinaryEncodedWasm;

use crate::{serialized_module::SerializedModule, CompilationResult, WasmtimeEmbedder};

pub mod decoding;
pub mod errors;
pub mod instrumentation;
pub mod validation;
mod wasm_module_builder;

use instrumentation::{instrument, InstructionCostTable};
use validation::validate_wasm_binary;

use self::{instrumentation::InstrumentationOutput, validation::WasmValidationDetails};

fn validate_and_instrument(
    wasm: &BinaryEncodedWasm,
    instruction_cost_table: &InstructionCostTable,
    config: &EmbeddersConfig,
) -> HypervisorResult<(WasmValidationDetails, InstrumentationOutput)> {
    let wasm_validation_details = validate_wasm_binary(wasm, config)?;
    let instrumentation_output = instrument(
        wasm,
        instruction_cost_table,
        config.cost_to_compile_wasm_instruction,
    )?;
    Ok((wasm_validation_details, instrumentation_output))
}

/// Only exposed for tests that need to inspect the instrumented wasm or
/// validation details.
#[doc(hidden)]
pub fn validate_and_instrument_for_testing(
    embedder: &WasmtimeEmbedder,
    wasm: &BinaryEncodedWasm,
) -> HypervisorResult<(WasmValidationDetails, InstrumentationOutput)> {
    validate_and_instrument(wasm, &InstructionCostTable::default(), embedder.config())
}

pub fn compile(
    embedder: &WasmtimeEmbedder,
    wasm: &BinaryEncodedWasm,
) -> HypervisorResult<(EmbedderCache, CompilationResult, SerializedModule)> {
    let timer = Instant::now();
    let (wasm_validation_details, instrumentation_output) =
        validate_and_instrument(wasm, &InstructionCostTable::default(), embedder.config())?;
    let module = embedder.compile(&instrumentation_output.binary)?;
    let largest_function_instruction_count =
        wasm_validation_details.largest_function_instruction_count;
    let serialized_module = SerializedModule::new(
        embedder.config().feature_flags.module_sharing,
        &module,
        instrumentation_output,
        wasm_validation_details,
    )?;
    Ok((
        EmbedderCache::new(module),
        CompilationResult {
            largest_function_instruction_count,
            compilation_time: timer.elapsed(),
        },
        serialized_module,
    ))
}
