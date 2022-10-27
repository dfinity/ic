use std::time::Instant;

use ic_config::embedders::Config as EmbeddersConfig;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::EmbedderCache;
use ic_wasm_types::BinaryEncodedWasm;
use wasmtime::Module;

use crate::{serialized_module::SerializedModule, CompilationResult, WasmtimeEmbedder};

pub mod decoding;
pub mod errors;
pub mod instrumentation;
pub mod validation;
mod wasm_module_builder;
pub mod wasm_transform;

use instrumentation::instrument;
use validation::validate_wasm_binary;

use self::{instrumentation::InstrumentationOutput, validation::WasmValidationDetails};

fn validate_and_instrument(
    wasm: &BinaryEncodedWasm,
    config: &EmbeddersConfig,
) -> HypervisorResult<(WasmValidationDetails, InstrumentationOutput)> {
    let wasm_validation_details = validate_wasm_binary(wasm, config)?;
    let instrumentation_output = instrument(wasm, config.cost_to_compile_wasm_instruction)?;
    Ok((wasm_validation_details, instrumentation_output))
}

/// Only exposed for tests that need to inspect the instrumented wasm or
/// validation details.
#[doc(hidden)]
pub fn validate_and_instrument_for_testing(
    embedder: &WasmtimeEmbedder,
    wasm: &BinaryEncodedWasm,
) -> HypervisorResult<(WasmValidationDetails, InstrumentationOutput)> {
    validate_and_instrument(wasm, embedder.config())
}

fn compile_inner(
    embedder: &WasmtimeEmbedder,
    wasm: &BinaryEncodedWasm,
) -> HypervisorResult<(Module, CompilationResult, SerializedModule)> {
    let timer = Instant::now();
    let (wasm_validation_details, instrumentation_output) =
        validate_and_instrument(wasm, embedder.config())?;
    let module = embedder.compile(&instrumentation_output.binary)?;
    let largest_function_instruction_count =
        wasm_validation_details.largest_function_instruction_count;
    let serialized_module =
        SerializedModule::new(&module, instrumentation_output, wasm_validation_details)?;
    Ok((
        module,
        CompilationResult {
            largest_function_instruction_count,
            compilation_time: timer.elapsed(),
        },
        serialized_module,
    ))
}

pub fn compile(
    embedder: &WasmtimeEmbedder,
    wasm: &BinaryEncodedWasm,
) -> (
    EmbedderCache,
    HypervisorResult<(CompilationResult, SerializedModule)>,
) {
    let (cache, result) = match compile_inner(embedder, wasm) {
        Ok((module, result, serialized)) => (Ok(module), Ok((result, serialized))),
        Err(err) => (Err(err.clone()), Err(err)),
    };
    (EmbedderCache::new(cache), result)
}
