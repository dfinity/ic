use std::time::{Duration, Instant};

use ic_interfaces::execution_environment::{CompilationResult, HypervisorResult};
use ic_replicated_state::EmbedderCache;
use ic_wasm_types::BinaryEncodedWasm;

use crate::WasmtimeEmbedder;

pub mod decoding;
pub mod errors;
pub mod instrumentation;
pub mod validation;
mod wasm_module_builder;

use instrumentation::{instrument, InstructionCostTable, InstrumentationOutput};
use validation::{validate_wasm_binary, WasmValidationDetails};

/// All data required to create an execution state after compiling a canister.
pub struct FullCompilationOutput {
    pub validation_details: WasmValidationDetails,
    pub instrumentation_output: InstrumentationOutput,
    pub compilation_time: Duration,
}

impl From<&FullCompilationOutput> for CompilationResult {
    fn from(item: &FullCompilationOutput) -> Self {
        CompilationResult {
            largest_function_instruction_count: item
                .validation_details
                .largest_function_instruction_count,
            compilation_cost: item.instrumentation_output.compilation_cost,
            compilation_time: item.compilation_time,
        }
    }
}

pub fn compile(
    embedder: &WasmtimeEmbedder,
    wasm: &BinaryEncodedWasm,
) -> HypervisorResult<(EmbedderCache, FullCompilationOutput)> {
    let timer = Instant::now();
    let wasm_validation_details = validate_wasm_binary(wasm, embedder.config())?;
    let instrumentation_output = instrument(
        wasm,
        &InstructionCostTable::default(),
        embedder.config().cost_to_compile_wasm_instruction,
    )?;
    let compilate = embedder.compile(&instrumentation_output.binary)?;
    Ok((
        compilate,
        FullCompilationOutput {
            validation_details: wasm_validation_details,
            instrumentation_output,
            compilation_time: timer.elapsed(),
        },
    ))
}
