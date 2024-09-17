use std::{
    collections::{BTreeSet, HashMap},
    time::Instant,
};

use ic_config::embedders::Config as EmbeddersConfig;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::{
    canister_state::{execution_state::WasmMetadata, WASM_PAGE_SIZE_IN_BYTES},
    EmbedderCache, NumWasmPages, PageIndex,
};
use ic_sys::{PageBytes, PAGE_SIZE};
use ic_types::{methods::WasmMethod, NumInstructions};
use ic_wasm_types::{BinaryEncodedWasm, WasmInstrumentationError};
use serde::{Deserialize, Serialize};

use self::{instrumentation::instrument, validation::validate_wasm_binary};
use crate::wasmtime_embedder::StoreData;
use crate::{serialized_module::SerializedModule, CompilationResult, WasmtimeEmbedder};
use wasmtime::InstancePre;

pub mod decoding;
pub mod instrumentation;
mod system_api_replacements;
pub mod validation;

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct WasmImportsDetails {
    // True if the module imports these IC0 methods.
    pub imports_call_cycles_add: bool,
    pub imports_canister_cycle_balance: bool,
    pub imports_msg_cycles_available: bool,
    pub imports_msg_cycles_refunded: bool,
    pub imports_msg_cycles_accept: bool,
    pub imports_mint_cycles: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default)]
pub struct Complexity(pub u64);

/// Returned as a result of `validate_wasm_binary` and provides
/// additional information about the validation.
#[derive(Eq, PartialEq, Debug, Default)]
pub struct WasmValidationDetails {
    pub imports_details: WasmImportsDetails,
    pub wasm_metadata: WasmMetadata,
    pub largest_function_instruction_count: NumInstructions,
    pub max_complexity: Complexity,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
struct Segment {
    offset: usize,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

/// Vector of heap data chunks with their offsets.
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct Segments(Vec<Segment>);

impl FromIterator<(usize, Vec<u8>)> for Segments {
    fn from_iter<T: IntoIterator<Item = (usize, Vec<u8>)>>(iter: T) -> Self {
        Segments(
            iter.into_iter()
                .map(|(offset, bytes)| Segment { offset, bytes })
                .collect(),
        )
    }
}

impl Segments {
    // Returns the slice of the internal data. For testing purposes only.
    #[doc(hidden)]
    pub fn into_slice(self) -> Vec<(usize, Vec<u8>)> {
        self.0
            .into_iter()
            .map(|seg| (seg.offset, seg.bytes))
            .collect()
    }

    pub fn validate(
        &self,
        initial_wasm_pages: NumWasmPages,
    ) -> Result<(), WasmInstrumentationError> {
        let initial_memory_size = initial_wasm_pages.get() * WASM_PAGE_SIZE_IN_BYTES;
        for Segment { offset, bytes } in self.0.iter() {
            let out_of_bounds = match offset.checked_add(bytes.len()) {
                None => true,
                Some(end) => end > initial_memory_size,
            };
            if out_of_bounds {
                return Err(WasmInstrumentationError::InvalidDataSegment {
                    offset: *offset,
                    len: bytes.len(),
                });
            }
        }
        Ok(())
    }

    // Takes chunks extracted from data, and creates pages out of them, by mapping
    // them to the corresponding page, leaving uninitialized parts filled with
    // zeros.
    pub fn as_pages(&self) -> Vec<(PageIndex, PageBytes)> {
        self.0
            .iter()
            // We go over all chunks and split them into multiple chunks if they cross page
            // boundaries.
            .flat_map(|Segment { offset, bytes }| {
                // First, we determine the size of the first chunk, which is equal to the chunk
                // itself, if it does not cross the page boundary.
                let first_chunk_size = std::cmp::min(bytes.len(), PAGE_SIZE - (offset % PAGE_SIZE));
                let mut split_chunks = vec![(*offset, bytes[..first_chunk_size].to_vec())];
                // If the chunk crosses the page boundary, split the rest of it into
                // page-sized chunks and compute the correct offset for them.
                split_chunks.extend_from_slice(
                    bytes[first_chunk_size..]
                        .chunks(PAGE_SIZE)
                        .enumerate()
                        .map(move |(chunk_num, chunk)| {
                            (
                                offset + first_chunk_size + PAGE_SIZE * chunk_num,
                                chunk.to_vec(),
                            )
                        })
                        .collect::<Vec<(usize, Vec<u8>)>>()
                        .as_slice(),
                );
                split_chunks
            })
            // Second, after we know, that no chunk crosses the page boundary, simply fold all of
            // them into a map page_num -> page. Whenever we map a chunk into its page,
            // we simply copy its bytes to the right place inside the page.
            .fold(HashMap::new(), |mut acc, (offset, bytes)| {
                let page_num = offset / PAGE_SIZE;
                let list = acc
                    .entry(PageIndex::new(page_num as u64))
                    .or_insert_with(|| [0; PAGE_SIZE]);
                let local_offset = offset % PAGE_SIZE;
                list[local_offset..local_offset + bytes.len()].copy_from_slice(&bytes);
                acc
            })
            .into_iter()
            .collect()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
enum SystemApiFunc {
    StableGrow,
    Stable64Grow,
    StableSize,
    Stable64Size,
    StableRead,
    Stable64Read,
    StableWrite,
    Stable64Write,
}

impl SystemApiFunc {
    fn from_import_name(name: &str) -> Option<Self> {
        match name {
            "stable_grow" => Some(Self::StableGrow),
            "stable64_grow" => Some(Self::Stable64Grow),
            "stable_size" => Some(Self::StableSize),
            "stable64_size" => Some(Self::Stable64Size),
            "stable_read" => Some(Self::StableRead),
            "stable64_read" => Some(Self::Stable64Read),
            "stable_write" => Some(Self::StableWrite),
            "stable64_write" => Some(Self::Stable64Write),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct InstrumentationOutput {
    /// All exported methods that are relevant to the IC.
    /// Methods relevant to the IC are:
    ///     - Queries (e.g. canister_query ___)
    ///     - Composite queries (e.g. canister_composite_query ___)
    ///     - Updates (e.g. canister_update ___)
    ///     - System methods (e.g. canister_init)
    /// Other methods are assumed to be private to the module and are ignored.
    pub exported_functions: BTreeSet<WasmMethod>,

    /// Data segments.
    pub data: Segments,

    /// Instrumented Wasm binary.
    pub binary: BinaryEncodedWasm,

    /// The time it takes to compile this module is comparable to executing this
    /// many instructions.
    pub compilation_cost: NumInstructions,
}

fn validate_and_instrument(
    wasm: &BinaryEncodedWasm,
    config: &EmbeddersConfig,
) -> HypervisorResult<(WasmValidationDetails, InstrumentationOutput)> {
    println!("validate_and_instrument");
    let (wasm_validation_details, module) = validate_wasm_binary(wasm, config)?;
    let instrumentation_output = instrument(
        module,
        config.cost_to_compile_wasm_instruction,
        config.feature_flags.write_barrier,
        config.feature_flags.wasm_native_stable_memory,
        config.metering_type,
        config.subnet_type,
        config.dirty_page_overhead,
        config.max_wasm_memory_size,
        config.max_stable_memory_size,
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
    validate_and_instrument(wasm, embedder.config())
}

fn compile_inner(
    embedder: &WasmtimeEmbedder,
    wasm: &BinaryEncodedWasm,
) -> HypervisorResult<(InstancePre<StoreData>, CompilationResult, SerializedModule)> {
    let timer = Instant::now();
    let (wasm_validation_details, instrumentation_output) =
        validate_and_instrument(wasm, embedder.config())?;
    let module = embedder.compile(&instrumentation_output.binary)?;
    let instance_pre = embedder.pre_instantiate(&module)?;
    let largest_function_instruction_count =
        wasm_validation_details.largest_function_instruction_count;
    let max_complexity = wasm_validation_details.max_complexity.0;
    let serialized_module =
        SerializedModule::new(&module, instrumentation_output, wasm_validation_details)?;
    Ok((
        instance_pre,
        CompilationResult {
            largest_function_instruction_count,
            compilation_time: timer.elapsed(),
            max_complexity,
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
