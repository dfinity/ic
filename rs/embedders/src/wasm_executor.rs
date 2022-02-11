use std::collections::BTreeSet;
use std::path::PathBuf;

use ic_replicated_state::canister_state::execution_state::WasmBinary;
use ic_replicated_state::{ExportedFunctions, Global, Memory, NumWasmPages, PageMap};
use ic_system_api::sandbox_safe_system_state::{SandboxSafeSystemState, SystemStateChanges};
use ic_system_api::ApiType;
use ic_types::methods::{FuncRef, WasmMethod};
use prometheus::{Histogram, IntCounter};

use crate::{
    wasm_utils::instrumentation::{instrument, InstructionCostTable},
    wasm_utils::validation::{validate_wasm_binary, WasmImportsDetails, WasmValidationDetails},
    wasmtime_embedder::WasmtimeInstance,
    WasmExecutionInput, WasmExecutionOutput, WasmtimeEmbedder,
};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_config::flag_status::FlagStatus;
use ic_interfaces::execution_environment::{
    ExecutionParameters, HypervisorError, HypervisorResult, InstanceStats, SystemApi,
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::buckets::decimal_buckets_with_zero;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{EmbedderCache, ExecutionState};
use ic_sys::{page_bytes_from_ptr, PageBytes, PageIndex, PAGE_SIZE};
use ic_system_api::{system_api_empty::SystemApiEmpty, ModificationTracking, SystemApiImpl};
use ic_types::{CanisterId, NumBytes, NumInstructions};
use ic_wasm_types::BinaryEncodedWasm;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Please enable only for debugging.
// If enabled, will collect and log checksums of execution results.
// Disabled by default to avoid producing too much data.
const EMIT_STATE_HASHES_FOR_DEBUGGING: FlagStatus = FlagStatus::Disabled;

struct WasmExecutorMetrics {
    // TODO(EXC-350): Remove this metric once we confirm that no reserved functions are exported.
    reserved_exports: IntCounter,
    // TODO(EXC-365): Remove this metric once we confirm that no module imports `ic0.call_simple`
    // anymore.
    imports_call_simple: IntCounter,
    // TODO(EXC-376): Remove these metrics once we confirm that no module imports these IC0 methods
    // anymore.
    imports_call_cycles_add: IntCounter,
    imports_canister_cycle_balance: IntCounter,
    imports_msg_cycles_available: IntCounter,
    imports_msg_cycles_refunded: IntCounter,
    imports_msg_cycles_accept: IntCounter,
    imports_mint_cycles: IntCounter,
    compile: Histogram,
}

impl WasmExecutorMetrics {
    #[doc(hidden)] // pub for usage in tests
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            reserved_exports: metrics_registry.int_counter(
                "execution_wasm_reserved_exports_total",
                "The number of reserved functions exported from Wasm modules",
            ),
            imports_call_simple: metrics_registry.int_counter(
                "execution_wasm_imports_call_simple_total",
                "The number of Wasm modules that import ic0.call_simple",
            ),
            imports_call_cycles_add: metrics_registry.int_counter(
                "execution_wasm_imports_call_cycles_add",
                "The number of Wasm modules that import ic0.call_cycles_add",
            ),
            imports_canister_cycle_balance: metrics_registry.int_counter(
                "execution_wasm_imports_canister_cycle_balance",
                "The number of Wasm modules that import ic0.canister_cycle_balance",
            ),
            imports_msg_cycles_available: metrics_registry.int_counter(
                "execution_wasm_imports_msg_cycles_available",
                "The number of Wasm modules that import ic0.msg_cycles_available",
            ),
            imports_msg_cycles_refunded: metrics_registry.int_counter(
                "execution_wasm_imports_msg_cycles_refunded",
                "The number of Wasm modules that import ic0.msg_cycles_refunded",
            ),
            imports_msg_cycles_accept: metrics_registry.int_counter(
                "execution_wasm_imports_msg_cycles_accept",
                "The number of Wasm modules that import ic0.msg_cycles_accept",
            ),
            imports_mint_cycles: metrics_registry.int_counter(
                "execution_wasm_imports_mint_cycles",
                "The number of Wasm modules that import ic0.mint_cycles",
            ),
            compile: metrics_registry.histogram(
                "execution_wasm_compile",
                "The duration of Wasm module compilation including validation and instrumentation",
                decimal_buckets_with_zero(-4, 1),
            ),
        }
    }
}

/// An executor that can process any message (query or not).
pub struct WasmExecutor {
    wasm_embedder: WasmtimeEmbedder,
    config: EmbeddersConfig,
    metrics: WasmExecutorMetrics,
    log: ReplicaLogger,
}

impl WasmExecutor {
    pub fn new(
        wasm_embedder: WasmtimeEmbedder,
        metrics_registry: &MetricsRegistry,
        config: EmbeddersConfig,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            wasm_embedder,
            metrics: WasmExecutorMetrics::new(metrics_registry),
            config,
            log,
        }
    }

    pub fn observe_metrics(&self, imports_details: &WasmImportsDetails) {
        if imports_details.imports_call_simple {
            self.metrics.imports_call_simple.inc();
        }
        if imports_details.imports_call_cycles_add {
            self.metrics.imports_call_cycles_add.inc();
        }
        if imports_details.imports_canister_cycle_balance {
            self.metrics.imports_canister_cycle_balance.inc();
        }
        if imports_details.imports_msg_cycles_available {
            self.metrics.imports_msg_cycles_available.inc();
        }
        if imports_details.imports_msg_cycles_accept {
            self.metrics.imports_msg_cycles_accept.inc();
        }
        if imports_details.imports_msg_cycles_refunded {
            self.metrics.imports_msg_cycles_refunded.inc();
        }
        if imports_details.imports_mint_cycles {
            self.metrics.imports_mint_cycles.inc();
        }
    }

    pub fn compile(&self, wasm_binary: &BinaryEncodedWasm) -> HypervisorResult<EmbedderCache> {
        let _timer = self.metrics.compile.start_timer();
        validate_wasm_binary(wasm_binary, &self.config)
            .map_err(HypervisorError::from)
            .and_then(|details| {
                if details.reserved_exports > 0 {
                    self.metrics
                        .reserved_exports
                        .inc_by(details.reserved_exports as u64);
                }
                self.observe_metrics(&details.imports_details);
                instrument(wasm_binary, &InstructionCostTable::new()).map_err(HypervisorError::from)
            })
            .and_then(|output| self.wasm_embedder.compile(&output.binary))
    }

    fn get_embedder_cache(&self, wasm_binary: &WasmBinary) -> HypervisorResult<EmbedderCache> {
        let mut guard = wasm_binary.embedder_cache.lock().unwrap();
        if let Some(embedder_cache) = &*guard {
            Ok(embedder_cache.clone())
        } else {
            // The wasm_binary stored in the `ExecutionState` is not
            // instrumented so instrument it before compiling. Further, due to
            // IC upgrades, it is possible that the `validate_wasm_binary()`
            // function has changed, so also validate the binary.
            match self.compile(&wasm_binary.binary) {
                Ok(cache) => {
                    *guard = Some(cache.clone());
                    Ok(cache)
                }
                Err(err) => Err(err),
            }
        }
    }

    pub fn process(
        &self,
        WasmExecutionInput {
            api_type,
            sandbox_safe_system_state,
            canister_current_memory_usage,
            execution_parameters,
            func_ref,
            mut execution_state,
        }: WasmExecutionInput,
    ) -> (WasmExecutionOutput, ExecutionState, SystemStateChanges) {
        // Ensure that Wasm is compiled.
        let embedder_cache = match self.get_embedder_cache(&execution_state.wasm_binary) {
            Ok(embedder_cache) => embedder_cache,
            Err(err) => {
                return (
                    WasmExecutionOutput {
                        wasm_result: Err(err),
                        num_instructions_left: NumInstructions::from(0),
                        instance_stats: InstanceStats {
                            accessed_pages: 0,
                            dirty_pages: 0,
                        },
                    },
                    execution_state,
                    sandbox_safe_system_state.changes(),
                )
            }
        };
        let (wasm_execution_output, wasm_state_changes, instance_or_system_api) = process(
            func_ref,
            api_type,
            canister_current_memory_usage,
            execution_parameters,
            sandbox_safe_system_state,
            &embedder_cache,
            &self.wasm_embedder,
            &mut execution_state.wasm_memory,
            &mut execution_state.stable_memory,
            &execution_state.exported_globals,
            self.log.clone(),
        );

        // Collect logs only when the flag is enabled to avoid producing too much data.
        if EMIT_STATE_HASHES_FOR_DEBUGGING == FlagStatus::Enabled {
            self.emit_state_hashes_for_debugging(&wasm_state_changes, &wasm_execution_output);
        }

        if let Some(wasm_state_changes) = wasm_state_changes {
            execution_state.exported_globals = wasm_state_changes.globals;
        }

        let system_api = match instance_or_system_api {
            Ok(instance) => instance.into_store_data().system_api,
            Err(system_api) => system_api,
        };
        let system_state_changes = system_api.into_system_state_changes();

        (wasm_execution_output, execution_state, system_state_changes)
    }

    pub fn create_execution_state(
        &self,
        wasm_source: Vec<u8>,
        canister_root: PathBuf,
        canister_id: CanisterId,
    ) -> HypervisorResult<ExecutionState> {
        // Compile Wasm binary and cache it.
        let binary_encoded_wasm = BinaryEncodedWasm::new(wasm_source);
        let wasm_binary = WasmBinary::new(binary_encoded_wasm.clone());
        let embedder_cache = self.get_embedder_cache(&wasm_binary)?;
        let mut wasm_page_map = PageMap::default();

        let (
            exported_functions,
            globals,
            _wasm_page_delta,
            wasm_memory_size,
            wasm_validation_details,
        ) = get_initial_globals_and_memory(
            &binary_encoded_wasm,
            &embedder_cache,
            &self.wasm_embedder,
            &self.config,
            &mut wasm_page_map,
            canister_id,
        )?;

        // Create the execution state.
        let stable_memory = Memory::default();
        let execution_state = ExecutionState::new(
            canister_root,
            wasm_binary,
            ExportedFunctions::new(exported_functions),
            Memory::new(wasm_page_map, wasm_memory_size),
            stable_memory,
            globals,
            wasm_validation_details.wasm_metadata,
        );
        Ok(execution_state)
    }

    pub fn compile_count_for_testing(&self) -> u64 {
        self.metrics.compile.get_sample_count()
    }

    // Collecting information based on the result of the execution and wasm state changes.
    fn emit_state_hashes_for_debugging(
        &self,
        wasm_state_changes: &Option<WasmStateChanges>,
        wasm_execution_output: &WasmExecutionOutput,
    ) {
        // Log information only for non-empty deltas.
        // This would automatically exclude queries.
        if let Some(deltas) = wasm_state_changes {
            let delta_hashes = deltas.calculate_hashes();
            warn!(
                self.log,
                "Executed update call: result  => [{}], deltas hash => [ wasm memory delta => {}, stable memory delta => {}, globals => {}]",
                wasm_execution_output,
                delta_hashes.0,
                delta_hashes.1,
                delta_hashes.2,
            );
        };
    }
}

/// Utility function to compute the page delta. It creates a copy of `Instance`
/// dirty pages. The function is public because it is used in
/// `wasmtime_random_memory_writes` tests.
#[doc(hidden)]
pub fn compute_page_delta<'a, S: SystemApi>(
    instance: &'a mut WasmtimeInstance<S>,
    dirty_pages: &[PageIndex],
) -> Vec<(PageIndex, &'a PageBytes)> {
    // heap pointer is only valid as long as the `Instance` is alive.
    let heap_addr: *const u8 = unsafe { instance.heap_addr() };

    let mut pages = vec![];

    for page_index in dirty_pages {
        let i = page_index.get();
        // SAFETY: All dirty pages are mapped and remain valid for the lifetime of
        // `instance`. Since this function is called after Wasm execution, the dirty
        // pages are not borrowed as mutable.
        let page_ref = unsafe {
            let offset: usize = i as usize * PAGE_SIZE;
            page_bytes_from_ptr(instance, (heap_addr as *const u8).add(offset))
        };
        pages.push((*page_index, page_ref));
    }
    pages
}

pub struct DirtyPageIndices {
    pub wasm_memory_delta: Vec<PageIndex>,
    pub stable_memory_delta: Vec<PageIndex>,
}

// A struct which holds the changes of the wasm state resulted from execution.
pub struct WasmStateChanges {
    pub dirty_page_indices: DirtyPageIndices,
    pub globals: Vec<Global>,
}

impl WasmStateChanges {
    fn new(
        wasm_memory_delta: Vec<PageIndex>,
        stable_memory_delta: Vec<PageIndex>,
        globals: Vec<Global>,
    ) -> Self {
        Self {
            dirty_page_indices: DirtyPageIndices {
                wasm_memory_delta,
                stable_memory_delta,
            },
            globals,
        }
    }

    // Only used when collecting information based on the result of message execution.
    //
    // See `collect_logs_after_execution`.
    fn calculate_hashes(&self) -> (u64, u64, u64) {
        fn hash<T: Hash>(x: &[T]) -> u64 {
            let mut hasher = DefaultHasher::new();
            x.hash(&mut hasher);
            hasher.finish()
        }

        (
            hash(&self.dirty_page_indices.stable_memory_delta),
            hash(&self.dirty_page_indices.wasm_memory_delta),
            hash(&self.globals),
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn process(
    func_ref: FuncRef,
    api_type: ApiType,
    canister_current_memory_usage: NumBytes,
    execution_parameters: ExecutionParameters,
    sandbox_safe_system_state: SandboxSafeSystemState,
    embedder_cache: &EmbedderCache,
    embedder: &WasmtimeEmbedder,
    wasm_memory: &mut Memory,
    stable_memory: &mut Memory,
    globals: &[Global],
    logger: ReplicaLogger,
) -> (
    WasmExecutionOutput,
    Option<WasmStateChanges>,
    Result<WasmtimeInstance<SystemApiImpl>, SystemApiImpl>,
) {
    let instruction_limit = execution_parameters.instruction_limit;
    let canister_id = sandbox_safe_system_state.canister_id();
    let modification_tracking = api_type.modification_tracking();
    let system_api = SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        canister_current_memory_usage,
        execution_parameters,
        stable_memory.clone(),
        logger,
    );

    let mut instance = match embedder.new_instance(
        canister_id,
        embedder_cache,
        globals,
        wasm_memory.size,
        wasm_memory.page_map.clone(),
        modification_tracking,
        system_api,
    ) {
        Ok(instance) => instance,
        Err((err, system_api)) => {
            return (
                WasmExecutionOutput {
                    wasm_result: Err(err),
                    num_instructions_left: NumInstructions::from(0),
                    instance_stats: InstanceStats {
                        accessed_pages: 0,
                        dirty_pages: 0,
                    },
                },
                None,
                Err(system_api),
            );
        }
    };
    instance.set_num_instructions(instruction_limit);
    let run_result = instance.run(func_ref);

    let num_instructions_left = instance.get_num_instructions();
    let instance_stats = instance.get_stats();

    // Has the side effect up deallocating memory if message failed and
    // returning cycles from a request that wasn't sent.
    let wasm_result = instance
        .store_data_mut()
        .system_api
        .take_execution_result(run_result.as_ref().err());

    let wasm_state_changes = match run_result {
        Ok(run_result) => {
            match modification_tracking {
                ModificationTracking::Track => {
                    // Update the Wasm memory and serialize the delta.
                    let wasm_memory_delta = wasm_memory
                        .page_map
                        .update(&compute_page_delta(&mut instance, &run_result.dirty_pages));
                    wasm_memory.size = instance.heap_size();

                    // Update the stable memory and serialize the delta.
                    let stable_memory_delta = stable_memory.page_map.update(
                        &instance
                            .store_data_mut()
                            .system_api
                            .stable_memory_dirty_pages(),
                    );
                    stable_memory.size = run_result.stable_memory_size;

                    Some(WasmStateChanges::new(
                        wasm_memory_delta,
                        stable_memory_delta,
                        run_result.exported_globals,
                    ))
                }
                ModificationTracking::Ignore => None,
            }
        }
        Err(_) => None,
    };

    (
        WasmExecutionOutput {
            wasm_result,
            num_instructions_left,
            instance_stats,
        },
        wasm_state_changes,
        Ok(instance),
    )
}

/// Validates and instruments a compiled wasm module, updating the wasm memory
/// `PageMap`. Returns the exported methods and globals, as well as wasm memory
/// delta and final wasm memory size.
///
/// The only wasm code that will be run is const evaluation of the wasm globals.
#[allow(clippy::type_complexity)]
pub fn get_initial_globals_and_memory(
    binary_encoded_wasm: &BinaryEncodedWasm,
    embedder_cache: &EmbedderCache,
    embedder: &WasmtimeEmbedder,
    config: &EmbeddersConfig,
    wasm_page_map: &mut PageMap,
    canister_id: CanisterId,
) -> HypervisorResult<(
    BTreeSet<WasmMethod>,
    Vec<Global>,
    Vec<PageIndex>,
    NumWasmPages,
    WasmValidationDetails,
)> {
    // Step 1. Get data from instrumentation output.
    let wasm_validation_details = validate_wasm_binary(binary_encoded_wasm, config)?;
    let instrumentation_output = instrument(binary_encoded_wasm, &InstructionCostTable::new())?;
    let exported_functions = instrumentation_output.exported_functions;
    let wasm_memory_pages = instrumentation_output.data.as_pages();

    // Step 2. Apply the initial memory pages to the page map.
    let wasm_memory_delta = wasm_page_map.update(
        &wasm_memory_pages
            .iter()
            .map(|(index, bytes)| (*index, bytes as &PageBytes))
            .collect::<Vec<(PageIndex, &PageBytes)>>(),
    );

    // Step 3. Instantiate the Wasm module to get the globals and the memory size.
    //
    // We are using the wasm instance to initialize the execution state properly.
    // SystemApi is needed when creating a Wasmtime instance because the Linker
    // will try to assemble a list of all imports used by the wasm module.
    //
    // However, there is no need to initialize a `SystemApiImpl`
    // as we don't execute any wasm instructions at this point,
    // so we use an empty SystemApi instead.
    let system_api = SystemApiEmpty;
    // This runs the module's `start` function, but instrumentation clears the
    // start section and re-exports the start function as `canister_start`.
    let mut instance = match embedder.new_instance(
        canister_id,
        embedder_cache,
        &[],
        NumWasmPages::from(0),
        wasm_page_map.clone(),
        ModificationTracking::Ignore,
        system_api,
    ) {
        Ok(instance) => instance,
        Err((err, _system_api)) => {
            return Err(err);
        }
    };

    Ok((
        exported_functions,
        instance.get_exported_globals(),
        wasm_memory_delta,
        instance.heap_size(),
        wasm_validation_details,
    ))
}
