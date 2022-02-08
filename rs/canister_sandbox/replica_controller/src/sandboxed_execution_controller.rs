use ic_canister_sandbox_common::protocol;
use ic_canister_sandbox_common::protocol::id::{MemoryId, WasmId};
use ic_canister_sandbox_common::protocol::sbxsvc::MemorySerialization;
use ic_canister_sandbox_common::protocol::structs::SandboxExecInput;
use ic_canister_sandbox_common::sandbox_service::SandboxService;
use ic_embedders::{WasmExecutionInput, WasmExecutionOutput};
use ic_interfaces::execution_environment::{HypervisorResult, InstanceStats};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::buckets::decimal_buckets_with_zero;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::canister_state::execution_state::{
    SandboxMemory, SandboxMemoryHandle, SandboxMemoryOwner, WasmBinary,
};
use ic_replicated_state::{EmbedderCache, ExecutionState, ExportedFunctions, Memory, PageMap};
use ic_system_api::sandbox_safe_system_state::SystemStateChanges;
use ic_types::{CanisterId, NumInstructions};
use ic_wasm_types::BinaryEncodedWasm;
use prometheus::{Histogram, HistogramVec, IntGauge};
use std::collections::HashMap;
use std::convert::TryInto;
use std::path::PathBuf;
use std::sync::Weak;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use crate::active_execution_state_registry::ActiveExecutionStateRegistry;
use crate::controller_service_impl::ControllerServiceImpl;
use crate::launch_as_process::{create_sandbox_argv, create_sandbox_process};
use crate::process_os_metrics;
use std::process::Child;
use std::process::ExitStatus;
use std::thread;

struct SandboxedExecutionMetrics {
    sandboxed_execution_replica_execute_duration: HistogramVec,
    sandboxed_execution_replica_execute_prepare_duration: HistogramVec,
    sandboxed_execution_replica_execute_wait_duration: HistogramVec,
    sandboxed_execution_replica_execute_finish_duration: HistogramVec,
    sandboxed_execution_sandbox_execute_duration: HistogramVec,
    sandboxed_execution_sandbox_execute_run_duration: HistogramVec,
    sandboxed_execution_spawn_process: Histogram,
    sandboxed_execution_subprocess_anon_rss_total: IntGauge,
    sandboxed_execution_subprocess_memfd_rss_total: IntGauge,
}

impl SandboxedExecutionMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            sandboxed_execution_replica_execute_duration: metrics_registry.histogram_vec(
                "sandboxed_execution_replica_execute_duration_seconds",
                "The total message execution duration in the replica controller",
                decimal_buckets_with_zero(-4, 1),
                &["api_type"],
            ),
            sandboxed_execution_replica_execute_prepare_duration: metrics_registry.histogram_vec(
                "sandboxed_execution_replica_execute_prepare_duration_seconds",
                "The time until sending an execution request to the sandbox process",
                decimal_buckets_with_zero(-4, 1),
                &["api_type"],
            ),
            sandboxed_execution_replica_execute_wait_duration: metrics_registry.histogram_vec(
                "sandboxed_execution_replica_execute_wait_duration_seconds",
                "The time from sending an execution request to receiving response",
                decimal_buckets_with_zero(-4, 1),
                &["api_type"],
            ),
            sandboxed_execution_replica_execute_finish_duration: metrics_registry.histogram_vec(
                "sandboxed_execution_replica_execute_finish_duration_seconds",
                "The time to finalize execution in the replica controller",
                decimal_buckets_with_zero(-4, 1),
                &["api_type"],
            ),
            sandboxed_execution_sandbox_execute_duration: metrics_registry.histogram_vec(
                "sandboxed_execution_sandbox_execute_duration_seconds",
                "The time from receiving an execution request to finishing execution",
                decimal_buckets_with_zero(-4, 1),
                &["api_type"],
            ),

            sandboxed_execution_sandbox_execute_run_duration: metrics_registry.histogram_vec(
                "sandboxed_execution_sandbox_execute_run_duration_seconds",
                "The time spent in the sandbox's worker thread responsible for actually performing the executions",
                decimal_buckets_with_zero(-4, 1),
                &["api_type"],
            ),
            sandboxed_execution_spawn_process: metrics_registry.histogram(
                "sandboxed_execution_spawn_process_duration_seconds",
                "The time to spawn a sandbox process",
                decimal_buckets_with_zero(-4, 1),
            ),
            sandboxed_execution_subprocess_anon_rss_total: metrics_registry.int_gauge(
                "sandboxed_execution_subprocess_anon_rss_total_kib",
                "The resident anonymous memory for all canister sandbox processes in KiB",
            ),
            sandboxed_execution_subprocess_memfd_rss_total: metrics_registry.int_gauge(
                "sandboxed_execution_subprocess_memfd_rss_total_kib",
                "The resident shared memory for all canister sandbox processes in KiB"
            ),
        }
    }
}

#[derive(Clone)]
pub struct SandboxProcess {
    /// Registry for all executions that are currently running on
    /// this backend process.
    execution_states: Arc<ActiveExecutionStateRegistry>,

    /// Handle for IPC down to sandbox.
    sandbox_service: Arc<dyn SandboxService>,

    /// Process id of the backend process.
    pid: u32,
}

/// Manages the lifetime of a remote compiled Wasm and provides its id.
///
/// It keeps a weak reference to the sandbox service to allow early
/// termination of the sandbox process when it becomes inactive.
pub struct OpenedWasm {
    sandbox_service: Weak<dyn SandboxService>,
    wasm_id: WasmId,
}

impl OpenedWasm {
    fn new(sandbox_service: Weak<dyn SandboxService>, wasm_id: WasmId) -> Self {
        Self {
            sandbox_service,
            wasm_id,
        }
    }
}

impl Drop for OpenedWasm {
    fn drop(&mut self) {
        if let Some(sandbox_service) = self.sandbox_service.upgrade() {
            sandbox_service
                .close_wasm(protocol::sbxsvc::CloseWasmRequest {
                    wasm_id: self.wasm_id,
                })
                .on_completion(|_| {});
        }
    }
}

impl std::fmt::Debug for OpenedWasm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedWasm")
            .field("wasm_id", &self.wasm_id)
            .finish()
    }
}

/// Manages the lifetime of a remote sandbox memory and provides its id.
pub struct OpenedMemory {
    sandbox_service: Arc<dyn SandboxService>,
    memory_id: MemoryId,
}

impl OpenedMemory {
    fn new(sandbox_service: Arc<dyn SandboxService>, memory_id: MemoryId) -> Self {
        Self {
            sandbox_service,
            memory_id,
        }
    }
}

impl SandboxMemoryOwner for OpenedMemory {
    fn get_id(&self) -> usize {
        self.memory_id.as_usize()
    }
}

impl Drop for OpenedMemory {
    fn drop(&mut self) {
        self.sandbox_service
            .close_memory(protocol::sbxsvc::CloseMemoryRequest {
                memory_id: self.memory_id,
            })
            .on_completion(|_| {});
    }
}

impl std::fmt::Debug for OpenedMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedMemory")
            .field("memory_id", &self.memory_id)
            .finish()
    }
}

/// Manages sandboxed processes, forwards requests to the appropriate
/// process.
pub struct SandboxedExecutionController {
    backends: Arc<Mutex<HashMap<CanisterId, SandboxProcess>>>,
    logger: ReplicaLogger,
    /// Executuable and arguments to be passed to `canister_sandbox` which are
    /// the same for all canisters.
    sandbox_exec_argv: Vec<String>,
    compile_count_for_testing: AtomicU64,
    metrics: Arc<SandboxedExecutionMetrics>,
}

impl SandboxedExecutionController {
    /// Create a new sandboxed execution controller. It provides the
    /// same interface as the `WasmExecutor`.
    pub fn new(logger: ReplicaLogger, metrics_registry: &MetricsRegistry) -> Self {
        let sandbox_exec_argv = create_sandbox_argv().expect("No canister_sandbox binary found");
        let backends = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(SandboxedExecutionMetrics::new(metrics_registry));

        let backends_copy = Arc::clone(&backends);
        let metrics_copy = Arc::clone(&metrics);
        let logger_copy = logger.clone();

        std::thread::spawn(move || {
            SandboxedExecutionController::collect_process_metrics(
                logger_copy,
                backends_copy,
                metrics_copy,
            );
        });

        Self {
            backends,
            logger,
            compile_count_for_testing: AtomicU64::new(0),
            sandbox_exec_argv,
            metrics,
        }
    }

    // Walk through all our backend processes and fetch information about them
    // from kernel. Publish these as metrics.
    fn collect_process_metrics(
        logger: ReplicaLogger,
        backends: Arc<Mutex<HashMap<CanisterId, SandboxProcess>>>,
        metrics: Arc<SandboxedExecutionMetrics>,
    ) {
        loop {
            // Collect pids while having list of backend processes locked, but
            // ensure that we only hold the lock long enough for the collection
            // to finish. This ensures that metrics collection does not unduly
            // lock out normal operation, at the risk that metrics may be
            // temporarily stale (but that is something to be expected anyways).
            let pids = {
                let mut pids = Vec::<u32>::new();
                for sandbox_process in backends.lock().unwrap().values() {
                    pids.push(sandbox_process.pid);
                }
                pids
            };

            let mut total_anon_rss: u64 = 0;
            let mut total_memfd_rss: u64 = 0;

            // For all processes requested, get their memory usage and report
            // it keyed by pid. Ignore processes failures to get
            for pid in &pids {
                if let Ok(kib) = process_os_metrics::get_nonshared_rss(*pid) {
                    total_anon_rss += kib;
                } else {
                    warn!(logger, "Unable to get anon RSS for pid {}", *pid);
                }
                if let Ok(kib) = process_os_metrics::get_memfd_rss(*pid) {
                    total_memfd_rss += kib;
                } else {
                    warn!(logger, "Unable to get memfd RSS for pid {}", *pid);
                }
            }

            metrics
                .sandboxed_execution_subprocess_anon_rss_total
                .set(total_anon_rss.try_into().unwrap());

            metrics
                .sandboxed_execution_subprocess_memfd_rss_total
                .set(total_memfd_rss.try_into().unwrap());

            // Collect metrics sufficiently infrequently that it does not use
            // excessive compute resources. It might be sensible to scale this
            // based on the time measured to perform the collection and e.g.
            // ensure that we are 99% idle instead of using a static duration
            // here.
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }

    fn get_sandbox_process(&self, canister_id: &CanisterId) -> SandboxProcess {
        let mut guard = self.backends.lock().unwrap();

        if let Some(sandbox_process) = (*guard).get(canister_id) {
            // Sandbox backend running for this canister already.
            sandbox_process.clone()
        } else {
            let _timer = self.metrics.sandboxed_execution_spawn_process.start_timer();
            // No sandbox backend found for this canister. Start a new
            // one and register it.
            let reg = Arc::new(ActiveExecutionStateRegistry::new());
            let controller_service =
                ControllerServiceImpl::new(Arc::clone(&reg), self.logger.clone());

            let (sandbox_service, child_handle) = create_sandbox_process(
                controller_service,
                canister_id,
                self.sandbox_exec_argv.clone(),
            )
            .unwrap();

            let sandbox_process = SandboxProcess {
                execution_states: reg,
                sandbox_service,
                pid: child_handle.id(),
            };
            (*guard).insert(*canister_id, sandbox_process.clone());

            self.observe_sandbox_process(child_handle, *canister_id);

            sandbox_process
        }
    }

    // Observes the exit of a sandbox process and cleans up the entry in backends
    fn observe_sandbox_process(&self, mut child_handle: Child, canister_id: CanisterId) {
        // We spawn a thread to wait for the exit notification of a sandbox process
        thread::spawn(move || {
            let pid = child_handle.id();
            let output = child_handle.wait().unwrap();

            // Panic due to the fact that we do not expect that a sandbox process ever
            // exits for now.
            panic_due_to_sandbox_exit(output, canister_id, pid);
        });
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
        let api_type_label = api_type.as_str();
        let _execute_timer = self
            .metrics
            .sandboxed_execution_replica_execute_duration
            .with_label_values(&[api_type_label])
            .start_timer();
        let prepare_timer = self
            .metrics
            .sandboxed_execution_replica_execute_prepare_duration
            .with_label_values(&[api_type_label])
            .start_timer();

        // Determine which process we want to run this on.
        let sandbox_process = self.get_sandbox_process(&sandbox_safe_system_state.canister_id());

        // Ensure that Wasm is compiled.
        let (wasm_id, compile_count) = match open_wasm(
            &sandbox_process.sandbox_service,
            &*execution_state.wasm_binary,
        ) {
            Ok((wasm_id, compile_count)) => (wasm_id, compile_count),
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
                    SystemStateChanges::default(),
                );
            }
        };

        if compile_count > 0 {
            self.compile_count_for_testing
                .fetch_add(compile_count, Ordering::Relaxed);
        }

        // Create channel through which we will receive the execution
        // output from closure (running by IPC thread at end of
        // execution).
        let (tx, rx) = std::sync::mpsc::sync_channel(1);

        // Generate an ID for this execution, register it. We need to
        // pass the system state accessor as well as the completion
        // function that gets our result back in the end.
        let exec_id =
            sandbox_process
                .execution_states
                .register_execution(move |_id, exec_output| {
                    tx.send(exec_output).unwrap();
                });

        // Now set up resources on the sandbox to drive the execution.
        let wasm_memory_handle = open_remote_memory(
            &sandbox_process.sandbox_service,
            &execution_state.wasm_memory,
        );
        let wasm_memory_id = MemoryId::from(wasm_memory_handle.get_id());
        let next_wasm_memory_id = MemoryId::new();

        let stable_memory_handle = open_remote_memory(
            &sandbox_process.sandbox_service,
            &execution_state.stable_memory,
        );
        let stable_memory_id = MemoryId::from(stable_memory_handle.get_id());
        let next_stable_memory_id = MemoryId::new();

        let subnet_available_memory = execution_parameters.subnet_available_memory.clone();

        sandbox_process
            .sandbox_service
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: SandboxExecInput {
                    func_ref,
                    api_type,
                    globals: execution_state.exported_globals.clone(),
                    canister_current_memory_usage,
                    execution_parameters,
                    next_wasm_memory_id,
                    next_stable_memory_id,
                    sandox_safe_system_state: sandbox_safe_system_state,
                },
            })
            .on_completion(|_| {});
        drop(prepare_timer);

        let wait_timer = self
            .metrics
            .sandboxed_execution_replica_execute_wait_duration
            .with_label_values(&[api_type_label])
            .start_timer();
        // Wait for completion.
        let exec_output = rx.recv().unwrap();
        drop(wait_timer);
        let _finish_timer = self
            .metrics
            .sandboxed_execution_replica_execute_finish_duration
            .with_label_values(&[api_type_label])
            .start_timer();

        // Unless execution trapped, commit state (applying execution state
        // changes, returning system state changes to caller).
        let system_state_changes = if exec_output.wasm.wasm_result.is_ok() {
            if let Some(state_modifications) = exec_output.state {
                // TODO: If a canister has broken out of wasm then it might have allocated more
                // wasm or stable memory then allowed. We should add an additional check here
                // that thet canister is still within it's allowed memory usage.
                execution_state
                    .wasm_memory
                    .page_map
                    .deserialize_delta(state_modifications.wasm_memory.page_delta);
                execution_state.wasm_memory.size = state_modifications.wasm_memory.size;
                execution_state.wasm_memory.sandbox_memory = SandboxMemory::synced(
                    wrap_remote_memory(&sandbox_process.sandbox_service, next_wasm_memory_id),
                );

                execution_state
                    .stable_memory
                    .page_map
                    .deserialize_delta(state_modifications.stable_memory.page_delta);
                execution_state.stable_memory.size = state_modifications.stable_memory.size;
                execution_state.stable_memory.sandbox_memory = SandboxMemory::synced(
                    wrap_remote_memory(&sandbox_process.sandbox_service, next_stable_memory_id),
                );

                execution_state.exported_globals = state_modifications.globals;

                // Unconditionally update the subnet available memory.
                // This value is actually a shared value under a RwLock, and the non-sandbox
                // workflow involves directly updating the value. So failed executions are
                // responsible for reseting the value themselves (see
                // `SystemApiImpl::take_execution_result`).
                subnet_available_memory.set(state_modifications.subnet_available_memory);
                state_modifications.system_state_changes
            } else {
                SystemStateChanges::default()
            }
        } else {
            SystemStateChanges::default()
        };
        self.metrics
            .sandboxed_execution_sandbox_execute_duration
            .with_label_values(&[api_type_label])
            .observe(exec_output.execute_total_duration.as_secs_f64());
        self.metrics
            .sandboxed_execution_sandbox_execute_run_duration
            .with_label_values(&[api_type_label])
            .observe(exec_output.execute_run_duration.as_secs_f64());

        (exec_output.wasm, execution_state, system_state_changes)
    }

    pub fn create_execution_state(
        &self,
        wasm_source: Vec<u8>,
        canister_root: PathBuf,
        canister_id: CanisterId,
    ) -> HypervisorResult<ExecutionState> {
        let sandbox_process = self.get_sandbox_process(&canister_id);

        // Step 1: Compile Wasm binary and cache it.
        let binary_encoded_wasm = BinaryEncodedWasm::new(wasm_source.clone());
        let wasm_binary = WasmBinary::new(binary_encoded_wasm);
        let (wasm_id, compile_count) = open_wasm(&sandbox_process.sandbox_service, &wasm_binary)?;
        if compile_count > 0 {
            self.compile_count_for_testing
                .fetch_add(compile_count, Ordering::Relaxed);
        }

        // Steps 2, 3, 4 are performed by the sandbox process.
        let wasm_page_map = PageMap::default();
        let next_wasm_memory_id = MemoryId::new();
        let reply = sandbox_process
            .sandbox_service
            .create_execution_state(protocol::sbxsvc::CreateExecutionStateRequest {
                wasm_id,
                wasm_binary: wasm_source,
                wasm_page_map: wasm_page_map.serialize(),
                next_wasm_memory_id,
                canister_id,
            })
            .sync()
            .unwrap()
            .0?;

        // Step 5. Create the execution state.
        let mut wasm_memory = Memory::new(wasm_page_map, reply.wasm_memory_modifications.size);
        wasm_memory
            .page_map
            .deserialize_delta(reply.wasm_memory_modifications.page_delta);
        wasm_memory.sandbox_memory = SandboxMemory::synced(wrap_remote_memory(
            &sandbox_process.sandbox_service,
            next_wasm_memory_id,
        ));

        let stable_memory = Memory::default();
        let execution_state = ExecutionState::new(
            canister_root,
            wasm_binary,
            ExportedFunctions::new(reply.exported_functions),
            wasm_memory,
            stable_memory,
            reply.exported_globals,
        );
        Ok(execution_state)
    }

    pub fn compile_count_for_testing(&self) -> u64 {
        self.compile_count_for_testing.load(Ordering::Relaxed)
    }
}

// Get compiled wasm object in sandbox. Ask cache first, upload + compile if
// needed.
fn open_wasm(
    sandbox_service: &Arc<dyn SandboxService>,
    wasm_binary: &WasmBinary,
) -> HypervisorResult<(WasmId, u64)> {
    let mut embedder_cache = wasm_binary.embedder_cache.lock().unwrap();
    if let Some(cache) = embedder_cache.as_ref() {
        if let Some(opened_wasm) = cache.downcast::<OpenedWasm>() {
            if let Some(cached_sandbox_service) = opened_wasm.sandbox_service.upgrade() {
                assert_eq!(
                    data_pointer(cached_sandbox_service.as_ref()),
                    data_pointer(sandbox_service.as_ref())
                );
                return Ok((opened_wasm.wasm_id, 0));
            }
        }
    }
    let wasm_id = WasmId::new();
    sandbox_service
        .open_wasm(protocol::sbxsvc::OpenWasmRequest {
            wasm_id,
            wasm_src: wasm_binary.binary.as_slice().to_vec(),
        })
        .sync()
        .unwrap()
        .0?;
    let opened_wasm = OpenedWasm::new(Arc::downgrade(sandbox_service), wasm_id);
    *embedder_cache = Some(EmbedderCache::new(opened_wasm));
    Ok((wasm_id, 1))
}

// Returns the id of the remote memory after making sure that the remote memory
// is in sync with the local memory.
fn open_remote_memory(
    sandbox_service: &Arc<dyn SandboxService>,
    memory: &Memory,
) -> SandboxMemoryHandle {
    let mut guard = memory.sandbox_memory.lock().unwrap();
    match &*guard {
        SandboxMemory::Synced(id) => id.clone(),
        SandboxMemory::Unsynced => {
            let serialized_page_map = memory.page_map.serialize();
            // Only clean memory without any dirty pages can be unsynced.
            // That is because all dirty pages are created by the sandbox and
            // they are automatically synced using `wrap_remote_memory`.
            assert!(serialized_page_map.page_delta.is_empty());
            assert!(serialized_page_map.round_delta.is_empty());
            let serialized_memory = MemorySerialization {
                page_map: serialized_page_map,
                num_wasm_pages: memory.size,
            };
            let memory_id = MemoryId::new();
            sandbox_service
                .open_memory(protocol::sbxsvc::OpenMemoryRequest {
                    memory_id,
                    memory: serialized_memory,
                })
                .on_completion(|_| {});
            let handle = wrap_remote_memory(sandbox_service, memory_id);
            *guard = SandboxMemory::Synced(handle.clone());
            handle
        }
    }
}

fn wrap_remote_memory(
    sandbox_service: &Arc<dyn SandboxService>,
    memory_id: MemoryId,
) -> SandboxMemoryHandle {
    let opened_memory = OpenedMemory::new(Arc::clone(sandbox_service), memory_id);
    SandboxMemoryHandle::new(Arc::new(opened_memory))
}

fn panic_due_to_sandbox_exit(output: ExitStatus, canister_id: CanisterId, pid: u32) {
    match output.code() {
        Some(code) => panic!(
            "Canister {}, pid {} exited with status code: {}",
            canister_id, pid, code
        ),
        None => panic!(
            "Canister {}, pid {} exited due to signal!",
            canister_id, pid
        ),
    }
}

// Extracts the data pointer from the given fat pointer.
fn data_pointer(sandbox_service: &dyn SandboxService) -> *const u8 {
    sandbox_service as *const dyn SandboxService as *const u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;
    use libc::kill;
    use std::convert::TryInto;

    #[test]
    #[should_panic(expected = "exited due to signal!")]
    fn controller_handles_killed_sandbox_process() {
        let sandbox_exec_argv = create_sandbox_argv().unwrap();
        let logger = no_op_logger();
        let canister_id = CanisterId::from_u64(42);
        let reg = Arc::new(ActiveExecutionStateRegistry::new());

        let controller_service = ControllerServiceImpl::new(Arc::clone(&reg), logger);

        let (_sandbox_service, mut child_handle) =
            create_sandbox_process(controller_service, &canister_id, sandbox_exec_argv).unwrap();

        let pid = child_handle.id();

        unsafe {
            kill(pid.try_into().unwrap(), libc::SIGKILL);
        }
        let output = child_handle.wait().unwrap();
        panic_due_to_sandbox_exit(output, canister_id, pid);
    }
}
