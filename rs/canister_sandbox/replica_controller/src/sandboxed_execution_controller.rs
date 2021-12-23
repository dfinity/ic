use ic_canister_sandbox_common::protocol;
use ic_canister_sandbox_common::protocol::id::{MemoryId, WasmId};
use ic_canister_sandbox_common::protocol::sbxsvc::MemorySerialization;
use ic_canister_sandbox_common::protocol::structs::SandboxExecInput;
use ic_canister_sandbox_common::sandbox_service::SandboxService;
use ic_embedders::{WasmExecutionInput, WasmExecutionOutput};
use ic_interfaces::execution_environment::{HypervisorResult, InstanceStats};
use ic_logger::ReplicaLogger;
use ic_replicated_state::canister_state::execution_state::{
    SandboxMemory, SandboxMemoryHandle, SandboxMemoryOwner, WasmBinary,
};
use ic_replicated_state::{EmbedderCache, ExecutionState, ExportedFunctions, Memory, PageMap};
use ic_system_api::SystemStateAccessorDirect;
use ic_types::{CanisterId, NumInstructions};
use ic_wasm_types::BinaryEncodedWasm;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use crate::active_execution_state_registry::ActiveExecutionStateRegistry;
use crate::controller_service_impl::ControllerServiceImpl;
use crate::launch_as_process::{create_sandbox_argv, create_sandbox_process};
use std::process::Child;
use std::process::ExitStatus;
use std::thread;

#[derive(Clone)]
pub struct SandboxProcess {
    /// Registry for all executions that are currently running on
    /// this backend process.
    execution_states: Arc<ActiveExecutionStateRegistry>,

    /// Handle for IPC down to sandbox.
    sandbox_service: Arc<dyn SandboxService>,
}

/// Manages the lifetime of a remote compiled Wasm and provides its id.
pub struct OpenedWasm {
    sandbox_service: Arc<dyn SandboxService>,
    wasm_id: WasmId,
}

impl OpenedWasm {
    fn new(sandbox_service: Arc<dyn SandboxService>, wasm_id: WasmId) -> Self {
        Self {
            sandbox_service,
            wasm_id,
        }
    }
}

impl Drop for OpenedWasm {
    fn drop(&mut self) {
        self.sandbox_service
            .close_wasm(protocol::sbxsvc::CloseWasmRequest {
                wasm_id: self.wasm_id,
            })
            .on_completion(|_| {});
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
}

impl SandboxedExecutionController {
    /// Create a new sandboxed execution controller. It provides the
    /// same interface as the `WasmExecutor`.
    pub fn new(logger: ReplicaLogger) -> Self {
        let sandbox_exec_argv = create_sandbox_argv().expect("No canister_sandbox binary found");
        Self {
            backends: Arc::new(Mutex::new(HashMap::new())),
            logger,
            compile_count_for_testing: AtomicU64::new(0),
            sandbox_exec_argv,
        }
    }

    fn get_sandbox_process(&self, canister_id: &CanisterId) -> SandboxProcess {
        let mut guard = self.backends.lock().unwrap();

        if let Some(sandbox_process) = (*guard).get(canister_id) {
            // Sandbox backend running for this canister already.
            sandbox_process.clone()
        } else {
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
            static_system_state,
            canister_current_memory_usage,
            execution_parameters,
            func_ref,
            mut execution_state,
            system_state_accessor,
        }: WasmExecutionInput,
    ) -> (
        WasmExecutionOutput,
        ExecutionState,
        SystemStateAccessorDirect,
    ) {
        // Determine which process we want to run this on.
        let sandbox_process = self.get_sandbox_process(&static_system_state.canister_id());

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
                    system_state_accessor,
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
        let exec_id = sandbox_process.execution_states.register_execution(
            system_state_accessor,
            move |_id, exec_output| {
                tx.send(exec_output).unwrap();
            },
        );

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
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
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
                    static_system_state,
                },
            })
            .on_completion(|_| {});

        // Wait for completion.
        let (exec_output, state_modifications) = rx.recv().unwrap().unwrap();

        // Release all resources on the sandbox process (compiled wasm is
        // left cached).
        sandbox_process
            .sandbox_service
            .close_execution(protocol::sbxsvc::CloseExecutionRequest { exec_id })
            .on_completion(|_| {});

        // Release the system state accessor (we need to return it to the caller).
        let system_state_accessor = sandbox_process
            .execution_states
            .unregister_execution(exec_id)
            .unwrap();

        // Unless execution trapped, commit state.
        if exec_output.wasm_result.is_ok() {
            if let Some(state_modifications) = state_modifications {
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
            }
        }

        (exec_output, execution_state, system_state_accessor)
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
        let mut wasm_page_map = PageMap::default();
        let reply = sandbox_process
            .sandbox_service
            .create_execution_state(protocol::sbxsvc::CreateExecutionStateRequest {
                wasm_id,
                wasm_binary: wasm_source,
                wasm_page_map: wasm_page_map.serialize(),
                canister_id,
            })
            .sync()
            .unwrap()
            .0?;

        // Step 5. Create the execution state.
        wasm_page_map.deserialize_delta(reply.wasm_memory.page_delta);
        let wasm_memory = Memory::new(wasm_page_map, reply.wasm_memory.size);
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
            return Ok((opened_wasm.wasm_id, 0));
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
    let opened_wasm = OpenedWasm::new(Arc::clone(sandbox_service), wasm_id);
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
