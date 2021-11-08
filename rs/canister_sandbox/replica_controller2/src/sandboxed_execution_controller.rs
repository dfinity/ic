use ic_canister_sandbox_common::protocol;
use ic_canister_sandbox_common::sandbox_service::SandboxService;
use ic_embedders::{WasmExecutionInput, WasmExecutionOutput};
use ic_logger::ReplicaLogger;
use ic_replicated_state::canister_state::execution_state::WasmBinary;
use ic_replicated_state::EmbedderCache;
use ic_replicated_state::PageMap;
use ic_system_api::SystemStateAccessorDirect;
use ic_types::CanisterId;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use crate::active_execution_state_registry::ActiveExecutionStateRegistry;
use crate::controller_service_impl::ControllerServiceImpl;
use crate::elastic_cache::Cache;
use crate::launch_as_process::create_sandbox_process;
use crate::unique_id::UniqueId;

#[derive(Clone)]
pub struct SandboxProcess {
    /// Registry for all executions that are currently running on
    /// this backend process.
    execution_states: Arc<ActiveExecutionStateRegistry>,

    /// Handle for IPC down to sandbox.
    sandbox_service: Arc<dyn SandboxService>,

    // Cache compiled objects on the sandbox process.
    compilation_cache: Arc<Cache<UniqueId, String>>,
}

/// Manages sandboxed processes, forwards requests to the appropriate
/// process.
pub struct SandboxedExecutionController {
    backends: Mutex<HashMap<CanisterId, SandboxProcess>>,
    logger: ReplicaLogger,
    compile_count: AtomicU64,
}

impl SandboxedExecutionController {
    /// Create a new sandboxed execution controller. It provides the
    /// same interface as the
    pub fn new(logger: ReplicaLogger) -> Self {
        Self {
            backends: Mutex::new(HashMap::new()),
            logger,
            compile_count: AtomicU64::new(0),
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
            let sandbox_service = create_sandbox_process(controller_service, canister_id);

            let sandbox_service_copy = Arc::clone(&sandbox_service);

            // Set up compilation cache. Set up "deleter" in cache to issue
            // CloseWasmRequest when we drop something from cache.
            let compilation_cache = Cache::new(
                move |_key, value: String| {
                    sandbox_service_copy
                        .close_wasm(protocol::sbxsvc::CloseWasmRequest { wasm_id: value })
                        .on_completion(|_| {});
                },
                2,
            );
            let sandbox_process = SandboxProcess {
                execution_states: reg,
                sandbox_service,
                compilation_cache,
            };
            (*guard).insert(*canister_id, sandbox_process.clone());
            sandbox_process
        }
    }

    fn get_wasm_binary_id(&self, wasm_binary: &WasmBinary) -> UniqueId {
        let mut embedder_cache = wasm_binary.embedder_cache.lock().unwrap();
        if let Some(cache) = embedder_cache.as_ref() {
            if let Some(unique_id) = cache.downcast::<UniqueId>() {
                return unique_id.clone();
            }
        }
        let unique_id = UniqueId::new();
        *embedder_cache = Some(EmbedderCache::new(unique_id.clone()));
        unique_id
    }

    pub fn process(
        &self,
        WasmExecutionInput {
            api_type,
            system_state,
            canister_current_memory_usage,
            execution_parameters,
            func_ref,
            mut execution_state,
            cycles_account_manager,
        }: WasmExecutionInput,
    ) -> WasmExecutionOutput {
        let canister_id = system_state.canister_id();

        // Determine which process we want to run this on.
        let sandbox_process = self.get_sandbox_process(&canister_id);

        // Create channel through which we will receive the execution
        // output from closure (running by IPC thread at end of
        // execution).
        let (tx, rx) = std::sync::mpsc::sync_channel::<Option<protocol::structs::ExecOutput>>(1);

        // Generate an ID for this execution, register it. We need to
        // pass the system state accessor as well as the completion
        // function that gets our result back in the end.
        let id = sandbox_process.execution_states.register_execution(
            SystemStateAccessorDirect::new(
                system_state,
                cycles_account_manager,
                &execution_state.stable_memory,
            ),
            move |_id, exec_output| {
                tx.send(exec_output).unwrap();
            },
            "exec",
        );

        // Now set up resources on the sandbox to drive the execution.

        // Get compiled wasm object in sandbox. Ask cache first, upload + compile if
        // needed.
        let wasm_binary_id = self.get_wasm_binary_id(&*execution_state.wasm_binary);
        let wasm_binary_id = sandbox_process
            .compilation_cache
            .get(&wasm_binary_id, |key| {
                sandbox_process
                    .sandbox_service
                    .open_wasm(protocol::sbxsvc::OpenWasmRequest {
                        wasm_id: key.to_string(),
                        wasm_file_path: None,
                        wasm_src: execution_state.wasm_binary.binary.as_slice().to_vec(),
                    })
                    .on_completion(|_| {});
                self.compile_count.fetch_add(1, Ordering::Relaxed);
                key.to_string()
            });
        sandbox_process
            .sandbox_service
            .open_state(protocol::sbxsvc::OpenStateRequest {
                state_id: id.clone(),
                globals: execution_state.exported_globals.clone(),
                wasm_memory: serialize_pagemap(&execution_state.wasm_memory.page_map),
                memory_size: execution_state.wasm_memory.size,
            })
            .on_completion(|_| {});
        sandbox_process
            .sandbox_service
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
                exec_id: id.clone(),
                wasm_id: wasm_binary_id.to_string(),
                state_id: id.clone(),
                exec_input: protocol::structs::ExecInput {
                    canister_id,
                    func_ref,
                    api_type,
                    globals: execution_state.exported_globals.clone(),
                    canister_current_memory_usage,
                    execution_parameters,
                },
            })
            .on_completion(|_| {});

        // Wait for completion.
        let exec_output = rx.recv().unwrap().unwrap();

        // Release all resources on the sandbox process (compiled wasm is
        // left cached).
        sandbox_process
            .sandbox_service
            .close_state(protocol::sbxsvc::CloseStateRequest {
                state_id: id.clone(),
            })
            .on_completion(|_| {});
        sandbox_process
            .sandbox_service
            .close_execution(protocol::sbxsvc::CloseExecutionRequest {
                exec_id: id.clone(),
            })
            .on_completion(|_| {});

        // Release the system state (we need to return it to the caller).
        let (system_state, stable_memory) = sandbox_process
            .execution_states
            .unregister_execution(&id)
            .unwrap()
            .release_system_state();

        // Unless execution trapped, commit state.
        if exec_output.wasm_result.is_ok() {
            let page_refs: Vec<_> = exec_output
                .page_delta
                .iter()
                .map(|page| (page.index, &page.data))
                .collect();
            execution_state.wasm_memory.page_map.update(&page_refs[..]);
            execution_state.exported_globals = exec_output.globals;
            execution_state.wasm_memory.size = exec_output.heap_size;
            execution_state.stable_memory = stable_memory;
        }

        WasmExecutionOutput {
            wasm_result: exec_output.wasm_result,
            num_instructions_left: exec_output.num_instructions_left,
            system_state,
            execution_state,
            instance_stats: exec_output.instance_stats,
        }
    }

    pub fn compile_count_for_testing(&self) -> u64 {
        self.compile_count.load(Ordering::Relaxed)
    }
}

fn serialize_pagemap(page_map: &PageMap) -> Vec<protocol::structs::IndexedPage> {
    page_map
        .host_pages_iter()
        .map(|x| protocol::structs::IndexedPage {
            index: x.0,
            data: *x.1,
        })
        .collect()
}
