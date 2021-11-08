use ic_canister_sandbox_common::protocol;
use ic_canister_sandbox_common::sandbox_service::SandboxService;
use ic_embedders::{WasmExecutionInput, WasmExecutionOutput};
use ic_logger::ReplicaLogger;
use ic_replicated_state::PageIndex;
use ic_replicated_state::PageMap;
use ic_sys::PageBytes;
use ic_system_api::SystemStateAccessorDirect;
use ic_types::CanisterId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::active_execution_state_registry::ActiveExecutionStateRegistry;
use crate::controller_service_impl::ControllerServiceImpl;
use crate::launch_as_process::create_sandbox_process;

#[derive(Clone)]
pub struct SandboxProcess {
    /// Registry for all executions that are currently running on
    /// this backend process.
    execution_states: Arc<ActiveExecutionStateRegistry>,

    /// Handle for IPC down to sandbox.
    sandbox_service: Arc<dyn SandboxService>,
}

/// Manages sandboxed processes, forwards requests to the appropriate
/// process.
pub struct SandboxedExecutionController {
    backends: Mutex<HashMap<CanisterId, SandboxProcess>>,
    logger: ReplicaLogger,
}

impl SandboxedExecutionController {
    /// Create a new sandboxed execution controller. It provides the
    /// same interface as the
    pub fn new(logger: ReplicaLogger) -> Self {
        Self {
            backends: Mutex::new(HashMap::new()),
            logger,
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
            let sandbox_process = SandboxProcess {
                execution_states: reg,
                sandbox_service,
            };
            (*guard).insert(*canister_id, sandbox_process.clone());
            sandbox_process
        }
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
            SystemStateAccessorDirect::new(system_state, cycles_account_manager),
            move |_id, exec_output| {
                tx.send(exec_output).unwrap();
            },
            "exec",
        );

        // Now set up resources on the sandbox to drive the execution.
        sandbox_process
            .sandbox_service
            .open_wasm(protocol::sbxsvc::OpenWasmRequest {
                wasm_id: id.clone(),
                wasm_file_path: None,
                wasm_src: execution_state.wasm_binary.binary.as_slice().to_vec(),
            })
            .on_completion(|_| {});
        sandbox_process
            .sandbox_service
            .open_state(protocol::sbxsvc::OpenStateRequest {
                state_id: id.clone(),
                globals: execution_state.exported_globals.clone(),
                wasm_memory: serialize_pagemap(&execution_state.page_map),
                memory_size: execution_state.heap_size,
            })
            .on_completion(|_| {});
        sandbox_process
            .sandbox_service
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
                exec_id: id.clone(),
                wasm_id: id.clone(),
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

        // Release all resources on the sandbox process.
        sandbox_process
            .sandbox_service
            .close_wasm(protocol::sbxsvc::CloseWasmRequest {
                wasm_id: id.clone(),
            })
            .on_completion(|_| {});
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
                commit_state: false,
            })
            .on_completion(|_| {});

        // Release the system state (we need to return it to the caller).
        let system_state = sandbox_process
            .execution_states
            .unregister_execution(&id)
            .unwrap()
            .release_system_state();

        // Unless execution trapped, commit state.
        if exec_output.wasm_result.is_ok() {
            let page_refs: Vec<(PageIndex, &PageBytes)> = exec_output
                .page_delta
                .iter()
                .map(|page| {
                    (
                        page.index,
                        protocol::structs::IndexedPage::page_bytes_ref(&page.data[..]),
                    )
                })
                .collect();
            execution_state.page_map.update(&page_refs[..]);
            execution_state.exported_globals = exec_output.globals;
            execution_state.heap_size = exec_output.heap_size;
        }

        WasmExecutionOutput {
            wasm_result: exec_output.wasm_result,
            num_instructions_left: exec_output.num_instructions_left,
            system_state,
            execution_state,
            instance_stats: exec_output.instance_stats,
        }
    }
}

fn serialize_pagemap(page_map: &PageMap) -> Vec<protocol::structs::IndexedPage> {
    page_map
        .host_pages_iter()
        .map(|x| protocol::structs::IndexedPage {
            index: x.0,
            data: x.1.to_vec(),
        })
        .collect()
}
