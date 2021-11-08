//! The sandbox manager provides the actual functionality of the sandbox
//! process. It allows the replica controller process to manage
//! everything required in order to execute code. It holds three
//! kinds of resources that it manages on behalf of the replica
//! controller process:
//!
//! - CanisterWasm: The (wasm) code corresponding to one canister
//! - State: The heap and other (mutable) user state associated with a canister
//! - Execution: An ongoing execution of a canister, using one wasm and state
//!   object
//!
//! All of the above objects as well as the functionality provided
//! towards the controller are found in this module.
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};

use ic_canister_sandbox_common::{
    controller_service::ControllerService,
    protocol,
    protocol::logging::{LogLevel, LogRequest},
};
use ic_config::embedders::{Config, PersistenceType};
use ic_embedders::{
    wasm_executor::compute_page_delta,
    wasm_utils::{
        instrumentation::{instrument, InstructionCostTable},
        validation::validate_wasm_binary,
    },
    WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::{HypervisorError, InstanceStats};
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{EmbedderCache, Global, NumWasmPages, PageMap};
use ic_system_api::SystemApiImpl;
use ic_types::{
    methods::{FuncRef, SystemMethod, WasmMethod},
    NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;
use memory_tracker::DirtyPageTracking;

use crate::logging::log;
use crate::system_state_accessor_rpc::SystemStateAccessorRPC;

/// This represents the "state" object as it is used in the RPC protocol.
#[derive(Clone)]
struct State {
    /// Global variables.
    globals: Vec<Global>,

    /// Wasm memory.
    pages: PageMap,

    /// Wasm memory size.
    heap_size: NumWasmPages,
}

struct ExecutionInstantiateError;

impl Debug for ExecutionInstantiateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Failed to instantatiate execution.")
    }
}

/// A canister execution currently in progress.
struct Execution {
    /// Id of the execution. This is used in communicating back to
    /// the replica (e.g. for syscalls) such that replica can associate
    /// events with the correct execution.
    exec_id: String,

    /// The canister wasm used in this execution.
    canister_wasm: Arc<CanisterWasm>,

    /// Handle for RPC service to controller (e.g. for syscalls).
    controller: Arc<dyn ControllerService>,

    /// Internal synchronized state -- the execution object itself
    /// needs to be sychronized because it is accessed from different
    /// threads (incoming RPC handling as well as actual execution
    /// thread).
    internal: Mutex<ExecutionInner>,
}
/// Inner synchronized data held in Execution. It evolves from Running
/// to {FinishedOk | FinishedError} to Closed.
enum ExecutionInner {
    /// The execution thread is running.
    Running,

    FinishedOk {},

    FinishedError {},

    /// Execution is finished and has been closed. This is an
    /// intermittent state before the object is destroyed -- it should
    /// not really be externally visible, but if it were to (e.g.
    /// due to a race condition) this also guards against illegal
    /// operations.
    Closed,
}

impl Execution {
    /// Creates new execution based on canister wasm and state. In order
    /// to start the execution, the given state object will be "locked" --
    /// if that cannot be done, then creation of execution will fail.
    /// The actual code to be run will be scheduled to the given
    /// thread pool.
    ///
    /// This will *actually* schedule and initiate a new execution.
    pub(crate) fn create(
        exec_id: String,
        canister_wasm: Arc<CanisterWasm>,
        state: Arc<State>,
        controller: Arc<dyn ControllerService>,
        workers: &mut threadpool::ThreadPool,
        exec_input: protocol::structs::ExecInput,
    ) -> Result<Arc<Self>, ExecutionInstantiateError> {
        let runtime_state = (*state).clone();

        let instance = Arc::new(Self {
            exec_id,
            canister_wasm,
            controller,
            internal: Mutex::new(ExecutionInner::Running),
        });

        let instance_copy = Arc::clone(&instance);
        workers.execute(move || instance_copy.entry(exec_input, runtime_state));

        Ok(instance)
    }

    // Actual wasm code execution -- this is run on the target thread
    // in the thread pool.
    fn entry(&self, exec_input: protocol::structs::ExecInput, runtime_state: State) {
        fn record_error(
            exec: &Execution,
            err: HypervisorError,
            num_instructions_left: NumInstructions,
            globals: Vec<Global>,
            instance_stats: InstanceStats,
            heap_size: NumWasmPages,
        ) {
            *exec.internal.lock().unwrap() = ExecutionInner::FinishedError {};
            let exec_output = protocol::structs::ExecOutput {
                wasm_result: Err(err),
                num_instructions_left,
                globals,
                instance_stats,
                page_delta: vec![],
                heap_size,
            };
            exec.controller
                .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                    exec_id: exec.exec_id.to_string(),
                    exec_output,
                });
        }

        // Prepare instance for running -- memory map, some ancillary
        // parameters and system API.
        let memory_creator = None;
        let memory_init: Option<PageMap> = Some(runtime_state.pages.clone());

        let system_state_accessor =
            SystemStateAccessorRPC::new(self.exec_id.clone(), self.controller.clone());
        let num_instructions = exec_input.execution_parameters.instruction_limit;
        let system_api = SystemApiImpl::new(
            exec_input.canister_id,
            exec_input.api_type,
            system_state_accessor,
            exec_input.canister_current_memory_usage,
            exec_input.execution_parameters,
            no_op_logger(),
        );

        let mut instance = match self.canister_wasm.embedder.new_instance(
            exec_input.canister_id,
            &self.canister_wasm.compilate,
            &runtime_state.globals,
            runtime_state.heap_size,
            memory_creator,
            memory_init,
            DirtyPageTracking::Track,
            system_api,
        ) {
            Ok(instance) => instance,
            Err((err, _)) => {
                record_error(
                    self,
                    err,
                    NumInstructions::from(0),
                    exec_input.globals,
                    InstanceStats {
                        accessed_pages: 0,
                        dirty_pages: 0,
                    },
                    NumWasmPages::from(0),
                );
                return;
            }
        };
        instance.set_num_instructions(num_instructions);

        if let FuncRef::Method(WasmMethod::System(SystemMethod::Empty)) = exec_input.func_ref {
            let exec_output = protocol::structs::ExecOutput {
                wasm_result: Ok(None),
                num_instructions_left: NumInstructions::from(0),
                instance_stats: instance.get_stats(),
                globals: instance.get_exported_globals(),
                heap_size: instance.heap_size(),
                page_delta: vec![],
            };

            *self.internal.lock().unwrap() = ExecutionInner::FinishedOk {};
            self.controller
                .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                    exec_id: self.exec_id.to_string(),
                    exec_output,
                });
            return;
        }

        // Run actual code and take out results.
        let run_result = instance.run(exec_input.func_ref);

        let num_instructions_left = instance.get_num_instructions();
        let instance_stats = instance.get_stats();
        let heap_size = instance.heap_size();

        match run_result {
            Ok(run_result) => {
                let wasm_result = instance.store_data_mut().system_api.take_execution_result();
                let page_delta = compute_page_delta(&mut instance, &run_result.dirty_pages);

                let ser_page_delta: Vec<protocol::structs::IndexedPage> = page_delta
                    .iter()
                    .map(|x| protocol::structs::IndexedPage {
                        index: x.0,
                        data: *x.1,
                    })
                    .collect();

                let mut pages = runtime_state.pages;
                pages.update(&page_delta);

                let exec_output = protocol::structs::ExecOutput {
                    wasm_result,
                    num_instructions_left,
                    instance_stats,
                    globals: run_result.exported_globals.clone(),
                    heap_size: instance.heap_size(),
                    page_delta: ser_page_delta,
                };

                *self.internal.lock().unwrap() = ExecutionInner::FinishedOk {};
                self.controller
                    .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                        exec_id: self.exec_id.to_string(),
                        exec_output,
                    });
            }
            Err(err) => {
                record_error(
                    self,
                    err,
                    num_instructions_left,
                    exec_input.globals,
                    instance_stats,
                    heap_size,
                );
            }
        }
    }

    /// Closes the current execution (assuming that it has finished).
    /// Optionally, commits changes made during execution to the state.
    /// The state is finally unlocked.
    pub(crate) fn close(&self) -> bool {
        let mut guard = self.internal.lock().unwrap();

        // "Optimistically" replace present state with "Closed" state --
        // this trickery is partially necessary as there is no other
        // way to perform a consuming in-place modification of an
        // enum.
        match std::mem::replace(&mut *guard, ExecutionInner::Closed) {
            ExecutionInner::FinishedOk {} => true,
            ExecutionInner::FinishedError {} => true,
            ExecutionInner::Running => {
                // Restore state to running if it was running before --
                // cannot close yet.
                *guard = ExecutionInner::Running;
                false
            }
            _ => false,
        }
    }
}

impl State {
    /// Instantiates a new state. This consists of the global variables,
    /// wasm memory and memory size.
    pub fn new(
        globals: &[Global],
        wasm_memory: &[protocol::structs::IndexedPage],
        memory_size: NumWasmPages,
    ) -> Self {
        let mut page_map = PageMap::new();
        let page_refs: Vec<_> = wasm_memory
            .iter()
            .map(|page| (page.index, &page.data))
            .collect();
        page_map.update(&page_refs);

        Self {
            globals: globals.to_vec(),
            pages: page_map,
            heap_size: memory_size,
        }
    }
}

/// Represents a wasm object of a canister. This is the executable code
/// of the canister.
struct CanisterWasm {
    embedder: Arc<WasmtimeEmbedder>,
    compilate: Arc<EmbedderCache>,
}

impl CanisterWasm {
    /// Creates new wasm object for given binary encoded wasm.
    pub fn new(wasm: BinaryEncodedWasm) -> Self {
        let log = ic_logger::replica_logger::no_op_logger();
        let mut config = Config::new();
        config.persistence_type = PersistenceType::Sigsegv;

        let embedder = Arc::new(WasmtimeEmbedder::new(config.clone(), log));
        let compilate = Arc::new(
            validate_wasm_binary(&wasm, &config)
                .map_err(HypervisorError::from)
                .and_then(|_| {
                    instrument(&wasm, &InstructionCostTable::new()).map_err(HypervisorError::from)
                })
                .and_then(|output| embedder.compile(PersistenceType::Sigsegv, &output.binary))
                .unwrap(),
        );
        Self {
            embedder,
            compilate,
        }
    }

    /// Creates new wasm object from file.
    pub fn new_from_file_path(wasm_file_path: &str) -> Self {
        let wasm =
            BinaryEncodedWasm::new_from_file(std::path::PathBuf::from(wasm_file_path)).unwrap();

        CanisterWasm::new(wasm)
    }

    /// Creates new wasm object from inline data (binary encoded wasm).
    pub fn new_from_src(wasm_src: Vec<u8>) -> Self {
        let wasm = BinaryEncodedWasm::new(wasm_src);

        CanisterWasm::new(wasm)
    }
}

/// Manages the entirety of the sandbox process. It provides the methods
/// through which the controller process (the replica) manages the
/// sandboxed execution.
pub struct SandboxManager {
    repr: Mutex<SandboxManagerInt>,
    controller: Arc<dyn ControllerService>,
}
struct SandboxManagerInt {
    canister_wasms: std::collections::HashMap<String, Arc<CanisterWasm>>,
    states: std::collections::HashMap<String, Arc<State>>,
    active_execs: std::collections::HashMap<String, Arc<Execution>>,
    workers: threadpool::ThreadPool,
}

impl SandboxManager {
    /// Creates new sandbox manager. In order to operate, it needs
    /// an established backward RPC channel to the controller process
    /// to relay e.g. syscalls and completions.
    pub fn new(controller: Arc<dyn ControllerService>) -> Self {
        SandboxManager {
            repr: Mutex::new(SandboxManagerInt {
                canister_wasms: HashMap::new(),
                states: HashMap::new(),
                active_execs: HashMap::new(),
                workers: threadpool::ThreadPool::new(4),
            }),
            controller,
        }
    }

    /// Opens new wasm instance. Note that if a previous wasm canister
    /// was assigned to this id, we simply update the internal table
    /// with the new wasm canister, and do NOT complain. This is
    /// necessary as we might and likely will keep a wasm execution
    /// open for multiple, requests.
    pub fn open_wasm(
        &self,
        wasm_id: &str,
        wasm_file_path: Option<String>,
        wasm_src: Vec<u8>,
    ) -> bool {
        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!(
                    "Opening wasm session: Wasm id: {:?}; wasm file path: {:?}",
                    &wasm_id, wasm_file_path
                ),
            ),
        );

        let mut guard = self.repr.lock().unwrap();
        // Note that we can override an existing open wasm.
        let wasm = match wasm_file_path.clone() {
            Some(path) => Arc::new(CanisterWasm::new_from_file_path(path.as_ref())),
            None => Arc::new(CanisterWasm::new_from_src(wasm_src)),
        };

        guard.canister_wasms.insert(wasm_id.to_string(), wasm);

        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!(
                    "Opened wasm session: Wasm id: {:?}; wasm file path: {:?}",
                    &wasm_id, wasm_file_path
                ),
            ),
        );

        true
    }

    /// Closes previously opened wasm instance, by id.
    pub fn close_wasm(&self, wasm_id: &str) -> bool {
        let mut guard = self.repr.lock().unwrap();
        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!("Closing wasm session: Wasm id: {:?}", &wasm_id),
            ),
        );
        guard.canister_wasms.remove(wasm_id).is_some()
    }

    /// Opens new state instance.
    pub fn open_state(
        &self,
        state_id: &str,
        globals: &[Global],
        pages: &[protocol::structs::IndexedPage],
        memory_size: NumWasmPages,
    ) -> bool {
        let mut guard = self.repr.lock().unwrap();

        match guard.states.get(&state_id.to_owned()) {
            Some(_) => false,
            None => {
                let state = Arc::new(State::new(globals, pages, memory_size));
                guard.states.insert(state_id.to_owned(), state);
                true
            }
        }
    }

    /// Closes previously opened state instance, by id.
    pub fn close_state(&self, state_id: &str) -> bool {
        let mut guard = self.repr.lock().unwrap();
        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!("Closing state session: state id: {:?}", &state_id),
            ),
        );
        guard.states.remove(state_id).is_some()
    }

    /// Opens new execution using specific code and state, passing
    /// execution input.
    ///
    /// Note that inside here we start a transaction and the state of
    /// execution can not and does not change while we are processing
    /// this particular session.
    pub fn open_execution(
        &self,
        exec_id: &str,
        wasm_id: &str,
        state_id: &str,
        exec_input: protocol::structs::ExecInput,
    ) -> bool {
        let mut guard = self.repr.lock().unwrap();
        eprintln!("Exec: Exec id: {:?}", &exec_id);
        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!(
                    "Opening exec session: Exec id: {:?} on state {:?} with wasm {:?}",
                    &exec_id, &wasm_id, &wasm_id
                ),
            ),
        );

        if let Some(_exec_id) = guard.active_execs.get(&exec_id.to_owned()) {
            // This should be unreachable: if we reach this point
            // we have failed to close an execution.
            //
            // Note that we do not have a lot of options regarding the panic. If we
            // are instructing to start a new execution it means that the replica
            // controller and the sandbox are now out of sync.
            unreachable!();
        }
        eprintln!("To open with wasm id : {:?}", wasm_id);
        let wasm_runner = guard.canister_wasms.get(wasm_id);
        if let Some(wasm_runner) = wasm_runner {
            eprintln!("Found wasm id : {:?}", wasm_id);
            let state = guard.states.get(state_id);
            if let Some(state) = state {
                let exec = Execution::create(
                    exec_id.to_string(),
                    Arc::clone(wasm_runner),
                    Arc::clone(state),
                    Arc::clone(&self.controller),
                    &mut guard.workers,
                    exec_input,
                );

                if let Ok(exec) = exec {
                    guard.active_execs.insert(exec_id.to_owned(), exec);
                    log(
                        &*self.controller,
                        LogRequest(
                            LogLevel::Debug,
                            format!(
                                "Opened exec session: Exec id: {:?} on state {:?} with wasm {:?}",
                                &exec_id, &wasm_id, &wasm_id
                            ),
                        ),
                    );

                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            eprintln!("NOT FOUND wasm id : {:?}", wasm_id);
            false
        }
    }

    /// Closes previously opened execution. Execution must have
    /// finished previously.
    ///
    /// If execution has not finished we return false. Disagreement
    /// between replica and sandbox needs to be handled by the
    /// replica, as we assume a malicious sandboxed process. For
    /// stability reasons we should ensure still that sandbox is
    /// robust.
    pub fn close_execution(&self, exec_id: &str) -> bool {
        let mut guard = self.repr.lock().unwrap();
        match guard.active_execs.remove(exec_id) {
            Some(exec) => {
                // **Attempt** closing the execution object.
                exec.close()
            }
            None => false,
        }
    }
}
