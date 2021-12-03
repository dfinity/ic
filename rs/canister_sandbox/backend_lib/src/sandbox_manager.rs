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
use std::collections::{BTreeSet, HashMap};
use std::fmt::{Debug, Formatter};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ic_canister_sandbox_common::protocol::id::{ExecId, StateId, WasmId};
use ic_canister_sandbox_common::protocol::sbxsvc::{
    CreateExecutionStateSuccessReply, MemoryDeltaSerialization, MemorySerialization,
    OpenStateRequest, StateSerialization,
};
use ic_canister_sandbox_common::{
    controller_service::ControllerService,
    protocol,
    protocol::logging::{LogLevel, LogRequest},
};
use ic_config::embedders::{Config, PersistenceType};
use ic_embedders::cow_memory_creator::CowMemoryCreator;
use ic_embedders::{
    wasm_executor::compute_page_delta,
    wasm_utils::{
        instrumentation::{instrument, InstructionCostTable},
        validation::validate_wasm_binary,
    },
    WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, InstanceStats, SystemApi,
};
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::page_map::PageSerialization;
use ic_replicated_state::{
    EmbedderCache, ExecutionState, ExportedFunctions, Global, Memory, NumWasmPages, PageMap,
};
use ic_system_api::system_api_empty::SystemApiEmpty;
use ic_system_api::{ModificationTracking, SystemApiImpl};
use ic_types::CanisterId;
use ic_types::{
    methods::{FuncRef, SystemMethod, WasmMethod},
    NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;

use crate::logging::log;
use crate::system_state_accessor_rpc::SystemStateAccessorRPC;

/// This represents the "state" object as it is used in the RPC protocol.
#[derive(Clone)]
struct State {
    /// Global variables.
    globals: Vec<Global>,

    /// Wasm memory.
    wasm_memory: Memory,

    /// The canister's stable memory.
    stable_memory: Memory,
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
    exec_id: ExecId,

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
    FinishedOk,
    FinishedError,
    /// Execution is finished and has been closed. This is an
    /// intermittent state before the object is destroyed -- it should
    /// not really be externally visible, but if it were to (e.g.
    /// due to a race condition) this also guards against illegal
    /// operations.
    Closed,
}

impl Execution {
    fn record_error(&self, exec_output: protocol::structs::ExecOutput) {
        *self.internal.lock().unwrap() = ExecutionInner::FinishedError;
        self.controller
            .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                exec_id: self.exec_id,
                exec_output,
            });
    }

    /// Creates new execution based on canister wasm and state. In order
    /// to start the execution, the given state object will be "locked" --
    /// if that cannot be done, then creation of execution will fail.
    /// The actual code to be run will be scheduled to the given
    /// thread pool.
    ///
    /// This will *actually* schedule and initiate a new execution.
    pub(crate) fn create(
        exec_id: ExecId,
        canister_wasm: Arc<CanisterWasm>,
        state: Arc<State>,
        controller: Arc<dyn ControllerService>,
        workers: &mut threadpool::ThreadPool,
        exec_input: protocol::structs::ExecInput,
    ) -> Arc<Self> {
        let runtime_state = (*state).clone();

        let instance = Arc::new(Self {
            exec_id,
            canister_wasm,
            controller,
            internal: Mutex::new(ExecutionInner::Running),
        });

        let instance_copy = Arc::clone(&instance);
        workers.execute(move || instance_copy.entry(exec_input, runtime_state));

        instance
    }

    // Actual wasm code execution -- this is run on the target thread
    // in the thread pool.
    fn entry(&self, exec_input: protocol::structs::ExecInput, runtime_state: State) {
        fn error_exec_output(
            err: HypervisorError,
            num_instructions_left: NumInstructions,
            instance_stats: InstanceStats,
        ) -> protocol::structs::ExecOutput {
            protocol::structs::ExecOutput {
                wasm_result: Err(err),
                num_instructions_left,
                instance_stats,
                state_modifications: None,
            }
        }

        // Prepare instance for running -- memory map, some ancillary
        // parameters and system API.
        let memory_creator = None;
        let memory_init = Some(runtime_state.wasm_memory.page_map.clone());
        let stable_memory = runtime_state.stable_memory.clone();

        let system_state_accessor =
            SystemStateAccessorRPC::new(self.exec_id, self.controller.clone());
        let num_instructions = exec_input.execution_parameters.instruction_limit;
        let initial_stable_memory_size = stable_memory.size;
        let canister_id = exec_input.static_system_state.canister_id();
        let modification_tracking = exec_input.api_type.modification_tracking();
        let subnet_available_memory = exec_input
            .execution_parameters
            .subnet_available_memory
            .clone();
        let system_api = SystemApiImpl::new(
            exec_input.api_type,
            system_state_accessor,
            exec_input.static_system_state,
            exec_input.canister_current_memory_usage,
            exec_input.execution_parameters,
            stable_memory,
            no_op_logger(),
        );

        let mut instance = match self.canister_wasm.embedder.new_instance(
            canister_id,
            &self.canister_wasm.compilate,
            &runtime_state.globals,
            runtime_state.wasm_memory.size,
            memory_creator,
            memory_init,
            modification_tracking,
            system_api,
        ) {
            Ok(instance) => instance,
            Err((err, _)) => {
                self.record_error(error_exec_output(
                    err,
                    NumInstructions::from(0),
                    InstanceStats {
                        accessed_pages: 0,
                        dirty_pages: 0,
                    },
                ));
                return;
            }
        };
        instance.set_num_instructions(num_instructions);

        if let FuncRef::Method(WasmMethod::System(SystemMethod::Empty)) = exec_input.func_ref {
            let exec_output = protocol::structs::ExecOutput {
                wasm_result: Ok(None),
                num_instructions_left: NumInstructions::from(0),
                instance_stats: instance.get_stats(),
                state_modifications: Some(protocol::structs::StateModifications {
                    globals: instance.get_exported_globals(),
                    wasm_memory_size: instance.heap_size(),
                    wasm_memory_page_delta: vec![],
                    stable_memory_size: initial_stable_memory_size,
                    stable_memory_page_delta: vec![],
                    subnet_available_memory: subnet_available_memory.get(),
                }),
            };

            *self.internal.lock().unwrap() = ExecutionInner::FinishedOk;
            self.controller
                .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                    exec_id: self.exec_id,
                    exec_output,
                });
            return;
        }

        // Run actual code and take out results.
        let run_result = instance.run(exec_input.func_ref);

        let num_instructions_left = instance.get_num_instructions();
        let instance_stats = instance.get_stats();

        // Has the side effect up deallocating unused memory.
        let wasm_result = instance.store_data_mut().system_api.take_execution_result();
        match run_result {
            Ok(run_result) => {
                let state_modifications = match modification_tracking {
                    ModificationTracking::Ignore => None,
                    ModificationTracking::Track => {
                        let page_delta = compute_page_delta(&mut instance, &run_result.dirty_pages);

                        let ser_page_delta: Vec<_> = page_delta
                            .iter()
                            .map(|x| PageSerialization {
                                index: x.0,
                                bytes: *x.1,
                            })
                            .collect();

                        let wasm_memory_size = instance.heap_size();

                        let stable_memory_delta = instance
                            .store_data_mut()
                            .system_api
                            .stable_memory_dirty_pages();

                        let ser_stable_memory_page_delta: Vec<_> = stable_memory_delta
                            .into_iter()
                            .map(|(index, bytes)| PageSerialization {
                                index,
                                bytes: *bytes,
                            })
                            .collect();
                        Some(protocol::structs::StateModifications {
                            globals: run_result.exported_globals.clone(),
                            wasm_memory_size,
                            wasm_memory_page_delta: ser_page_delta,
                            stable_memory_size: run_result.stable_memory_size,
                            stable_memory_page_delta: ser_stable_memory_page_delta,
                            subnet_available_memory: subnet_available_memory.get(),
                        })
                    }
                };

                // This has a side effect of refunding unused cycles.
                let _ = instance
                    .into_store_data()
                    .system_api
                    .release_system_state_accessor();
                let exec_output = protocol::structs::ExecOutput {
                    wasm_result,
                    num_instructions_left,
                    instance_stats,
                    state_modifications,
                };

                *self.internal.lock().unwrap() = ExecutionInner::FinishedOk;
                self.controller
                    .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                        exec_id: self.exec_id,
                        exec_output,
                    });
            }
            Err(err) => {
                let system_api = instance.into_store_data().system_api;
                // This has a side effect of refunding unused cycles.
                let _ = system_api.release_system_state_accessor();
                self.record_error(error_exec_output(
                    err,
                    num_instructions_left,
                    instance_stats,
                ));
            }
        }
    }

    /// Closes the current execution (assuming that it has finished).
    /// Returns true if the close completed successfully.
    pub(crate) fn close(&self) -> bool {
        let mut guard = self.internal.lock().unwrap();
        match *guard {
            ExecutionInner::FinishedOk | ExecutionInner::FinishedError => {
                *guard = ExecutionInner::Closed;
                true
            }
            ExecutionInner::Closed | ExecutionInner::Running => false,
        }
    }
}

impl State {
    /// Instantiates a new state. This consists of the global variables and
    /// the wasm memory.
    pub fn new(globals: Vec<Global>, wasm_memory: Memory, stable_memory: Memory) -> Self {
        Self {
            globals: globals.to_vec(),
            wasm_memory,
            stable_memory,
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
        let instrumentation_output = validate_wasm_binary(&wasm, &config)
            .map_err(HypervisorError::from)
            .and_then(|_| {
                instrument(&wasm, &InstructionCostTable::new()).map_err(HypervisorError::from)
            })
            .unwrap();

        let compilate = Arc::new(
            embedder
                .compile(PersistenceType::Sigsegv, &instrumentation_output.binary)
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
    canister_wasms: std::collections::HashMap<WasmId, Arc<CanisterWasm>>,
    states: std::collections::HashMap<StateId, Arc<State>>,
    active_execs: std::collections::HashMap<ExecId, Arc<Execution>>,
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
        wasm_id: WasmId,
        wasm_file_path: Option<String>,
        wasm_src: Vec<u8>,
    ) -> bool {
        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!(
                    "Opening wasm session: {}; wasm file path: {:?}",
                    wasm_id, wasm_file_path
                ),
            ),
        );

        let mut guard = self.repr.lock().unwrap();
        // Note that we can override an existing open wasm.
        let wasm = match wasm_file_path.clone() {
            Some(path) => Arc::new(CanisterWasm::new_from_file_path(path.as_ref())),
            None => Arc::new(CanisterWasm::new_from_src(wasm_src)),
        };

        guard.canister_wasms.insert(wasm_id, wasm);

        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!(
                    "Opened wasm session: {}; wasm file path: {:?}",
                    wasm_id, wasm_file_path
                ),
            ),
        );

        true
    }

    /// Closes previously opened wasm instance, by id.
    pub fn close_wasm(&self, wasm_id: WasmId) -> bool {
        let mut guard = self.repr.lock().unwrap();
        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!("Closing wasm session: {}", wasm_id),
            ),
        );
        guard.canister_wasms.remove(&wasm_id).is_some()
    }

    pub fn open_state(&self, request: OpenStateRequest) -> bool {
        let mut guard = self.repr.lock().unwrap();
        guard.open_state(request)
    }

    /// Closes previously opened state instance, by id.
    pub fn close_state(&self, state_id: StateId) -> bool {
        let mut guard = self.repr.lock().unwrap();
        log(
            &*self.controller,
            LogRequest(
                LogLevel::Debug,
                format!("Closing state session: {}", state_id),
            ),
        );
        guard.states.remove(&state_id).is_some()
    }

    /// Opens new execution using specific code and state, passing
    /// execution input.
    ///
    /// Note that inside here we start a transaction and the state of
    /// execution can not and does not change while we are processing
    /// this particular session.
    pub fn open_execution(
        &self,
        exec_id: ExecId,
        wasm_id: WasmId,
        state_id: StateId,
        exec_input: protocol::structs::ExecInput,
    ) -> bool {
        let mut guard = self.repr.lock().unwrap();
        eprintln!(
            "Opening exec session: {}, {}, {}",
            exec_id, state_id, wasm_id
        );

        if let Some(_exec_id) = guard.active_execs.get(&exec_id) {
            // This should be unreachable: if we reach this point
            // we have failed to close an execution.
            //
            // Note that we do not have a lot of options regarding the panic. If we
            // are instructing to start a new execution it means that the replica
            // controller and the sandbox are now out of sync.
            eprintln!("Exec session {} error: id is already in use.", exec_id);
            unreachable!();
        }
        let wasm_runner = guard.canister_wasms.get(&wasm_id);
        if let Some(wasm_runner) = wasm_runner {
            let state = guard.states.get(&state_id);
            if let Some(state) = state {
                let exec = Execution::create(
                    exec_id,
                    Arc::clone(wasm_runner),
                    Arc::clone(state),
                    Arc::clone(&self.controller),
                    &mut guard.workers,
                    exec_input,
                );
                guard.active_execs.insert(exec_id, exec);
                true
            } else {
                eprintln!(
                    "Exec session {} error: state {} not found",
                    exec_id, state_id
                );
                false
            }
        } else {
            eprintln!("Exec session {} error: wasm {} not found", exec_id, wasm_id);
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
    pub fn close_execution(&self, exec_id: ExecId) -> bool {
        let mut guard = self.repr.lock().unwrap();
        match guard.active_execs.remove(&exec_id) {
            Some(exec) => {
                // **Attempt** closing the execution object.
                exec.close()
            }
            None => {
                eprintln!("Failed to close exec session {}: not found", exec_id);
                false
            }
        }
    }

    pub fn create_execution_state(
        &self,
        wasm_binary: Vec<u8>,
        canister_root: PathBuf,
        canister_id: CanisterId,
    ) -> HypervisorResult<CreateExecutionStateSuccessReply> {
        let embedder = WasmtimeEmbedder::new(Config::default(), no_op_logger());
        let wasm_binary = BinaryEncodedWasm::new(wasm_binary);
        validate_wasm_binary(&wasm_binary, &Config::default())?;
        let instrumentation_output = instrument(&wasm_binary, &InstructionCostTable::new())?;
        let wasm_memory_pages = instrumentation_output.data.as_pages();
        let execution_state = ExecutionState::new(
            instrumentation_output.binary.clone(),
            canister_root,
            ExportedFunctions::new(instrumentation_output.exported_functions),
            &wasm_memory_pages,
        )?;

        let memory_creator = if execution_state.mapped_state.is_some() {
            let mapped_state = Arc::as_ref(execution_state.mapped_state.as_ref().unwrap());
            Some(Arc::new(CowMemoryCreator::new(mapped_state)))
        } else {
            None
        };

        let compilate = embedder
            .compile(PersistenceType::Sigsegv, &instrumentation_output.binary)
            .unwrap();

        // We are using the wasm instance to initialize the execution state properly.
        // SystemApi is needed when creating a Wasmtime instance because the Linker
        // will try to assemble a list of all imports used by the wasm module.
        //
        // However, there is no need to initialize a `SystemApiImpl`
        // as we don't execute any wasm instructions at this point,
        // so we use an empty SystemApi instead.
        let system_api = SystemApiEmpty;
        let mut instance = match embedder.new_instance(
            canister_id,
            &compilate,
            &execution_state.exported_globals,
            NumWasmPages::from(0),
            memory_creator,
            Some(PageMap::default()),
            ModificationTracking::Ignore,
            system_api,
        ) {
            Ok(instance) => instance,
            Err((err, _system_api)) => {
                return Err(err);
            }
        };

        Ok(CreateExecutionStateSuccessReply {
            wasm_memory_pages: wasm_memory_pages
                .into_iter()
                .map(|(index, bytes)| PageSerialization { index, bytes })
                .collect(),
            wasm_memory_size: instance.heap_size(),
            exported_globals: instance.get_exported_globals(),
            exported_functions: BTreeSet::clone(execution_state.exports.as_ref()),
        })
    }
}

impl SandboxManagerInt {
    fn open_state(&mut self, request: OpenStateRequest) -> bool {
        if self.states.get(&request.state_id).is_some() {
            eprintln!("Failed to open {}: already exists", request.state_id);
            return false;
        }

        let (globals, wasm_memory, stable_memory) = match request.state {
            StateSerialization::Full {
                globals,
                wasm_memory,
                stable_memory,
            } => {
                let wasm_memory = deserialize_memory(wasm_memory);
                let stable_memory = deserialize_memory(stable_memory);
                (globals, wasm_memory, stable_memory)
            }
            StateSerialization::Delta {
                parent_state_id,
                globals,
                wasm_memory,
                stable_memory,
            } => {
                let parent_state = self.states.get(&parent_state_id).unwrap();
                let wasm_memory =
                    deserialize_delta_memory(&parent_state.wasm_memory.page_map, wasm_memory);
                let stable_memory =
                    deserialize_delta_memory(&parent_state.stable_memory.page_map, stable_memory);
                (globals, wasm_memory, stable_memory)
            }
        };

        let state = Arc::new(State::new(globals, wasm_memory, stable_memory));
        self.states.insert(request.state_id, state);
        true
    }
}

// Constructs `Memory` from the given full memory serialization.
fn deserialize_memory(memory: MemorySerialization) -> Memory {
    let page_map = PageMap::deserialize(memory.page_map).unwrap();
    Memory {
        page_map,
        size: memory.num_wasm_pages,
    }
}

// Constructs `Memory` by applying the given delta to the given parent memory.
fn deserialize_delta_memory(parent_page_map: &PageMap, delta: MemoryDeltaSerialization) -> Memory {
    let mut page_map = parent_page_map.clone();
    if let Some(page_allocator) = delta.page_allocator {
        page_map.deserialize_allocator(page_allocator);
    }
    page_map.deserialize_delta(delta.page_delta);
    Memory {
        page_map,
        size: delta.num_wasm_pages,
    }
}
