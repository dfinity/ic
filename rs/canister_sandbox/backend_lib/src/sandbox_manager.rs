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

use ic_canister_sandbox_common::protocol::id::{ExecId, StateId, WasmId};
use ic_canister_sandbox_common::protocol::sbxsvc::{
    CreateExecutionStateSuccessReply, MemorySerialization, OpenStateRequest,
};
use ic_canister_sandbox_common::protocol::structs::MemoryModifications;
use ic_canister_sandbox_common::{controller_service::ControllerService, protocol};
use ic_config::embedders::{Config, PersistenceType};
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
use ic_replicated_state::page_map::PageMapSerialization;
use ic_replicated_state::{EmbedderCache, Global, Memory, NumWasmPages, PageIndex, PageMap};
use ic_sys::PageBytes;
use ic_system_api::system_api_empty::SystemApiEmpty;
use ic_system_api::{ModificationTracking, SystemApiImpl};
use ic_types::CanisterId;
use ic_types::NumInstructions;
use ic_wasm_types::BinaryEncodedWasm;

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

    /// The sandbox manager that is responsible for
    /// 1) Providing the controller to talk to the replica process.
    /// 2) Creating a new execution state.
    sandbox_manager: Arc<SandboxManager>,

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
        self.sandbox_manager
            .controller
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
        sandbox_manager: Arc<SandboxManager>,
        workers: &mut threadpool::ThreadPool,
        exec_input: protocol::structs::ExecInput,
    ) -> Arc<Self> {
        let runtime_state = (*state).clone();

        let instance = Arc::new(Self {
            exec_id,
            canister_wasm,
            sandbox_manager,
            internal: Mutex::new(ExecutionInner::Running),
        });

        let instance_copy = Arc::clone(&instance);
        workers.execute(move || instance_copy.entry(exec_input, runtime_state));

        instance
    }

    // Actual wasm code execution -- this is run on the target thread
    // in the thread pool.
    fn entry(&self, exec_input: protocol::structs::ExecInput, mut runtime_state: State) {
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
            SystemStateAccessorRPC::new(self.exec_id, self.sandbox_manager.controller.clone());
        let num_instructions = exec_input.execution_parameters.instruction_limit;
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
                        // Update the Wasm memory and serialize the delta.
                        let wasm_memory_delta = runtime_state
                            .wasm_memory
                            .page_map
                            .update(&compute_page_delta(&mut instance, &run_result.dirty_pages));
                        runtime_state.wasm_memory.size = instance.heap_size();
                        let wasm_memory = MemoryModifications {
                            page_delta: runtime_state
                                .wasm_memory
                                .page_map
                                .serialize_delta(&wasm_memory_delta),
                            size: runtime_state.wasm_memory.size,
                        };

                        // Update the stable memory and serialize the delta.
                        let stable_memory_delta = runtime_state.stable_memory.page_map.update(
                            &instance
                                .store_data_mut()
                                .system_api
                                .stable_memory_dirty_pages(),
                        );
                        runtime_state.stable_memory.size = run_result.stable_memory_size;
                        let stable_memory = MemoryModifications {
                            page_delta: runtime_state
                                .stable_memory
                                .page_map
                                .serialize_delta(&stable_memory_delta),
                            size: runtime_state.stable_memory.size,
                        };

                        // Copy the globals.
                        runtime_state.globals = run_result.exported_globals;
                        let globals = runtime_state.globals.clone();

                        let next_state_id = exec_input.next_state_id;

                        self.sandbox_manager.add_state(next_state_id, runtime_state);

                        Some(protocol::structs::StateModifications {
                            globals,
                            wasm_memory,
                            stable_memory,
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
                self.sandbox_manager.controller.exec_finished(
                    protocol::ctlsvc::ExecFinishedRequest {
                        exec_id: self.exec_id,
                        exec_output,
                    },
                );
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
    pub(crate) fn close(&self) {
        let mut guard = self.internal.lock().unwrap();
        match *guard {
            ExecutionInner::FinishedOk | ExecutionInner::FinishedError => {
                *guard = ExecutionInner::Closed;
            }
            ExecutionInner::Closed => {
                unreachable!(
                    "Failed to close exec session {}: already closed",
                    self.exec_id
                );
            }
            ExecutionInner::Running => {
                unreachable!(
                    "Failed to close exec session {}: still running",
                    self.exec_id
                );
            }
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
        // TODO(EXC-755): Use the proper embedder config.
        let mut config = Config::new();
        config.persistence_type = PersistenceType::Sigsegv;

        // TODO(EXC-756): Cache WasmtimeEmbedder instance.
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

    /// Opens new wasm instance.
    pub fn open_wasm(&self, wasm_id: WasmId, wasm_file_path: Option<String>, wasm_src: Vec<u8>) {
        let mut guard = self.repr.lock().unwrap();
        assert!(
            !guard.canister_wasms.contains_key(&wasm_id),
            "Failed to open wasm session {}: id is already in use",
            wasm_id,
        );
        // Note that we can override an existing open wasm.
        let wasm = match wasm_file_path {
            Some(path) => Arc::new(CanisterWasm::new_from_file_path(path.as_ref())),
            None => Arc::new(CanisterWasm::new_from_src(wasm_src)),
        };

        guard.canister_wasms.insert(wasm_id, wasm);
    }

    /// Closes previously opened wasm instance, by id.
    pub fn close_wasm(&self, wasm_id: WasmId) {
        let mut guard = self.repr.lock().unwrap();
        let removed = guard.canister_wasms.remove(&wasm_id);
        assert!(
            removed.is_some(),
            "Failed to close wasm session {}: id not found",
            wasm_id
        );
    }

    /// Opens a new state requested by the replica process.
    pub fn open_state(&self, request: OpenStateRequest) {
        let mut guard = self.repr.lock().unwrap();
        guard.open_state(request);
    }

    /// Adds a new state after sandboxed execution.
    fn add_state(&self, state_id: StateId, state: State) {
        let mut guard = self.repr.lock().unwrap();
        guard.add_state(state_id, state);
    }

    /// Closes previously opened state instance, by id.
    pub fn close_state(&self, state_id: StateId) {
        let mut guard = self.repr.lock().unwrap();
        let removed = guard.states.remove(&state_id);
        assert!(
            removed.is_some(),
            "Failed to close state {}: id not found",
            state_id
        );
    }

    /// Opens new execution using specific code and state, passing
    /// execution input.
    ///
    /// Note that inside here we start a transaction and the state of
    /// execution can not and does not change while we are processing
    /// this particular session.
    pub fn open_execution(
        sandbox_manager: &Arc<SandboxManager>,
        exec_id: ExecId,
        wasm_id: WasmId,
        state_id: StateId,
        exec_input: protocol::structs::ExecInput,
    ) {
        let mut guard = sandbox_manager.repr.lock().unwrap();
        assert!(
            !guard.active_execs.contains_key(&exec_id),
            "Failed to open exec session {}: id is already in use",
            exec_id
        );
        let wasm_runner = guard.canister_wasms.get(&wasm_id).unwrap_or_else(|| {
            unreachable!(
                "Failed to open exec session {}: wasm {} not found",
                exec_id, wasm_id
            )
        });
        let state = guard.states.get(&state_id).unwrap_or_else(|| {
            unreachable!(
                "Failed to open exec session {}: state {} not found",
                exec_id, state_id,
            )
        });
        let exec = Execution::create(
            exec_id,
            Arc::clone(wasm_runner),
            Arc::clone(state),
            Arc::clone(sandbox_manager),
            &mut guard.workers,
            exec_input,
        );
        guard.active_execs.insert(exec_id, exec);
    }

    /// Closes previously opened execution. Execution must have
    /// finished previously.
    pub fn close_execution(&self, exec_id: ExecId) {
        let mut guard = self.repr.lock().unwrap();
        let exec = guard.active_execs.remove(&exec_id).unwrap_or_else(|| {
            unreachable!("Failed to close exec session {}: id not found", exec_id);
        });
        exec.close();
    }

    pub fn create_execution_state(
        &self,
        wasm_id: WasmId,
        wasm_source: Vec<u8>,
        wasm_page_map: PageMapSerialization,
        canister_id: CanisterId,
    ) -> HypervisorResult<CreateExecutionStateSuccessReply> {
        // Step 1: Get the compiled binary from the cache.
        let binary_encoded_wasm = BinaryEncodedWasm::new(wasm_source);
        let (embedder_cache, embedder) = {
            let guard = self.repr.lock().unwrap();
            let canister_wasm = guard.canister_wasms.get(&wasm_id).unwrap_or_else(|| {
                unreachable!(
                    "Failed to create execution state for {}: wasm {} not found",
                    canister_id, wasm_id
                )
            });
            (
                Arc::clone(&canister_wasm.compilate),
                Arc::clone(&canister_wasm.embedder),
            )
        };

        // Step 2. Get data from instrumentation output.
        // TODO(EXC-755): Use the proper embedder config.
        validate_wasm_binary(&binary_encoded_wasm, &Config::default())?;
        let instrumentation_output =
            instrument(&binary_encoded_wasm, &InstructionCostTable::new())?;
        let exported_functions = instrumentation_output.exported_functions;
        let wasm_memory_pages = instrumentation_output.data.as_pages();

        // Step 3. Apply the initial memory pages to the page map.
        let mut wasm_page_map = PageMap::deserialize(wasm_page_map).unwrap();
        let wasm_memory_delta = wasm_page_map.update(
            &wasm_memory_pages
                .iter()
                .map(|(index, bytes)| (*index, bytes as &PageBytes))
                .collect::<Vec<(PageIndex, &PageBytes)>>(),
        );

        // Step 4. Instantiate the Wasm module to get the globals and the memory size.
        //
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
            &embedder_cache,
            &[],
            NumWasmPages::from(0),
            None,
            Some(wasm_page_map.clone()),
            ModificationTracking::Ignore,
            system_api,
        ) {
            Ok(instance) => instance,
            Err((err, _system_api)) => {
                return Err(err);
            }
        };

        // Step 5. Send all necessary data for creating the execution state to replica.
        let wasm_memory = MemoryModifications {
            page_delta: wasm_page_map.serialize_delta(&wasm_memory_delta),
            size: instance.heap_size(),
        };

        Ok(CreateExecutionStateSuccessReply {
            wasm_memory,
            exported_globals: instance.get_exported_globals(),
            exported_functions,
        })
    }
}

impl SandboxManagerInt {
    fn open_state(&mut self, request: OpenStateRequest) {
        assert!(
            !self.states.contains_key(&request.state_id),
            "Failed to open state {}: id is already in use",
            request.state_id
        );
        let globals = request.state.globals;
        let wasm_memory = deserialize_memory(request.state.wasm_memory);
        let stable_memory = deserialize_memory(request.state.stable_memory);
        let state = Arc::new(State::new(globals, wasm_memory, stable_memory));
        self.states.insert(request.state_id, state);
    }

    fn add_state(&mut self, state_id: StateId, state: State) {
        let state = Arc::new(state);
        let previous = self.states.insert(state_id, state);
        assert!(previous.is_none());
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
