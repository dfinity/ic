use crate::canister_descriptor_table::WasmObjectGeneration;
use crate::sandbox_fsm::Fsm;
use crate::session_nonce::session_to_string;
use crate::{ReturnToken, RunnerInput};
use ic_canister_sandbox_common::controller_service::ControllerService;
use ic_canister_sandbox_common::protocol::ctlsvc::*;
use ic_canister_sandbox_common::protocol::logging::{LogLevel, LogRequest};
use ic_canister_sandbox_common::protocol::sbxsvc::*;
use ic_canister_sandbox_common::protocol::structs::{ExecInput, ExecOutput, Round};
use ic_canister_sandbox_common::rpc::Call;
use ic_canister_sandbox_common::sandbox_service::SandboxService;
use ic_canister_sandbox_common::{protocol, rpc};
use ic_embedders::{WasmExecutionInput, WasmExecutionOutput};
use ic_interfaces::execution_environment::{HypervisorError, TrapCode::StableMemoryOutOfBounds};
use ic_logger::{debug, info, trace, ReplicaLogger};
use ic_replicated_state::{EmbedderCache, ExecutionState, SystemState};
use ic_system_api::{ApiType, SystemStateAccessor, SystemStateAccessorDirect};
use ic_types::methods::{FuncRef, WasmMethod};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// `RunningExec` keeps track of the system state for a particular
/// execution and a particular state.
struct RunningExec {
    /// State that is used in execution.
    state_id: String,
    /// System state portion of canister under execution.
    /// Invariant: this is populated while the execution is running
    /// AND there is no syscall active on this accessor now. While
    /// a syscall is ongoing, it will "borrow" the system state
    /// accessor and return it after the syscall is done.
    system_state_accessor: Option<Box<SystemStateAccessorDirect>>,
}

type WasmIdWithGeneration = (String, WasmObjectGeneration);

type SessionState = HashMap<String, Option<(ExecutionState, ReturnToken, Arc<dyn SandboxService>)>>;

/// Responsible for responding to the sandbox. It keeps track of
/// system state to be able to respond system api requests. Session
/// information is used to ensure we have appropriately terminated
/// execution and that we do not send a callback in a session with no
/// appropriate system state session setup.
///
/// # Namespacing
///
/// Note that all state is kept per canister. This form of namespacing
/// ensures that a jail-broken sandbox can not trick the replica to
/// alter the state or session status or cancel/commit execution
/// for any other canister, which the sandbox does not have access to.
///
/// # Ordering
///
/// For each individual state branch (and effectively session), we
/// assert that a message is not going to come in prior to returning
/// previosuly processed message.
pub(crate) struct ControllerServer {
    // Note that each access is a write access. For that reason the
    // most efficient way is to use directly a Mutex instead of a
    // read/write lock.
    sessions: Arc<Mutex<SessionState>>,
    sessions_state_machines: Arc<Mutex<HashMap<String, Fsm>>>,
    session_state: Arc<Mutex<HashSet<String>>>,
    state: Arc<Mutex<HashMap<String, RunningExec>>>,
    log: ReplicaLogger,
}

fn to_rpc_exec_input(input: &WasmExecutionInput) -> ExecInput {
    ExecInput {
        canister_id: input.system_state.canister_id,
        func_ref: input.func_ref.clone(),
        api_type: input.api_type.clone(),
        globals: input.execution_state.exported_globals.clone(),
        canister_current_memory_usage: input.canister_current_memory_usage,
        execution_parameters: input.execution_parameters.clone(),
    }
}

pub fn from_rpc_exec_output(
    mut execution_state: ExecutionState,
    ExecOutput {
        wasm_result,
        num_instructions_left,
        globals,
        instance_stats,
    }: ExecOutput,
    system_state: SystemState,
) -> WasmExecutionOutput {
    execution_state.exported_globals = globals;

    WasmExecutionOutput {
        wasm_result,
        num_instructions_left,
        system_state,
        execution_state,
        instance_stats,
    }
}

impl ControllerServer {
    pub fn new(log: ReplicaLogger) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            state: Arc::new(Mutex::new(HashMap::new())),
            session_state: Arc::new(Mutex::new(HashSet::new())),
            sessions_state_machines: Arc::new(Mutex::new(HashMap::new())),
            log,
        }
    }

    /// We block and ***modify*** the *single* runner input we
    /// currently manage per canister id.
    fn set_runner_state(
        &self,
        session: String,
        runner_state: (ExecutionState, ReturnToken, Arc<dyn SandboxService>),
    ) {
        let runner_state = Some(runner_state);
        // Acquire & release the lock.
        // We will overwrite only "update" and closures that are halted. We should check
        // that for our own sanity.
        self.sessions.lock().unwrap().insert(session, runner_state);
    }

    /// Checks if there are any active session states or running
    /// execution.
    pub(crate) fn is_active(&self) -> bool {
        // Assume worst case scenario. If a bug is injected here, we
        // will still assume the worst case and not kill an active
        // session which will later most likely cause a replica
        // abort().
        //
        // Avoid acquiring locks at the same time and also so each
        // check in a separate line.
        //
        // Assert first the main question: Are we keeping any (cow) session state?
        let is_active = self.session_state.lock().unwrap().is_empty();
        // State sessions first.
        let mut exec_is_active = self.sessions.lock().unwrap().is_empty();
        // Active running sessions second.
        exec_is_active &= self.state.lock().unwrap().is_empty();
        if exec_is_active {
            // If execution is active but no state session is tracked
            // we are in a bad incoherent state.
            assert!(is_active)
        }
        is_active
    }

    /// Send a series of requests to the provided sandbox to start
    /// execution the provided `RunnerInput`. We keep track of the
    /// state of the particular session.
    ///
    /// As is guaranteed by the dispatcher and scheduler we assume
    /// that no message is going to arrive unless we are done
    /// processing with any current message on the same state.
    pub(crate) fn process_message(
        &self,
        runner_input: RunnerInput,
        sandbox_handle: Arc<dyn SandboxService>,
        wasm_generation: WasmObjectGeneration,
    ) {
        let msg = &runner_input.input;
        let round = msg.execution_state.last_executed_round.get();
        let state_root = msg
            .execution_state
            .cow_mem_mgr
            .state_root()
            .into_os_string()
            .into_string()
            .expect("Invalid OS String: not UTF-8");
        let wasm_src = msg.execution_state.wasm_binary.as_slice().to_vec();
        let exec_input = to_rpc_exec_input(msg);
        let round = Round(round);

        let session_nonce = msg
            .execution_state
            .session_nonce
            .clone()
            .expect("No session has been started for the current request");

        let id = match msg.api_type {
            ApiType::Update { .. }
            | ApiType::Start
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. } => "update".to_owned(),
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => session_to_string(session_nonce.0, session_nonce.1),
        };

        let branch = match &msg.func_ref {
            FuncRef::Method(WasmMethod::Update(_))
            | FuncRef::Method(WasmMethod::System(_))
            | FuncRef::UpdateClosure(_) => {
                // This is the Tip of the Tip. That is in the tip state
                // directory this is the latest round.
                StateBranch::TipOfTheTip
            }
            FuncRef::QueryClosure(_) | FuncRef::Method(WasmMethod::Query(_)) => {
                StateBranch::Round(round)
            }
        };

        let to_commit = &msg.func_ref.to_commit();
        let mut execution_state = runner_input.input.execution_state;
        // We need at this point to decide if we need to open a new
        // wasm state. In case we do, we update the wasm cache.
        //
        // Note that with sandboxing on, the wasm cache is just a
        // small value used to reference the cache to the sandboxed
        // process and nothing more.
        let (to_open_wasm_cache, wasm_id) = match execution_state.embedder_cache.clone() {
            Some(wasm_cache_hint) => {
                let wasm_id_hint = wasm_cache_hint.downcast::<WasmIdWithGeneration>();
                match wasm_id_hint {
                    None => {
                        // In the end this case should never happen as
                        // we should not be utilizing any other mode
                        // of operation in production besides
                        // sandboxing.
                        //
                        // We need to ensure we are placing a `WasmIdWithGeneration` type
                        // inside of the EmbedderCache.
                        let wasm_id: String = id.clone();
                        let wasm_id_hint = (wasm_id.clone(), wasm_generation);
                        execution_state.embedder_cache = Some(EmbedderCache::new(wasm_id_hint));
                        (true, wasm_id)
                    }
                    Some(wasm_id_hint_cache) => {
                        let wasm_generation_in_cache = wasm_id_hint_cache.1;
                        let wasm_id = wasm_id_hint_cache.0.clone();
                        // If we are in a new generation update it
                        if wasm_generation > wasm_generation_in_cache {
                            let wasm_id_hint = (wasm_id.clone(), wasm_generation);
                            execution_state.embedder_cache = Some(EmbedderCache::new(wasm_id_hint));
                            (true, wasm_id)
                        } else {
                            (false, wasm_id)
                        }
                    }
                }
            }
            None => {
                // We need to ensure we are placing a `WasmIdWithGeneration` type
                // inside of the EmbedderCache.
                let wasm_id: String = id.clone();
                // There was no handle inside the cache, create a new
                // one, using the current generation. As we increment
                // atomically every time we shutdown a process, we
                // know we are not going to send an out of date
                // request with a past wasm generation.
                let wasm_id_hint = (wasm_id.clone(), wasm_generation);
                execution_state.embedder_cache = Some(EmbedderCache::new(wasm_id_hint));
                (true, wasm_id)
            }
        };

        let return_token = runner_input.return_token;
        let system_state = runner_input.input.system_state;
        let system_state = Box::new(SystemStateAccessorDirect::new(
            system_state,
            runner_input.input.cycles_account_manager,
        ));
        let runner_state = (execution_state, return_token, Arc::clone(&sandbox_handle));

        self.set_runner_state(id.clone(), runner_state);
        self.insert_system_state_accessor(id.clone(), system_state);
        let open_state_req = OpenStateRequest {
            state_id: id.clone(),
            state_path: state_root,
            branch,
        };
        let open_execution_req = OpenExecutionRequest {
            exec_id: id.clone(),
            state_id: id.clone(),
            wasm_id,
            exec_input,
        };

        // We assume that no other message is being processed at this
        // state. This is guaranteed by the execution environment. In
        // particular, by the scheduler and the hypervisor.
        if to_open_wasm_cache {
            let open_wasm_req = OpenWasmRequest {
                wasm_id: id.clone(),
                wasm_file_path: None,
                wasm_src,
            };
            sandbox_handle
                .open_wasm(open_wasm_req)
                .sync()
                .expect("Failed to message OpenWasm the sandbox!");
        }

        // Open state session on the sandbox. Prior to signaling
        // we need to keep track of that open state. This allows us
        // later when we introduce asynchronicity to ensure we are not
        // going to terminate a process that is at the point of
        // processing a request. We still require marking the process
        // as processing, but actual signaling can be done after
        // marking the session state as open totally asynchronously.
        self.session_state.lock().unwrap().insert(id.clone());
        sandbox_handle
            .open_state(open_state_req)
            .sync()
            .expect("Failed to message OpenState the sandbox!");
        let fsm = Fsm::Executing(*to_commit);
        self.sessions_state_machines.lock().unwrap().insert(id, fsm);
        sandbox_handle
            .open_execution(open_execution_req)
            .sync()
            .expect("Failed to message OpenExec the sandbox!");
    }

    /// Look up the system state accessor for this execution. If the
    /// execution exists, this blocks until it becomes available --
    /// otherwise, it will return None.
    fn remove_system_state_accessor(
        &self,
        exec_id: String,
    ) -> Option<Box<SystemStateAccessorDirect>> {
        let mut guard = self.state.lock().unwrap();

        match guard.entry(exec_id.clone()) {
		Entry::Occupied(entry) => {
		    let value = entry.remove();
		    value.system_state_accessor
		},
		Entry::Vacant(_) => panic!("Controller: Attempted to remove system state. No valid system state tracked. Exec id {:?}", exec_id),
	    }
    }

    // We allow this function for now as it is used and modified in a refactoring in
    // progress.
    #[allow(dead_code)]
    /// Look up the system state accessor for this execution. If the
    /// execution exists, this blocks until it becomes available --
    /// otherwise, it will return None.
    fn borrow_system_state_accessor(
        &self,
        exec_id: String,
    ) -> Option<Box<SystemStateAccessorDirect>> {
        let mut guard = self.state.lock().unwrap();

        match guard.entry(exec_id.clone()) {
            Entry::Occupied(entry) => {
                let value = entry.remove();
                let empty_running_exec = RunningExec {
                    state_id: value.state_id.clone(),
                    system_state_accessor: None,
                };
                guard.insert(exec_id, empty_running_exec);
                value.system_state_accessor
            }
            Entry::Vacant(_) => panic!("Controller: No valid system state tracked."),
        }
    }

    // We allow this function for now as it is used and modified in a refactoring in
    // progress.
    #[allow(dead_code)]
    /// Return a previously borrowed system state accessor for this
    /// execution.
    fn return_system_state_accessor(
        &self,
        exec_id: String,
        system_state_accessor: Box<SystemStateAccessorDirect>,
    ) {
        let mut guard = self.state.lock().unwrap();

        if let Some(item) = guard.get_mut(&exec_id) {
            item.system_state_accessor = Some(system_state_accessor);
        }
    }
    /// Inserts the provided system state to the
    /// `SystemStateAccessor`. This is used for initializing the state
    /// api interface.
    fn insert_system_state_accessor(
        &self,
        exec_id: String,
        system_state_accessor: Box<SystemStateAccessorDirect>,
    ) {
        let mut guard = self.state.lock().unwrap();
        let running_exec = RunningExec {
            state_id: exec_id.clone(),
            system_state_accessor: Some(system_state_accessor),
        };
        guard.insert(exec_id, running_exec);
    }
}

impl ControllerService for ControllerServer {
    fn exec_finished(&self, req: ExecFinishedRequest) -> Call<ExecFinishedReply> {
        let exec_output = req.exec_output;
        let exec_id = req.exec_id;
        // We need to ensure here that the provided exec_id is valid for this canister.
        let to_commit = {
            let mut guard = self.sessions_state_machines.lock().unwrap();
            let session_state = guard
                .get(&exec_id)
                .unwrap_or_else(|| {
                    panic!(
                        "Sandbox signaled execution finished without a session being tracked: {:?}",
                        &exec_id
                    )
                })
                .clone();
            if !session_state.is_executing() {
                panic!(
                    "Sandbox signaled execution finished, but the session was not running: {:?}",
                    &exec_id
                );
            }
            let to_commit = session_state.to_commit();
            let new_session_state = session_state.halt();
            guard.insert(exec_id.clone(), new_session_state);
            to_commit
        };
        // Now that we released session_state_machine we can inspect the runner state.
        //
        // Every time we block to add a seesion we block our "asynchronous sandbox
        // reader&responder" here.
        let runner_state: Option<(ExecutionState, ReturnToken, Arc<dyn SandboxService>)> = {
            // We use the "double" bracketing to stress that we need
            // to acquire and release the lock here before we move on.
            {
                let mut tx = self.sessions.lock().unwrap();
                match tx.entry(exec_id.clone()) {
                    Entry::Occupied(entry) => {
                        let value = entry.remove();
                        tx.insert(exec_id.clone(), None);
                        value
                    }
                    Entry::Vacant(_) => panic!("Controller: No valid session tracked."),
                }
            }
        };
        let runner_state = runner_state.expect("Controller: No valid tracked session running.");

        let return_token = runner_state.1;
        let past_execution_state = runner_state.0;
        let sandbox_handle = runner_state.2;
        let system_state: SystemState = self
            .remove_system_state_accessor(exec_id.clone())
            .expect("No System state")
            .release_system_state();

        let to_close_state = match system_state.call_context_manager() {
            Some(manager) => manager.callbacks().is_empty(),
            None => true,
        };

        let wasm_execution_output =
            from_rpc_exec_output(past_execution_state, exec_output, system_state);

        let state_guard = Arc::clone(&self.session_state);
        // We spawn a task to ensure. N.B. We ensure we return the result after
        // close execution has finished.
        //
        // We assume it is ok to interleave ExecFInishedReply and
        // CloseExecutionRequest.
        //
        // We ***commit*** prior to propagating
        // the result.
        std::thread::spawn(move || {
            // We may allow interleaving during any of this
            // sandbox commands. Thus, it is fine to yield to
            // another task.
            let close_execution_session_request = CloseExecutionRequest {
                exec_id: exec_id.clone(),
                commit_state: to_commit,
            };

            sandbox_handle
                .close_execution(close_execution_session_request)
                .sync()
                .expect("Failed to message OpenExec the sandbox!");
            if to_close_state {
                let close_state_session_request = CloseStateRequest {
                    state_id: exec_id.clone(),
                };
                sandbox_handle
                    .close_state(close_state_session_request)
                    .sync()
                    .expect("Failed to message OpenExec the sandbox!");
                // At this point we can stop tracking this (cow) state
                // session.
                state_guard.lock().unwrap().remove(&exec_id.clone());
            }

            // Send the request.
            return_token.return_result(wasm_execution_output);
        });

        rpc::Call::new_resolved(Ok(ExecFinishedReply {}))
    }

    fn log_via_replica(&self, req: LogRequest) -> Call<()> {
        let LogRequest((log_level, log_msg)) = req;
        match log_level {
            LogLevel::Info => info!(self.log, "CANISTER_SANDBOX: {}", log_msg),
            LogLevel::Debug => debug!(self.log, "CANISTER_SANDBOX: {}", log_msg),
            LogLevel::Trace => trace!(self.log, "CANISTER_SANDBOX: {}", log_msg),
        }

        rpc::Call::new_resolved(Ok(()))
    }

    fn canister_system_call(
        &self,
        req: CanisterSystemCallRequest,
    ) -> Call<CanisterSystemCallReply> {
        let protocol::ctlsvc::CanisterSystemCallRequest { exec_id, request } = req;
        let mut guard = self.state.lock().unwrap();
        let system_state_accessor = match guard.entry(exec_id.clone()) {
            Entry::Occupied(entry) => {
                let value = entry.remove();
                let empty_running_exec = RunningExec {
                    state_id: value.state_id.clone(),
                    system_state_accessor: None,
                };
                guard.insert(exec_id.to_owned(), empty_running_exec);
                value.system_state_accessor
            }
            Entry::Vacant(_) => panic!("Controller: No valid system state tracked."),
        };

        let reply = system_state_accessor.map_or_else(
            || Err(rpc::Error::ServerError),
            |system_state_accessor| {
                use protocol::syscall::*;
                let reply = match request {
                    Request::CanisterId(_req) => Reply::CanisterId(CanisterIdReply {
                        canister_id: system_state_accessor.canister_id(),
                    }),
                    Request::Controller(_req) => Reply::Controller(ControllerReply {
                        controller: system_state_accessor.controller(),
                    }),
                    Request::MintCycles(req) => {
                        let result = system_state_accessor.mint_cycles(req.amount);
                        Reply::MintCycles(MintCyclesReply { result })
                    }
                    Request::MsgCyclesAccept(req) => {
                        let amount = system_state_accessor
                            .msg_cycles_accept(&req.call_context_id, req.max_amount);
                        Reply::MsgCyclesAccept(MsgCyclesAcceptReply { amount })
                    }
                    Request::MsgCyclesAvailable(req) => {
                        let result =
                            system_state_accessor.msg_cycles_available(&req.call_context_id);
                        Reply::MsgCyclesAvailable(MsgCyclesAvailableReply { result })
                    }
                    Request::StableSize(_req) => {
                        let result = system_state_accessor.stable_size();
                        Reply::StableSize(StableSizeReply { result })
                    }
                    Request::StableGrow(req) => {
                        let result = system_state_accessor.stable_grow(req.additional_pages);
                        Reply::StableGrow(StableGrowReply { result })
                    }
                    Request::StableGrow64(req) => {
                        let result = system_state_accessor.stable64_grow(req.additional_pages);
                        Reply::StableGrow64(StableGrow64Reply { result })
                    }
                    Request::GetNumInstructionsFromBytes(req) => {
                        let result =
                            system_state_accessor.get_num_instructions_from_bytes(req.num_bytes);
                        Reply::GetNumInstructionsFromBytes(GetNumInstructionsFromBytesReply {
                            result,
                        })
                    }
                    Request::StableRead(req) => {
                        let mut buf = Vec::<u8>::new();
                        buf.resize(req.size as usize, 0);
                        let result =
                            system_state_accessor.stable_read(0, req.offset, req.size, &mut buf);
                        let result = result.map_or_else(Err, |_| Ok(buf));
                        Reply::StableRead(StableReadReply { result })
                    }
                    Request::StableRead64(req) => {
                        let mut buf = Vec::<u8>::new();
                        buf.resize(req.size as usize, 0);
                        let result =
                            system_state_accessor.stable64_read(0, req.offset, req.size, &mut buf);
                        let result = result.map_or_else(Err, |_| Ok(buf));
                        Reply::StableRead(StableReadReply { result })
                    }
                    Request::StableWrite(req) => {
                        let result = if req.data.len() <= (u32::MAX as usize) {
                            system_state_accessor.stable_write(
                                req.offset,
                                0,
                                req.data.len() as u32,
                                &req.data,
                            )
                        } else {
                            Err(HypervisorError::Trapped(StableMemoryOutOfBounds))
                        };
                        Reply::StableWrite(StableWriteReply { result })
                    }
                    Request::StableWrite64(req) => {
                        let result = if req.data.len() <= (u64::MAX as usize) {
                            system_state_accessor.stable64_write(
                                req.offset,
                                0,
                                req.data.len() as u64,
                                &req.data,
                            )
                        } else {
                            Err(HypervisorError::Trapped(StableMemoryOutOfBounds))
                        };
                        Reply::StableWrite(StableWriteReply { result })
                    }
                    Request::CanisterCyclesBalance(_req) => {
                        let amount = system_state_accessor.canister_cycles_balance();
                        Reply::CanisterCyclesBalance(CanisterCyclesBalanceReply { amount })
                    }
                    Request::CanisterCyclesWithdraw(req) => {
                        let result = system_state_accessor.canister_cycles_withdraw(
                            req.canister_current_memory_usage,
                            req.canister_compute_allocation,
                            req.amount,
                        );
                        Reply::CanisterCyclesWithdraw(CanisterCyclesWithdrawReply { result })
                    }
                    Request::CanisterCyclesRefund(req) => {
                        system_state_accessor.canister_cycles_refund(req.cycles);
                        Reply::CanisterCyclesRefund(CanisterCyclesRefundReply {})
                    }
                    Request::SetCertifiedData(req) => {
                        system_state_accessor.set_certified_data(req.data);
                        Reply::SetCertifiedData(SetCertifiedDataReply {})
                    }
                    Request::RegisterCallback(req) => {
                        let result = system_state_accessor.register_callback(req.callback);
                        Reply::RegisterCallback(RegisterCallbackReply { result })
                    }
                    Request::UnregisterCallback(req) => {
                        system_state_accessor.unregister_callback(req.callback_id);
                        Reply::UnregisterCallback(UnregisterCallbackReply {})
                    }
                    Request::PushOutputMessage(req) => {
                        let result = system_state_accessor.push_output_request(
                            req.canister_current_memory_usage,
                            req.canister_compute_allocation,
                            req.msg,
                        );
                        Reply::PushOutputMessage(PushOutputMessageReply { result })
                    }
                    Request::CanisterStatus(_req) => {
                        let status = system_state_accessor.canister_status();
                        Reply::CanisterStatus(CanisterStatusReply { status })
                    }
                };

                if let Some(item) = guard.get_mut(&exec_id) {
                    item.system_state_accessor = Some(system_state_accessor);
                } else {
                    panic!("No system state entry was being tracked.");
                }

                Ok(protocol::ctlsvc::CanisterSystemCallReply { reply })
            },
        );
        Call::new_resolved(reply)
    }
}
