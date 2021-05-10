#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
use crate::canister_descriptor_table::{CanisterDescriptorTable, WasmObjectGeneration};
use crate::controller_service;
use crate::process_watcher::ProcessWatcher;
use crate::session_nonce::{session_to_string, CallContextNonce};
use ic_canister_sandbox_common::protocol::sbxsvc::CloseStateRequest;
use ic_canister_sandbox_common::protocol::{ctlsvc, sbxsvc};
use ic_canister_sandbox_common::sandbox_client_stub::SandboxClientStub;
use ic_canister_sandbox_common::sandbox_service::SandboxService;
use ic_canister_sandbox_common::*;
use ic_canister_sandbox_common::{
    controller_client_stub,
    frame_decoder::FrameDecoder,
    process::{build_sandbox_binary_relative_path, spawn_canister_sandbox_process},
    protocol, rpc, transport,
};
use ic_config::embedders::{Config, EmbedderType};
use ic_embedders::{
    Embedder, ExecutionResult, Instance, ResumeToken, WasmExecutionInput, WasmExecutionOutput,
    WasmExecutionResult, WasmtimeEmbedder,
};
use ic_embedders::{QueueConfig, ReturnToken, RunnerConfig, RunnerInput};
use ic_interfaces::execution_environment::{HypervisorError, SystemApi};
use ic_logger::{error, info, ReplicaLogger};
use ic_replicated_state::{PageDelta, PageIndex};
use ic_system_api::{ApiType, SystemApiImpl};
use ic_types::CanisterId;
use ic_types::{
    methods::{FuncRef, WasmMethod},
    Cycles,
};
use ic_utils::ic_features::cow_state_feature;
use nix::{
    sys::signal::{self, Signal},
    sys::wait::*,
    unistd::Pid,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::io::{prelude::*, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process;
use std::process::Stdio;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// We set an arbitrary really low number for initial
// manual tests to forcefully exercise the feature.
#[cfg(not(test))]
const SOFT_MAX_PROCESS_LIMIT: u16 = 4;

// For tests we would like to constantly exercise process management.
#[cfg(test)]
const SOFT_MAX_PROCESS_LIMIT: u16 = 2;

/// Handle for each sandbox process. Currently, each process handles
/// requests of a particular canister only. This type should stay
/// internal to the controller. We assume a single issuer of commands
/// to the sandbox. It comprises of a `SandboxService` (the
/// sandbox_handle) and a `ControllerServer`. The former provides an
/// interface for issuing commands to the sandbox, while the latter
/// keeps track of the state of each request and is responsible for
/// replying to the sandbox.
// N.B. Do NOT Clone this type! We keep track of thread handles, and
// there is a 1-1 correspondence with a live process and thread.
struct ProcessHandle {
    sandbox_handle: Arc<dyn SandboxService>,
    controller_server: Arc<controller_service::ControllerServer>,
    safe_shutdown: Arc<AtomicBool>,
    pid: Pid,
    recv_thread_handle: std::thread::JoinHandle<()>,
}

impl ProcessHandle {
    /// Spawn a new process, and start a `ControllerServer`.
    ///
    /// # Panics
    ///
    /// Panics if sandbox executable can not be found.
    fn create_process(logger: ReplicaLogger) -> Self {
        let controller_server = Arc::new(controller_service::ControllerServer::new(logger));
        // Attempt to find the co-located canister_sandbox. If we are
        // testing, we first check if
        // TEST_ONLY_CANISTER_SANDBOX_BIN_PATH is set and use that
        // path. Note we do not check if that path is valid until we
        // try to spawn the process later here. Otherwise we follow
        // the normal flow and expect the canister_sandbox binary to
        // exist in the same directory as this process.
        //
        // All this is gated behind the SANDBOX_TESTING_ON flag. This
        // allows us to enable this behaviour in CI at will, and adds
        // another safeguarding step away from accidentally enabling
        // testing mode.
        //
        // In production we simply expect a co-located binary.
        let exec_path = if env::var("SANDBOX_TESTING_ON".to_owned()).is_ok() {
            env::var("TEST_ONLY_CANISTER_SANDBOX_BIN_PATH".to_owned()).unwrap_or_else(|_| {
                build_sandbox_binary_relative_path("canister_sandbox")
                    .expect("No canister_sandbox binary found.")
            })
        } else {
            build_sandbox_binary_relative_path("canister_sandbox")
                .expect("No canister_sandbox binary found.")
        };

        let safe_shutdown = Arc::new(AtomicBool::new(false));

        let (sandbox_handle, pid, recv_thread_handle) = spawn_canister_sandbox_process(
            &exec_path,
            &[exec_path.clone()],
            Arc::clone(&controller_server) as Arc<_>,
            Arc::clone(&safe_shutdown),
        )
        .expect("Failed to start sandbox process");

        Self {
            sandbox_handle,
            controller_server,
            pid,
            recv_thread_handle,
            safe_shutdown,
        }
    }
    /// Checks if there are any active session states or running
    /// execution.
    fn is_active(&self) -> bool {
        self.controller_server.is_active()
    }

    /// Consumes the `ProcessHandle`, sends a shutdown SIGNAL (SIGKILL) to the
    /// process
    fn shutdown(self) -> std::io::Result<()> {
        // Set the safe shutdown flag.
        self.safe_shutdown.store(true, Ordering::SeqCst);
        let pid = self.pid;
        signal::kill(pid, Signal::SIGKILL)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))?;
        let status = match waitpid(pid, None) {
            Ok(_) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to terminate sandbox process with pid {:?} -- {:?}",
                    pid, e
                ),
            )),
        };
        // We need to wait for the thread on our side to shutdown.
        self.recv_thread_handle.join().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to join {:?}", e))
        })?;
        status
    }

    /// Message a process with an incoming request.
    fn send_to_process(&mut self, msg: RunnerInput, wasm_generation: WasmObjectGeneration) {
        let sandbox_handle = self.sandbox_handle.clone();
        self.controller_server
            .process_message(msg, sandbox_handle, wasm_generation);
    }
}

/// Manages sandboxed processes, forwards requests to the appropriate
/// process.
pub struct SandboxedExecutionController {
    /// A process map is our effective routing table, matching requests
    /// to processes. We keep a separate process map, as we need for
    /// consistency initiate any process transaction by removing it
    /// from this table.
    process_map: HashMap<CanisterId, ProcessHandle>,
    canister_map: HashMap<CanisterId, CanisterDescriptorTable>,
    /// We currently implement an LRU process eviction mechanism and do
    /// not consider other factors such as memory usage.
    ///
    /// Note we require a pinning supporting algorithm. A sandboxed
    /// process, represented by the `ProcessHandler`, can retain
    /// active state sessions. In that case we require the eviction
    /// cache we are utilizing to support pinning. Otherwise, we will
    /// end up evicting from the cache but not killing a process, and
    /// then spawning a new one, which would need to have access to
    /// the state sessions and wasm compulation objects. Note in that
    /// scenario we will end up also never killing the original
    /// process, as no callback can be directed to that process
    /// anymore and thus no state session can be collected.
    process_watcher: ProcessWatcher,
    num_msgs: Arc<AtomicUsize>,
    nonce_cnt: Arc<AtomicU64>,
    logger: ReplicaLogger,
}

impl SandboxedExecutionController {
    /// Construct a new `ProcessController`. Right now we ignore any
    /// configuration.
    pub fn new(runner_config: RunnerConfig, _task_queue_config: QueueConfig) -> Self {
        Self {
            process_map: HashMap::new(),
            canister_map: HashMap::new(),
            process_watcher: ProcessWatcher::new(SOFT_MAX_PROCESS_LIMIT),
            num_msgs: Arc::new(AtomicUsize::new(0)),
            nonce_cnt: Arc::new(AtomicU64::new(0)),
            logger: runner_config.log,
        }
    }

    /// This initiates the shutdown process for a particular canister
    /// (via `CanisterId`). This function SHOULD be called ONLY when
    /// all state sessions have been closed. Currently, we NEED to make sure NO
    /// execution sessions are running either.
    fn purge_inactive_canister_process(&mut self, canister_id: &CanisterId) -> std::io::Result<()> {
        // First remove process handle. If we receive a new request at
        // this point we will simply start a new process. This would
        // be unfortunate, but we can not throttle. We will preserve
        // correctness, as all operations in this function block event
        // processing.
        info!(
            self.logger,
            "Shutting down sandboxed process: {:?}", canister_id
        );

        let handle = self
            .process_map
            .remove(canister_id)
            .expect("Attempted to shutdown a non-existent process.");
        // Increment wasm generation. Any new request will end up
        // recompiling wasm objects.
        info!(
            self.logger,
            "Incrementing wasm object generation for {:?}", canister_id
        );
        self.increment_wasm_generation(canister_id);
        // Shutdown may happen asynchronously in the near future, thus
        // the particular ordering.
        handle.shutdown()
    }

    /// Iterate through every single process to be killed, terminate
    /// them and update state accordingly. This allows us to keep
    /// track of processes to be killed.
    ///
    /// We treat a failure to shutdown a process as an acceptable
    /// leak. We still log it as necessary, but do not consider it a
    /// stability issue currently.
    fn purge_inactive_canister_processes(&mut self) -> std::io::Result<()> {
        // Iterate over all canisters.
        let to_evict_set: Vec<CanisterId> = self
            .process_watcher
            .processes_to_be_deleted()
            .cloned()
            .collect();
        for canister_process in to_evict_set {
            let handle = self.process_map.get(&canister_process).expect(
                "Attempted to
	    shutdown non-tracked canister",
            );

            if handle.is_active() {
                // Skip this canister id. Log that it is still active.
                info!(
                    self.logger,
                    "Skipping shutting down sandboxed
		process: {:?} because it is active",
                    &canister_process
                );

                continue;
            }
            self.purge_inactive_canister_process(&canister_process)?;
            let sanity_check = self.process_watcher.process_killed(&canister_process);
            // Ensure we just killed a process that should have been
            // killed.
            assert!(sanity_check);
        }
        Ok(())
    }

    /// Increments the wasm generation for a particular canister. Each
    /// canister starts/is initialized at generation 0. Note that we
    /// do not need this to persist.
    fn increment_wasm_generation(&mut self, canister_id: &CanisterId) {
        match self.canister_map.get_mut(canister_id) {
            Some(descriptor) => {
                descriptor.increment_wasm_generation();
            }
            None => {
                self.canister_map
                    .insert(*canister_id, CanisterDescriptorTable::new());
            }
        };
    }

    /// Returns the current Wasm object generation. Initializes it if necessary.
    fn wasm_generation(&mut self, canister_id: &CanisterId) -> WasmObjectGeneration {
        let map = &mut self.canister_map;
        let descriptor = map
            .entry(*canister_id)
            .or_insert_with(CanisterDescriptorTable::new);
        descriptor.wasm_generation_object()
    }

    // Right now we break the resume logic.
    /// Attempt to route provided message. It sends the message to the
    /// appropriate process, or creates a process.
    ///
    /// # Panics
    ///
    /// Panics if sandbox executable can not be found.
    ///
    /// # Approach
    ///
    /// At this point we need to decide if we are going to start
    /// shutting down a sandboxed process and then actually route the
    /// execution request (`RunnerInput`). We follow an event based
    /// approach to how we are handling process management. That is we
    /// do not issue shutdown signals unless we receive some request
    /// from execution or a session shutdown signal. At that point we
    /// ask the `ProcessWatcher` to take a look at the current state.
    ///
    /// This signal approach allows us to have a simple
    /// implementation, clean ownership of process status, while
    /// allowing us to later add active process management, that is
    /// checking and garbage collecting sandboxed processes by simply
    /// adding timer based signaling.
    ///
    /// # Correctness
    ///
    /// Let us consider why. Firstly, we need to mark the canister as
    /// recently used before processing the request, otherwise we risk
    /// miscounting. At this point we are also in the position to
    /// understand if the process is going to be spawned or is already
    /// running. Note that while shutting down a process we can end up
    /// spawning another one for the same canister. This is acceptable
    /// and unavoidable -- except if we allow blocking or throttling
    /// of incoming requests in the runtime.
    ///
    /// # In summary diagram
    ///
    ///
    ///
    /// +--------------------------------------+
    /// |                                      |
    /// |                                      |
    /// |      Query process manager with      |
    /// |           request E                  |
    /// |                                      |
    /// |                                      |
    /// +-----------------+--------------------+
    ///                   |
    ///                   |
    ///                   |
    ///                   |
    ///                   |
    ///                   |<-----------------------------------------------+
    ///                   |                                                |
    ///            +------v----+            +------------------+           |
    ///            |           |            |                  |           |
    ///            |           |y           |                  |       y   |
    ///            | While C in+------------>   Is C active    +----------->
    ///            | canisters |            |                  |           |
    ///            | to evict  |            |                  |           |
    ///            +-----+-----+            +---------+--------+           |
    ///                  |                            |n                   |
    ///                  |                +-----------v---------+          |
    ///                  | n              |                     |          |
    ///                  |                |  Remove Proc handle |          |
    ///                  |                |         for C       |          |
    ///                  |                +-----------+---------+          |
    ///                  |                            |                    |
    ///                  |                +-----------v---------+          |
    ///                  |                |                     |          |
    ///                  |                |  Shutdown P         |          |
    ///                  |                |                     |          |
    ///                  |                +-----------+---------+          |
    ///                  |                            |                    |
    ///                  |                +-----------v---------+          |
    ///                  |                |                     |          |
    ///                  v                |  Mark P as Killed   |          |
    ///       +-------------------+       |                     |          |
    ///       |   Route E         |       +-----------+---------+          |
    ///       |                   |                   |                    |
    ///       +-------------------+       +-----------v---------+          |
    ///                                   |                     |          |
    ///                                   |  Inc wasm gen for C |          |
    ///                                   |                     |          |
    ///                                   +------------+--------+          |
    ///                                                |                   |
    ///                                                +-------------------+
    fn route_message(&mut self, msg: RunnerInput) {
        let canister_id = msg.input.system_state.canister_id();
        let wasm_generation = self.wasm_generation(&canister_id);

        // A) "Touch" with the particular canister_id.
        self.process_watcher.touch(canister_id);
        // B) Iterate over all candidate processes to be shut down. We
        // may later upper bound the number of processes we shutdown
        // to ensure we do not pause for too long. We also keep
        // everything synchronous at first.
        if let Err(e) = self.purge_inactive_canister_processes() {
            error!(self.logger, "Failed to shutdown sandboxed process: {:?}", e);
        }
        // Check for the appropriate sandbox process. Bring up the
        // process if one does not exists. Submit message. We are
        // guaranteed by the correctness of the `ProcessWatcher` to
        // not shutdown a process that we are just going to route.
        let handle = match self.process_map.get_mut(&canister_id) {
            Some(handle) => handle,
            None => {
                let new_handle = ProcessHandle::create_process(self.logger.clone());
                self.process_map.insert(canister_id, new_handle);
                // If we fail to access the table we need to panic.
                self.process_map.get_mut(&canister_id).unwrap()
            }
        };
        // There is a race here that the process will die
        // prior to processing the message. The semantics here
        // are to panic and abort both replica and sandbox.
        handle.send_to_process(msg, wasm_generation)
    }

    /// Execute provided `WasmExecutionInput`.
    ///
    /// Panics
    ///
    /// We panic if we fail to route given `WasmExecutionInput`, can
    /// not communicate with or can not start the sandbox process.
    pub fn execute(&mut self, mut input: WasmExecutionInput) -> WasmExecutionResult {
        // We need to create a sesion first and foremost. Currently,
        // we can not depend on the call context id, as it has a
        // different context and does not satisfy any monotonicity
        // properties.
        let exec_state_session = &input.execution_state.session_nonce;
        // If we have not assigned a session to this state we simply.
        self.nonce_cnt.fetch_add(1, Ordering::SeqCst);
        if exec_state_session.is_none() {
            let nonce = CallContextNonce::new(self.nonce_cnt.load(Ordering::SeqCst));
            let (base, offset) = (nonce.base, nonce.offset);
            let session_nonce = Some((base, offset));
            input.execution_state.session_nonce = session_nonce;
        }

        let (output_sender, output_receiver) = crossbeam_channel::unbounded();

        let return_token = ReturnToken {
            output_sender,
            output_receiver: output_receiver.clone(),
            extra_worker_handle: None,
            num_msgs: self.num_msgs.clone(),
        };
        // We increment the number of messages. This might end up
        // being unnecessary, but we want to keep compatibility as
        // much as possible for now.
        self.num_msgs.fetch_add(1, Ordering::SeqCst);

        let runner_input = RunnerInput {
            input,
            return_token,
        };
        // Route the message to the appropriate process.
        //
        // Note that at this point we might panic, if we fail to
        // access a process handle.
        self.route_message(runner_input);

        WasmExecutionResult { output_receiver }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;
    use sysinfo::{ProcessExt, Signal, System, SystemExt};

    #[test]
    // We have three places we can unit tests: Hydra, Gitlab and
    // locally. We can not effectively distinugish between the three
    // and we can't provide the binary build on Hydra. Because we
    // don't want to alter the abort semantics we mark this as
    // ignored. If you are developing or altering runtime code, run
    // any tests locally for now.
    #[ignore]
    fn spawn_and_shut_process() {
        let logger = no_op_logger();
        let mut s = System::new();
        // Ensure the the binary exits at this point in time and is in the cwd.
        let _sandbox_binary_path = build_sandbox_binary_relative_path("canister_sandbox")
            .expect("No canister_sandbox binary found.");
        // First we create a sandbox process.
        let handle = ProcessHandle::create_process(logger);
        let pid = handle.pid;
        let pid = pid.as_raw();
        // Check the process is running.
        s.refresh_processes();
        let process = s.get_process(pid).unwrap();
        assert_eq!(process.name(), "canister_sandbox");

        // Terminate process.
        handle.shutdown().unwrap();
        // Check process name with above pid.
        s.refresh_processes();
        if let Some(process) = s.get_process(pid) {
            if process.name() == "canister_sandbox" {
                // KILL and have init reap.
                process.kill(Signal::Kill);
                panic!("Failed to shutdown process properly. Test framework cleaned it up.");
            }
        }
    }

    #[test]
    #[ignore]
    fn emulate_abort_and_test() {
        // Unfortunately, we can not cleanup this environment variable.
        std::env::set_var("SANDBOX_TESTING_ON_MALICIOUS_SHUTDOWN", "1");
        let logger = no_op_logger();
        let mut s = System::new();
        // Ensure the the binary exits at this point in time and is in the cwd.
        let _sandbox_binary_path = build_sandbox_binary_relative_path("canister_sandbox")
            .expect("No canister_sandbox binary found.");
        // First we create a sandbox process.
        let handle = ProcessHandle::create_process(logger);
        let pid = handle.pid;
        let pid = pid.as_raw();
        // Check the process is running.
        s.refresh_processes();
        let process = s.get_process(pid).unwrap();
        assert_eq!(process.name(), "canister_sandbox");

        // Check process name with above pid.
        s.refresh_processes();
        if let Some(process) = s.get_process(pid) {
            if process.name() == "canister_sandbox" {
                // KILL and have init reap.
                process.kill(Signal::Kill);
                // We should panic at this point, as the
                // canister_sandbox process has been terminated
                // unexpectedly.
                //
                // The panic is on another thread. To catch it we need
                // to join that thread, which we do directly. This way
                // we end up checking also the recv socket thread
                // deadlocking (unfortunately due to timeout only).
                let result = handle.recv_thread_handle.join();
                assert!(result.is_err());
            }
        } else {
            panic!("Failed to spawn sandboxed process");
        }
    }
}
