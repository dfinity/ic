/// Utility class to handle IPC endpoint exposed to sandbox process.
///
/// This implements the IPC interface exposed by the "replica controller
/// process" towards the "sandbox process": Whenever the sandbox process
/// issues an upwards call, it ends up here.
///
/// This is just a utility implementing the required interface and
/// passing information towards upper layers. In order to perform its
/// function, it is dependent on knowing which executions are "active"
/// on a specific sandbox process by their IDs, and the associated
/// target points provided by upper layers (system state access and
/// completion closure).
use crate::controller_service::ControllerService;
use crate::protocol;
use crate::rpc;
use ic_logger::{debug, error, info, trace, ReplicaLogger};

use super::active_execution_state_registry::ActiveExecutionStateRegistry;
use super::active_execution_state_registry::CompletionResult;

use std::sync::Arc;

pub struct ControllerServiceImpl {
    registry: Arc<ActiveExecutionStateRegistry>,
    log: ReplicaLogger,
}

impl ControllerServiceImpl {
    /// Create new instance of controller service.
    pub fn new(registry: Arc<ActiveExecutionStateRegistry>, log: ReplicaLogger) -> Arc<Self> {
        Arc::new(ControllerServiceImpl { registry, log })
    }

    pub fn flush_with_errors(&self) {
        let execs = self.registry.take_all();
        for (_exec_id, entry) in execs {
            // here we could do something like
            // entry.completion(exec_id, CompletionResult::Finished(exec_failed_result));
            // to pass the error to whoever is waiting, but since in the current setup we want to panic
            // there anyway, it is sufficient to just drop the closure
            // so the channel on which sandboxed_execution_controller is waiting will get disconnected
            drop(entry)
        }
    }
}

impl ControllerService for ControllerServiceImpl {
    fn execution_finished(
        &self,
        req: protocol::ctlsvc::ExecutionFinishedRequest,
    ) -> rpc::Call<protocol::ctlsvc::ExecutionFinishedReply> {
        let exec_id = req.exec_id;
        let exec_output = req.exec_output;
        // Sandbox is telling us that execution has finished for this
        // ID. We will validate this ID by looking up the execution
        // state for this ID and extracting its closure. If the closure
        // is not there, then the sandbox is "buggy" (or worse) and
        // trying to either issue "double-completions" or completions
        // for non-existent executions. Deal with this by ignoring
        // such calls (but log them).
        // Maybe we also want to deal with this in more radical ways
        // (e.g. forcibly terminate the sandbox process).
        let reply = self.registry.take(exec_id).map_or_else(
            || {
                // Should we log the entire erroneous request? It
                // could both be large and hold canister-sensitive
                // data, so maybe this is not advisable.
                error!(
                    self.log,
                    "Wasm sandbox process sent completion for non-existent execution {}", &exec_id
                );
                Err(rpc::Error::ServerError)
            },
            |completion| {
                completion(exec_id, CompletionResult::Finished(exec_output));
                Ok(protocol::ctlsvc::ExecutionFinishedReply {})
            },
        );
        rpc::Call::new_resolved(reply)
    }

    fn execution_paused(
        &self,
        req: protocol::ctlsvc::ExecutionPausedRequest,
    ) -> rpc::Call<protocol::ctlsvc::ExecutionPausedReply> {
        let exec_id = req.exec_id;
        let slice = req.slice;
        let reply = self.registry.take(exec_id).map_or_else(
            || {
                error!(
                    self.log,
                    "Wasm sandbox process paused non-existent execution {}", &exec_id
                );
                Err(rpc::Error::ServerError)
            },
            |completion| {
                completion(exec_id, CompletionResult::Paused(slice));
                Ok(protocol::ctlsvc::ExecutionPausedReply {})
            },
        );
        rpc::Call::new_resolved(reply)
    }

    fn log_via_replica(&self, req: protocol::logging::LogRequest) -> rpc::Call<()> {
        let protocol::logging::LogRequest(level, message) = req;
        match level {
            protocol::logging::LogLevel::Info => info!(self.log, "CANISTER_SANDBOX: {}", message),
            protocol::logging::LogLevel::Debug => debug!(self.log, "CANISTER_SANDBOX: {}", message),
            protocol::logging::LogLevel::Trace => trace!(self.log, "CANISTER_SANDBOX: {}", message),
        }

        rpc::Call::new_resolved(Ok(()))
    }
}
