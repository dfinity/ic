use crate::protocol::logging::LogRequest;
use serde::{Deserialize, Serialize};

use super::{id::ExecId, structs::SandboxExecOutput};

// This defines the RPC service methods offered by the controller process
// (used by the sandbox) as well as the expected replies.

// Notify controller that a canister run has finished.
#[derive(Serialize, Deserialize, Clone)]
pub struct ExecutionFinishedRequest {
    // Id for this run, as set up by controller.
    pub exec_id: ExecId,

    pub exec_output: SandboxExecOutput,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecutionFinishedReply {}

/// We reply to the replica controller that either the execution was
/// finished or the request failed, or request a system call or a log
/// to be applied.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Request {
    ExecutionFinished(ExecutionFinishedRequest),
    LogViaReplica(LogRequest),
}

/// We reply to the replica controller that either the execution was
/// finished or the request failed.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Reply {
    ExecutionFinished(ExecutionFinishedReply),
    LogViaReplica(()),
}
