use crate::protocol::{logging::LogRequest, structs, syscall};
use serde::{Deserialize, Serialize};

// This defines the RPC service methods offered by the controller process
// (used by the sandbox) as well as the expected replies.

// Notify controller that a canister run has finished.
#[derive(Serialize, Deserialize, Clone)]
pub struct ExecFinishedRequest {
    // Id for this run, as set up by controller.
    pub exec_id: String,
    pub exec_output: structs::ExecOutput,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ExecFinishedReply {}

// Relay system call made by canister to controller.
#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterSystemCallRequest {
    // Id for this run, as set up by controller.
    pub exec_id: String,

    // The actual system call and its arguments.
    pub request: syscall::Request,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterSystemCallReply {
    // Response to the system call.
    pub reply: syscall::Reply,
}

/// We reply to the replica controller that either the execution was
/// finished or the request failed, or request a system call or a log
/// to be applied.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Request {
    ExecFinished(ExecFinishedRequest),
    CanisterSystemCall(CanisterSystemCallRequest),
    LogViaReplica(LogRequest),
}

/// We reply to the replica controller that either the execution was
/// finished or the request failed.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Reply {
    ExecFinished(ExecFinishedReply),
    CanisterSystemCall(CanisterSystemCallReply),
    LogViaReplica(()),
}
