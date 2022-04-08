use crate::{fdenum::EnumerateInnerFileDescriptors, protocol::logging::LogRequest};
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

// Notify controller that a canister run is paused.
#[derive(Serialize, Deserialize, Clone)]
pub struct ExecutionPausedRequest {
    pub exec_id: ExecId,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecutionPausedReply {}

/// We reply to the replica controller that either the execution was
/// finished or the request failed, or request a system call or a log
/// to be applied.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Request {
    ExecutionFinished(ExecutionFinishedRequest),
    ExecutionPaused(ExecutionPausedRequest),
    LogViaReplica(LogRequest),
}

impl EnumerateInnerFileDescriptors for Request {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

/// We reply to the replica controller that either the execution was
/// finished or the request failed.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Reply {
    ExecutionFinished(ExecutionFinishedReply),
    ExecutionPaused(ExecutionPausedReply),
    LogViaReplica(()),
}

impl EnumerateInnerFileDescriptors for Reply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}
