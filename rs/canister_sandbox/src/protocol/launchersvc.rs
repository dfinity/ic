//! Service provided by the launcher process. It can spawn new processes,
//! passing on the given socket and should be notified before any of those
//! processes are killed.

use std::os::unix::io::RawFd;

use ic_types::CanisterId;
use serde::{Deserialize, Serialize};

use crate::fdenum::EnumerateInnerFileDescriptors;

#[derive(Clone, Deserialize, Serialize)]
pub struct LaunchSandboxRequest {
    pub sandbox_exec_path: String,
    pub argv: Vec<String>,
    pub canister_id: CanisterId,
    pub socket: RawFd,
}

impl EnumerateInnerFileDescriptors for LaunchSandboxRequest {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        fds.push(&mut self.socket)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct LaunchSandboxReply {
    pub pid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaunchCompilerRequest {
    pub exec_path: String,
    pub argv: Vec<String>,
    pub socket: RawFd,
}

impl EnumerateInnerFileDescriptors for LaunchCompilerRequest {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        fds.push(&mut self.socket)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct LaunchCompilerReply {
    pub pid: u32,
}

/// Instruct the Sandbox Launcher process to terminate.
#[derive(Clone, Deserialize, Serialize)]
pub struct TerminateRequest {}

/// Ack signal to the controller that termination was complete.
#[derive(Clone, Deserialize, Serialize)]
pub struct TerminateReply {}

#[derive(Clone, Deserialize, Serialize)]
pub enum Request {
    LaunchSandbox(LaunchSandboxRequest),
    LaunchCompiler(LaunchCompilerRequest),
    Terminate(TerminateRequest),
}

impl EnumerateInnerFileDescriptors for Request {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        match self {
            Request::LaunchSandbox(req) => req.enumerate_fds(fds),
            Request::LaunchCompiler(req) => req.enumerate_fds(fds),
            Request::Terminate(_req) => {}
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Deserialize, Serialize)]
pub enum Reply {
    LaunchSandbox(LaunchSandboxReply),
    LaunchCompiler(LaunchCompilerReply),
    Terminate(TerminateReply),
}

impl EnumerateInnerFileDescriptors for Reply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}
