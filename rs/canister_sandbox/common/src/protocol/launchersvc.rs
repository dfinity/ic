//! Service provided by the launcher process. It can spawn new processes,
//! passing on the given socket and should be notified before any of those
//! processes are killed.

use std::os::unix::io::RawFd;

use ic_types::CanisterId;
use serde::{Deserialize, Serialize};

use crate::fdenum::EnumerateInnerFileDescriptors;

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
pub struct LaunchSandboxReply {
    pub pid: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Request {
    LaunchSandbox(LaunchSandboxRequest),
}

impl EnumerateInnerFileDescriptors for Request {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        match self {
            Request::LaunchSandbox(req) => req.enumerate_fds(fds),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Reply {
    LaunchSandbox(LaunchSandboxReply),
}

impl EnumerateInnerFileDescriptors for Reply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}
