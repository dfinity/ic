//! A service provided by the controller to the launcher.

use ic_types::CanisterId;
use serde::{Deserialize, Serialize};

use crate::fdenum::EnumerateInnerFileDescriptors;

#[derive(Serialize, Deserialize, Clone)]
pub struct SandboxExitedRequest {
    pub canister_id: CanisterId,
}

impl EnumerateInnerFileDescriptors for SandboxExitedRequest {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Request {
    SandboxExited(SandboxExitedRequest),
}

impl EnumerateInnerFileDescriptors for Request {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SandboxExitedReply;

impl EnumerateInnerFileDescriptors for SandboxExitedReply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Reply {
    SandboxExited(SandboxExitedReply),
}

impl EnumerateInnerFileDescriptors for Reply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}
