//! A service provided by the controller to the launcher.

use ic_types::CanisterId;
use serde::{Deserialize, Serialize};

use crate::fdenum::EnumerateInnerFileDescriptors;

#[derive(Clone, Deserialize, Serialize)]
pub struct SandboxExitedRequest {
    pub canister_id: CanisterId,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SandboxCreatedRequest {
    pub canister_id: CanisterId,
    /// None indicates failure to spawn.
    pub pid: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
pub enum Request {
    SandboxExited(SandboxExitedRequest),
    SandboxCreated(SandboxCreatedRequest),
}

impl EnumerateInnerFileDescriptors for Request {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SandboxExitedReply;

#[derive(Clone, Deserialize, Serialize)]
pub struct SandboxCreatedReply;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Deserialize, Serialize)]
pub enum Reply {
    SandboxExited(SandboxExitedReply),
    SandboxCreated(SandboxCreatedReply),
}

impl EnumerateInnerFileDescriptors for Reply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}
