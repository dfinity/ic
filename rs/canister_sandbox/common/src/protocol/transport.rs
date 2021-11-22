use crate::fdenum::EnumerateInnerFileDescriptors;
use crate::protocol::{ctlsvc, sbxsvc};
use serde::{Deserialize, Serialize};
use std::os::unix::io::RawFd;

#[derive(Serialize, Deserialize, Clone)]
pub enum ControllerToSandboxMessage {
    Request(sbxsvc::Request),
    Reply(ctlsvc::Reply),
}

impl EnumerateInnerFileDescriptors for ControllerToSandboxMessage {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut RawFd>) {
        match self {
            ControllerToSandboxMessage::Request(req) => {
                req.enumerate_fds(fds);
            }
            ControllerToSandboxMessage::Reply(_) => (),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ControllerToSandbox {
    pub cookie: u64,
    pub msg: ControllerToSandboxMessage,
}

impl EnumerateInnerFileDescriptors for ControllerToSandbox {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut RawFd>) {
        self.msg.enumerate_fds(fds);
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum SandboxToControllerMessage {
    Request(ctlsvc::Request),
    Reply(sbxsvc::Reply),
}

impl EnumerateInnerFileDescriptors for SandboxToControllerMessage {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut RawFd>) {}
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SandboxToController {
    pub cookie: u64,
    pub msg: SandboxToControllerMessage,
}

impl EnumerateInnerFileDescriptors for SandboxToController {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut RawFd>) {
        self.msg.enumerate_fds(fds);
    }
}
