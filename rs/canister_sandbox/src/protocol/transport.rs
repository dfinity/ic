use crate::fdenum::EnumerateInnerFileDescriptors;
use crate::protocol::{ctllaunchersvc, ctlsvc, launchersvc, sbxsvc};
use serde::{Deserialize, Serialize};
use std::os::unix::io::RawFd;

#[derive(Serialize, Deserialize, Clone)]
pub enum Message<Request, Reply> {
    Request(Request),
    Reply(Reply),
}

impl<Request: EnumerateInnerFileDescriptors, Reply: EnumerateInnerFileDescriptors>
    EnumerateInnerFileDescriptors for Message<Request, Reply>
{
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut RawFd>) {
        match self {
            Message::Request(req) => req.enumerate_fds(fds),
            Message::Reply(rep) => rep.enumerate_fds(fds),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WireMessage<Request, Reply> {
    pub cookie: u64,
    pub msg: Message<Request, Reply>,
}

impl<Request, Reply> EnumerateInnerFileDescriptors for WireMessage<Request, Reply>
where
    Message<Request, Reply>: EnumerateInnerFileDescriptors,
{
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut RawFd>) {
        self.msg.enumerate_fds(fds);
    }
}

pub type ControllerToSandbox = WireMessage<sbxsvc::Request, ctlsvc::Reply>;
pub type SandboxToController = WireMessage<ctlsvc::Request, sbxsvc::Reply>;
pub type ControllerToLauncher = WireMessage<launchersvc::Request, ctllaunchersvc::Reply>;
pub type LauncherToController = WireMessage<ctllaunchersvc::Request, launchersvc::Reply>;
