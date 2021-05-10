use crate::protocol::{ctlsvc, sbxsvc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub enum ControllerToSandboxMessage {
    Request(sbxsvc::Request),
    Reply(ctlsvc::Reply),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ControllerToSandbox {
    pub cookie: u64,
    pub msg: ControllerToSandboxMessage,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum SandboxToControllerMessage {
    Request(ctlsvc::Request),
    Reply(sbxsvc::Reply),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SandboxToController {
    pub cookie: u64,
    pub msg: SandboxToControllerMessage,
}
