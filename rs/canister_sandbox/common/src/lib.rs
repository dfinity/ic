pub mod controller_client_stub;
pub mod controller_service;
pub mod frame_decoder;
pub mod process;
pub mod rpc;
pub mod sandbox_client_stub;
pub mod sandbox_service;
pub mod transport;
pub mod protocol {
    pub mod ctlsvc;
    pub mod logging;
    pub mod sbxsvc;
    pub mod structs;
    pub mod syscall;
    pub mod transport;
}

// Declare how messages are multiplexed on controller->sandbox channel.

impl transport::MessageDemux<protocol::sbxsvc::Request, protocol::ctlsvc::Reply>
    for protocol::transport::ControllerToSandbox
{
    fn split(
        self,
    ) -> Option<(
        u64,
        transport::RequestOrReply<protocol::sbxsvc::Request, protocol::ctlsvc::Reply>,
    )> {
        let protocol::transport::ControllerToSandbox { cookie, msg } = self;
        match msg {
            protocol::transport::ControllerToSandboxMessage::Request(req) => {
                Some((cookie, transport::RequestOrReply::Request(req)))
            }
            protocol::transport::ControllerToSandboxMessage::Reply(rep) => {
                Some((cookie, transport::RequestOrReply::Reply(rep)))
            }
        }
    }
}

impl transport::MuxInto<protocol::transport::ControllerToSandbox> for protocol::sbxsvc::Request {
    fn wrap(self, cookie: u64) -> protocol::transport::ControllerToSandbox {
        protocol::transport::ControllerToSandbox {
            cookie,
            msg: protocol::transport::ControllerToSandboxMessage::Request(self),
        }
    }
}

impl transport::MuxInto<protocol::transport::ControllerToSandbox> for protocol::ctlsvc::Reply {
    fn wrap(self, cookie: u64) -> protocol::transport::ControllerToSandbox {
        protocol::transport::ControllerToSandbox {
            cookie,
            msg: protocol::transport::ControllerToSandboxMessage::Reply(self),
        }
    }
}

impl transport::MessageDemux<protocol::ctlsvc::Request, protocol::sbxsvc::Reply>
    for protocol::transport::SandboxToController
{
    /// Multiplexes messages on the sandbox->controller channel.
    fn split(
        self,
    ) -> Option<(
        u64,
        transport::RequestOrReply<protocol::ctlsvc::Request, protocol::sbxsvc::Reply>,
    )> {
        let protocol::transport::SandboxToController { cookie, msg } = self;
        match msg {
            protocol::transport::SandboxToControllerMessage::Request(req) => {
                Some((cookie, transport::RequestOrReply::Request(req)))
            }
            protocol::transport::SandboxToControllerMessage::Reply(rep) => {
                Some((cookie, transport::RequestOrReply::Reply(rep)))
            }
        }
    }
}

impl transport::MuxInto<protocol::transport::SandboxToController> for protocol::ctlsvc::Request {
    fn wrap(self, cookie: u64) -> protocol::transport::SandboxToController {
        protocol::transport::SandboxToController {
            cookie,
            msg: protocol::transport::SandboxToControllerMessage::Request(self),
        }
    }
}

impl transport::MuxInto<protocol::transport::SandboxToController> for protocol::sbxsvc::Reply {
    fn wrap(self, cookie: u64) -> protocol::transport::SandboxToController {
        protocol::transport::SandboxToController {
            cookie,
            msg: protocol::transport::SandboxToControllerMessage::Reply(self),
        }
    }
}
