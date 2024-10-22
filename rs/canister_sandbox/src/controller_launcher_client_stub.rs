use crate::controller_launcher_service::ControllerLauncherService;
use crate::protocol::ctllaunchersvc::*;
use crate::rpc::{Call, Channel, Error};

use std::sync::Arc;

/// Client stub for controller RPC interface -- this is instantiated in launcher
/// and allows it to call the correspnoding functions inside the controller
/// service.
#[derive(Clone)]
pub struct ControllerLauncherClientStub {
    channel: Arc<Channel<Request, Reply>>,
}

impl ControllerLauncherClientStub {
    pub fn new(channel: Arc<Channel<Request, Reply>>) -> Self {
        Self { channel }
    }
}

impl ControllerLauncherService for ControllerLauncherClientStub {
    fn sandbox_exited(&self, req: SandboxExitedRequest) -> Call<SandboxExitedReply> {
        let cell = self
            .channel
            .call(Request::SandboxExited(req), |rep| match rep {
                Reply::SandboxExited(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }
    fn sandbox_created(&self, req: SandboxCreatedRequest) -> Call<SandboxCreatedReply> {
        let cell = self
            .channel
            .call(Request::SandboxCreated(req), |rep| match rep {
                Reply::SandboxCreated(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }
}
