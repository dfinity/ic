use crate::launcher_service::LauncherService;
use crate::protocol::launchersvc::*;
use crate::rpc::{Call, Channel};

pub struct LauncherClientStub {
    channel: Channel<Request, Reply>,
}

impl LauncherClientStub {
    pub fn new(channel: Channel<Request, Reply>) -> Self {
        Self { channel }
    }
}

impl LauncherService for LauncherClientStub {
    fn launch_sandbox(&self, req: LaunchSandboxRequest) -> Call<LaunchSandboxReply> {
        let cell = self
            .channel
            .call(Request::LaunchSandbox(req), |Reply::LaunchSandbox(rep)| {
                Ok(rep)
            });
        Call::new(cell)
    }
}
