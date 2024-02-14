use crate::launcher_service::LauncherService;
use crate::protocol::launchersvc::*;
use crate::rpc::{Call, Channel, Error};

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
            .call(Request::LaunchSandbox(req), |rep| match rep {
                Reply::LaunchSandbox(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn terminate(&self, req: TerminateRequest) -> Call<TerminateReply> {
        let cell = self.channel.call(Request::Terminate(req), |rep| match rep {
            Reply::Terminate(rep) => Ok(rep),
            _ => Err(Error::ServerError),
        });
        Call::new(cell)
    }
}
