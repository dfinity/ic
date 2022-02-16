use crate::protocol::launchersvc::*;
use crate::rpc::{Call, DemuxServer};

pub trait LauncherService: Send + Sync {
    /// Launch a new sandboxed process.
    fn launch_sandbox(&self, req: LaunchSandboxRequest) -> Call<LaunchSandboxReply>;
}

impl<Svc: LauncherService + Send + Sync> DemuxServer<Request, Reply> for Svc {
    fn dispatch(&self, Request::LaunchSandbox(req): Request) -> Call<Reply> {
        Call::new_wrap(self.launch_sandbox(req), Reply::LaunchSandbox)
    }
}
