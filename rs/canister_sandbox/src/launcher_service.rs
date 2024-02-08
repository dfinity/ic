use crate::protocol::launchersvc::*;
use crate::rpc::{Call, DemuxServer};

pub trait LauncherService: Send + Sync {
    /// Launch a new sandboxed process.
    fn launch_sandbox(&self, req: LaunchSandboxRequest) -> Call<LaunchSandboxReply>;

    /// Terinate the Sandbox Launcher process.
    fn terminate(&self, req: TerminateRequest) -> Call<TerminateReply>;
}

impl<Svc: LauncherService + Send + Sync> DemuxServer<Request, Reply> for Svc {
    fn dispatch(&self, req: Request) -> Call<Reply> {
        match req {
            Request::LaunchSandbox(req) => {
                Call::new_wrap(self.launch_sandbox(req), Reply::LaunchSandbox)
            }
            Request::Terminate(req) => Call::new_wrap(self.terminate(req), Reply::Terminate),
        }
    }
}
