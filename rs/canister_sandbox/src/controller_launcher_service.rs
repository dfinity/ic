use crate::protocol::ctllaunchersvc::*;
use crate::rpc::{Call, DemuxServer};

/// RPC interface exposed by the controller to the launcher.
pub trait ControllerLauncherService: Send + Sync {
    /// Triggered when a sandbox process has unexpectedly exited.
    fn sandbox_exited(&self, req: SandboxExitedRequest) -> Call<SandboxExitedReply>;
}

impl<Svc: ControllerLauncherService + Send + Sync> DemuxServer<Request, Reply> for Svc {
    /// Dispatch generic RPC message to target function and produce
    /// matched reply (sync or async)
    fn dispatch(&self, req: Request) -> Call<Reply> {
        match req {
            Request::SandboxExited(req) => {
                Call::new_wrap(self.sandbox_exited(req), Reply::SandboxExited)
            }
        }
    }
}
