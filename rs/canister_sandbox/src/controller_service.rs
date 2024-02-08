use crate::protocol::ctlsvc::*;
use crate::protocol::logging::LogRequest;
use crate::rpc::{Call, DemuxServer};

/// RPC interface exposed by sandbox process.
pub trait ControllerService: Send + Sync {
    /// Triggered when wasm code execution finishes. Results of execution
    /// (if successful) are transferred through this call.
    fn execution_finished(&self, req: ExecutionFinishedRequest) -> Call<ExecutionFinishedReply>;

    /// Triggered when wasm code execution is paused.
    fn execution_paused(&self, req: ExecutionPausedRequest) -> Call<ExecutionPausedReply>;

    /// Issue a logging request. Logging occurs via the replica
    /// itself. We do not provide access to underlying logging
    /// machinery to the spawned sandboxed processes and we keep a
    /// single writer to the pipe -- otherwise we have to synchronize
    /// buffered and unbuffered writers.
    fn log_via_replica(&self, log: LogRequest) -> Call<()>;
}

impl<Svc: ControllerService + Send + Sync> DemuxServer<Request, Reply> for Svc {
    /// Dispatch generic RPC message to target function and produce
    /// matched reply (sync or async)
    fn dispatch(&self, req: Request) -> Call<Reply> {
        match req {
            Request::ExecutionFinished(req) => {
                Call::new_wrap(self.execution_finished(req), Reply::ExecutionFinished)
            }
            Request::ExecutionPaused(req) => {
                Call::new_wrap(self.execution_paused(req), Reply::ExecutionPaused)
            }
            Request::LogViaReplica(req) => {
                Call::new_wrap(self.log_via_replica(req), Reply::LogViaReplica)
            }
        }
    }
}
