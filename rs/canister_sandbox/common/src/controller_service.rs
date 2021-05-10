use crate::protocol::ctlsvc::*;
use crate::protocol::logging::LogRequest;
use crate::rpc::{Call, DemuxServer};

/// RPC interface exposed by sandbox process.
pub trait ControllerService: Send + Sync {
    /// Triggered when wasm code execution finishes. Results of
    /// execution (if successful) are transferred through this
    /// call. After this call, the execution object still "lingers"
    /// around, until the controller disposes of it using
    /// CloseExecution (close_execution).
    fn exec_finished(&self, req: ExecFinishedRequest) -> Call<ExecFinishedReply>;

    /// Triggered when wasm code issues a system call that can not
    /// directly be resolved by the sandbox process. Arguments and
    /// results are relayed using RPC and depend on the respective RPC
    /// call.
    fn canister_system_call(&self, req: CanisterSystemCallRequest)
        -> Call<CanisterSystemCallReply>;

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
            Request::ExecFinished(req) => {
                Call::new_wrap(self.exec_finished(req), Reply::ExecFinished)
            }
            Request::CanisterSystemCall(req) => {
                Call::new_wrap(self.canister_system_call(req), |rep| {
                    Reply::CanisterSystemCall(rep)
                })
            }
            Request::LogViaReplica(req) => {
                Call::new_wrap(self.log_via_replica(req), Reply::LogViaReplica)
            }
        }
    }
}
