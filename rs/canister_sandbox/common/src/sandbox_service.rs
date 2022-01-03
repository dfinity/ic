use crate::protocol::sbxsvc::*;
use crate::rpc::{Call, DemuxServer};

/// RPC interface exposed by sandbox process.
pub trait SandboxService: Send + Sync {
    /// Terminate the sandbox.
    fn terminate(&self, req: TerminateRequest) -> Call<TerminateReply>;
    /// Creates a canister Wasm code object. The wasm code itself or
    /// the path to it is passed as the RPC payload.
    fn open_wasm(&self, req: OpenWasmRequest) -> Call<OpenWasmReply>;
    /// Close the indicated canister Wasm code object. Code cannot be
    /// used anymore.
    fn close_wasm(&self, req: CloseWasmRequest) -> Call<CloseWasmReply>;
    /// Open a state for subsequent use in executions. This can either be
    /// a “live” or “current” state that can be evolved through upgrade
    /// calls, or it can be a “snapshot” state that can only be virtually
    /// modified for the duration of a query execution but ultimately will
    /// be discarded.
    fn open_memory(&self, req: OpenMemoryRequest) -> Call<OpenMemoryReply>;
    /// Close the indicated state object.
    fn close_memory(&self, req: CloseMemoryRequest) -> Call<CloseMemoryReply>;
    /// Starts Wasm execution, passing parameters for execution down to sandbox
    /// process. The result of the execution is sent in a separate
    /// `ExecutionFinishedRequest` from the sandbox process to the replica
    /// process.
    fn start_execution(&self, req: StartExecutionRequest) -> Call<StartExecutionReply>;
    /// Perform initial parsing and evaluation needed to create the starting
    /// execution state.
    fn create_execution_state(
        &self,
        req: CreateExecutionStateRequest,
    ) -> Call<CreateExecutionStateReply>;
}

impl<Svc: SandboxService + Send + Sync> DemuxServer<Request, Reply> for Svc {
    /// Dispatch generic RPC message to target function and produce
    /// matched reply (sync or async)
    fn dispatch(&self, req: Request) -> Call<Reply> {
        match req {
            Request::Terminate(req) => Call::new_wrap(self.terminate(req), Reply::Terminate),
            Request::OpenWasm(req) => Call::new_wrap(self.open_wasm(req), Reply::OpenWasm),
            Request::CloseWasm(req) => Call::new_wrap(self.close_wasm(req), Reply::CloseWasm),
            Request::OpenMemory(req) => Call::new_wrap(self.open_memory(req), Reply::OpenMemory),
            Request::CloseMemory(req) => Call::new_wrap(self.close_memory(req), Reply::CloseMemory),
            Request::StartExecution(req) => {
                Call::new_wrap(self.start_execution(req), Reply::StartExecution)
            }
            Request::CreateExecutionState(req) => Call::new_wrap(
                self.create_execution_state(req),
                Reply::CreateExecutionState,
            ),
        }
    }
}
