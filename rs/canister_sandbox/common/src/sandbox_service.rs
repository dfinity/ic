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
    fn open_state(&self, req: OpenStateRequest) -> Call<OpenStateReply>;
    /// Close the indicated state object.
    fn close_state(&self, req: CloseStateRequest) -> Call<CloseStateReply>;
    /// Start an execution, passing parameters for execution down to
    /// sandbox process; requires both a code object (can be used in
    /// multiple executions concurrently) and a state object (can only
    /// be used in a single execution at a time). Takes a Wasm and
    /// state identifier.
    fn open_execution(&self, req: OpenExecutionRequest) -> Call<OpenExecutionReply>;
    /// Close the indicated execution state. Indicate if the state is
    /// to be committed.
    fn close_execution(&self, req: CloseExecutionRequest) -> Call<CloseExecutionReply>;
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
            Request::OpenState(req) => Call::new_wrap(self.open_state(req), Reply::OpenState),
            Request::CloseState(req) => Call::new_wrap(self.close_state(req), Reply::CloseState),
            Request::OpenExecution(req) => {
                Call::new_wrap(self.open_execution(req), Reply::OpenExecution)
            }
            Request::CloseExecution(req) => {
                Call::new_wrap(self.close_execution(req), Reply::CloseExecution)
            }
            Request::CreateExecutionState(req) => Call::new_wrap(
                self.create_execution_state(req),
                Reply::CreateExecutionState,
            ),
        }
    }
}
