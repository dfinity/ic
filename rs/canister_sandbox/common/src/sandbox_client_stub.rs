use crate::protocol::sbxsvc::*;
use crate::rpc::{Call, Channel, Error};
use crate::sandbox_service::SandboxService;

/// Client stub for sandbox RPC interface -- this is instantiated in
/// controller and allows to call the correspnoding functions inside
/// the sandbox service.
pub struct SandboxClientStub {
    channel: Channel<Request, Reply>,
}

impl SandboxClientStub {
    pub fn new(channel: Channel<Request, Reply>) -> Self {
        Self { channel }
    }
}

impl SandboxService for SandboxClientStub {
    fn terminate(&self, req: TerminateRequest) -> Call<TerminateReply> {
        let cell = self.channel.call(Request::Terminate(req), |rep| match rep {
            Reply::Terminate(rep) => Ok(rep),
            _ => Err(Error::ServerError),
        });
        Call::new(cell)
    }

    fn open_wasm(&self, req: OpenWasmRequest) -> Call<OpenWasmReply> {
        let cell = self.channel.call(Request::OpenWasm(req), |rep| match rep {
            Reply::OpenWasm(rep) => Ok(rep),
            _ => Err(Error::ServerError),
        });
        Call::new(cell)
    }

    fn close_wasm(&self, req: CloseWasmRequest) -> Call<CloseWasmReply> {
        let cell = self.channel.call(Request::CloseWasm(req), |rep| match rep {
            Reply::CloseWasm(rep) => Ok(rep),
            _ => Err(Error::ServerError),
        });
        Call::new(cell)
    }

    fn open_memory(&self, req: OpenMemoryRequest) -> Call<OpenMemoryReply> {
        let cell = self
            .channel
            .call(Request::OpenMemory(req), |rep| match rep {
                Reply::OpenMemory(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn close_memory(&self, req: CloseMemoryRequest) -> Call<CloseMemoryReply> {
        let cell = self
            .channel
            .call(Request::CloseMemory(req), |rep| match rep {
                Reply::CloseMemory(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn start_execution(&self, req: StartExecutionRequest) -> Call<StartExecutionReply> {
        let cell = self
            .channel
            .call(Request::StartExecution(req), |rep| match rep {
                Reply::StartExecution(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn resume_execution(&self, req: ResumeExecutionRequest) -> Call<ResumeExecutionReply> {
        let cell = self
            .channel
            .call(Request::ResumeExecution(req), |rep| match rep {
                Reply::ResumeExecution(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn create_execution_state(
        &self,
        req: CreateExecutionStateRequest,
    ) -> Call<CreateExecutionStateReply> {
        let cell = self
            .channel
            .call(Request::CreateExecutionState(req), |rep| match rep {
                Reply::CreateExecutionState(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }
}
