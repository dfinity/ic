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

    fn open_wasm_serialized(
        &self,
        req: OpenWasmSerializedRequest,
    ) -> Call<OpenWasmSerializedReply> {
        let cell = self
            .channel
            .call(Request::OpenWasmSerialized(req), |rep| match rep {
                Reply::OpenWasmSerialized(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn open_wasm_via_file(&self, req: OpenWasmViaFileRequest) -> Call<OpenWasmSerializedReply> {
        let cell = self
            .channel
            .call(Request::OpenWasmViaFile(req), |rep| match rep {
                Reply::OpenWasmSerialized(rep) => Ok(rep),
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

    fn abort_execution(&self, req: AbortExecutionRequest) -> Call<AbortExecutionReply> {
        let cell = self
            .channel
            .call(Request::AbortExecution(req), |rep| match rep {
                Reply::AbortExecution(rep) => Ok(rep),
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

    fn create_execution_state_serialized(
        &self,
        req: CreateExecutionStateSerializedRequest,
    ) -> Call<CreateExecutionStateSerializedReply> {
        let cell = self.channel.call(
            Request::CreateExecutionStateSerialized(req),
            |rep| match rep {
                Reply::CreateExecutionStateSerialized(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            },
        );
        Call::new(cell)
    }

    fn create_execution_state_via_file(
        &self,
        req: CreateExecutionStateViaFileRequest,
    ) -> Call<CreateExecutionStateSerializedReply> {
        let cell = self
            .channel
            .call(Request::CreateExecutionStateViaFile(req), |rep| match rep {
                Reply::CreateExecutionStateSerialized(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }
}
