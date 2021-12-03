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

    fn open_state(&self, req: OpenStateRequest) -> Call<OpenStateReply> {
        let cell = self.channel.call(Request::OpenState(req), |rep| match rep {
            Reply::OpenState(rep) => Ok(rep),
            _ => Err(Error::ServerError),
        });
        Call::new(cell)
    }

    fn close_state(&self, req: CloseStateRequest) -> Call<CloseStateReply> {
        let cell = self
            .channel
            .call(Request::CloseState(req), |rep| match rep {
                Reply::CloseState(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn open_execution(&self, req: OpenExecutionRequest) -> Call<OpenExecutionReply> {
        let cell = self
            .channel
            .call(Request::OpenExecution(req), |rep| match rep {
                Reply::OpenExecution(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn close_execution(&self, req: CloseExecutionRequest) -> Call<CloseExecutionReply> {
        let cell = self
            .channel
            .call(Request::CloseExecution(req), |rep| match rep {
                Reply::CloseExecution(rep) => Ok(rep),
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
