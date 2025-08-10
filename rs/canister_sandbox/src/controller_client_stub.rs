use crate::controller_service::ControllerService;
use crate::protocol::ctlsvc::*;
use crate::protocol::logging::LogRequest;
use crate::rpc::{Call, Channel, Error};

use std::sync::Arc;

/// Client stub for controller RPC interface -- this is instantiated in
/// sandbox and allows to call the correspnoding functions inside
/// the controller service.
pub struct ControllerClientStub {
    channel: Arc<Channel<Request, Reply>>,
}

impl ControllerClientStub {
    pub fn new(channel: Arc<Channel<Request, Reply>>) -> Self {
        Self { channel }
    }
}

impl ControllerService for ControllerClientStub {
    fn execution_finished(&self, req: ExecutionFinishedRequest) -> Call<ExecutionFinishedReply> {
        let cell = self
            .channel
            .call(Request::ExecutionFinished(req), |rep| match rep {
                Reply::ExecutionFinished(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn execution_paused(&self, req: ExecutionPausedRequest) -> Call<ExecutionPausedReply> {
        let cell = self
            .channel
            .call(Request::ExecutionPaused(req), |rep| match rep {
                Reply::ExecutionPaused(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }

    fn log_via_replica(&self, req: LogRequest) -> Call<()> {
        let cell = self
            .channel
            .call(Request::LogViaReplica(req), |rep| match rep {
                Reply::LogViaReplica(_) => Ok(()),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }
}
