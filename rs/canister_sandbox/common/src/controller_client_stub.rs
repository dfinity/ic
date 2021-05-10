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
    fn exec_finished(&self, req: ExecFinishedRequest) -> Call<ExecFinishedReply> {
        let cell = self
            .channel
            .call(Request::ExecFinished(req), |rep| match rep {
                Reply::ExecFinished(rep) => Ok(rep),
                _ => Err(Error::ServerError),
            });
        Call::new(cell)
    }
    fn canister_system_call(
        &self,
        req: CanisterSystemCallRequest,
    ) -> Call<CanisterSystemCallReply> {
        let cell = self
            .channel
            .call(Request::CanisterSystemCall(req), |rep| match rep {
                Reply::CanisterSystemCall(rep) => Ok(rep),
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
