use ic_canister_sandbox_common::{
    controller_service::ControllerService, protocol::logging::LogRequest,
};

#[inline(always)]
/// Signal the controller to log. This function should NOT BLOCK.
pub(crate) fn log(logger: &dyn ControllerService, log_request: LogRequest) {
    logger.log_via_replica(log_request);
}
