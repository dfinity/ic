/// Utility class to handle IPC endpoint exposed to sandbox process.
///
/// This implements the IPC interface exposed by the "replica controller
/// process" towards the "sandbox process": Whenever the sandbox process
/// issues an upwards call, it ends up here.
///
/// This is just a utility implementing the required interface and
/// passing information towards upper layers. In order to perform its
/// function, it is dependent on knowing which executions are "active"
/// on a specific sandbox process by their IDs, and the associated
/// target points provided by upper layers (system state access and
/// completion closure).
use ic_canister_sandbox_common::controller_service::ControllerService;
use ic_canister_sandbox_common::protocol;
use ic_canister_sandbox_common::rpc;
use ic_interfaces::execution_environment::{HypervisorError, TrapCode::StableMemoryOutOfBounds};
use ic_logger::{debug, error, info, trace, ReplicaLogger};
use ic_system_api::SystemStateAccessor;

use crate::active_execution_state_registry::ActiveExecutionStateRegistry;

use std::sync::Arc;

pub struct ControllerServiceImpl {
    registry: Arc<ActiveExecutionStateRegistry>,
    log: ReplicaLogger,
}

impl ControllerServiceImpl {
    /// Create new instance of controller service.
    pub fn new(registry: Arc<ActiveExecutionStateRegistry>, log: ReplicaLogger) -> Arc<Self> {
        Arc::new(ControllerServiceImpl { registry, log })
    }
}

impl ControllerService for ControllerServiceImpl {
    fn exec_finished(
        &self,
        req: protocol::ctlsvc::ExecFinishedRequest,
    ) -> rpc::Call<protocol::ctlsvc::ExecFinishedReply> {
        let exec_id = req.exec_id;
        let exec_output = req.exec_output;
        // Sandbox is telling us that execution has finished for this
        // ID. We will validate this ID by looking up the execution
        // state for this ID and extracting its closure. If the closure
        // is not there, then the sandbox is "buggy" (or worse) and
        // trying to either issue "double-completions" or completions
        // for non-existent executions. Deal with this by ignoring
        // such calls (but log them).
        // Maybe we also want to deal with this in more radical ways
        // (e.g. forcibly terminate the sandbox process).
        let reply = self.registry.extract_completion(&exec_id).map_or_else(
            || {
                // Should we log the entire erroneous request? It
                // could both be large and hold canister-sensitive
                // data, so maybe this is not advisable.
                error!(
                    self.log,
                    "Wasm sandbox process sent completion for non-existent execution {}", &exec_id
                );
                Err(rpc::Error::ServerError)
            },
            |completion| {
                completion(&exec_id, Some(exec_output));
                Ok(protocol::ctlsvc::ExecFinishedReply {})
            },
        );
        rpc::Call::new_resolved(reply)
    }

    fn log_via_replica(&self, req: protocol::logging::LogRequest) -> rpc::Call<()> {
        let protocol::logging::LogRequest((level, message)) = req;
        match level {
            protocol::logging::LogLevel::Info => info!(self.log, "CANISTER_SANDBOX: {}", message),
            protocol::logging::LogLevel::Debug => debug!(self.log, "CANISTER_SANDBOX: {}", message),
            protocol::logging::LogLevel::Trace => trace!(self.log, "CANISTER_SANDBOX: {}", message),
        }

        rpc::Call::new_resolved(Ok(()))
    }

    fn canister_system_call(
        &self,
        req: protocol::ctlsvc::CanisterSystemCallRequest,
    ) -> rpc::Call<protocol::ctlsvc::CanisterSystemCallReply> {
        let protocol::ctlsvc::CanisterSystemCallRequest { exec_id, request } = req;

        // Sandbox is relaying a system state access to us, referring to
        // a specific exec ID. We will validate this ID by looking up
        // the execution state for this ID and borrowing its system
        // state accessor. If we cannot borrow it, then this means that
        // the sandbox is "buggy" (or worse) and trying to issue illegal
        // system calls or system calls after the execution has finished
        // already. Deal with this by ignoring such calls (but log them).
        // Maybe we also want to deal with this in more radical ways
        // (e.g. forcibly terminate the sandbox process).
        let reply = self
            .registry
            .borrow_system_state_accessor(&exec_id)
            .map_or_else(
                || {
                    // Should we log the entire erroneous request? It
                    // could both be large and hold canister-sensitive
                    // data, so maybe this is not advisable.
                    error!(
                        self.log,
                        "Wasm sandbox process sent syscall for non-existent execution {}", &exec_id
                    );
                    Err(rpc::Error::ServerError)
                },
                |mut borrow| {
                    let system_state_accessor = borrow.access();
                    use protocol::syscall::*;
                    let reply = match request {
                        Request::CanisterId(_req) => Reply::CanisterId(CanisterIdReply {
                            canister_id: system_state_accessor.canister_id(),
                        }),
                        Request::Controller(_req) => Reply::Controller(ControllerReply {
                            controller: system_state_accessor.controller(),
                        }),
                        Request::MintCycles(req) => {
                            let result = system_state_accessor.mint_cycles(req.amount);
                            Reply::MintCycles(MintCyclesReply { result })
                        }
                        Request::MsgCyclesAccept(req) => {
                            let amount = system_state_accessor
                                .msg_cycles_accept(&req.call_context_id, req.max_amount);
                            Reply::MsgCyclesAccept(MsgCyclesAcceptReply { amount })
                        }
                        Request::MsgCyclesAvailable(req) => {
                            let result =
                                system_state_accessor.msg_cycles_available(&req.call_context_id);
                            Reply::MsgCyclesAvailable(MsgCyclesAvailableReply { result })
                        }
                        Request::StableSize(_req) => {
                            let result = system_state_accessor.stable_size();
                            Reply::StableSize(StableSizeReply { result })
                        }
                        Request::StableGrow(req) => {
                            let result = system_state_accessor.stable_grow(req.additional_pages);
                            Reply::StableGrow(StableGrowReply { result })
                        }
                        Request::StableGrow64(req) => {
                            let result = system_state_accessor.stable64_grow(req.additional_pages);
                            Reply::StableGrow64(StableGrow64Reply { result })
                        }
                        Request::GetNumInstructionsFromBytes(req) => {
                            let result = system_state_accessor
                                .get_num_instructions_from_bytes(req.num_bytes);
                            Reply::GetNumInstructionsFromBytes(GetNumInstructionsFromBytesReply {
                                result,
                            })
                        }
                        Request::StableRead(req) => {
                            let mut buf = Vec::<u8>::new();
                            buf.resize(req.size as usize, 0);
                            let result = system_state_accessor
                                .stable_read(0, req.offset, req.size, &mut buf);
                            let result = result.map_or_else(Err, |_| Ok(buf));
                            Reply::StableRead(StableReadReply { result })
                        }
                        Request::StableRead64(req) => {
                            let mut buf = Vec::<u8>::new();
                            buf.resize(req.size as usize, 0);
                            let result = system_state_accessor
                                .stable64_read(0, req.offset, req.size, &mut buf);
                            let result = result.map_or_else(Err, |_| Ok(buf));
                            Reply::StableRead(StableReadReply { result })
                        }
                        Request::StableWrite(req) => {
                            let result = if req.data.len() <= (u32::MAX as usize) {
                                system_state_accessor.stable_write(
                                    req.offset,
                                    0,
                                    req.data.len() as u32,
                                    &req.data,
                                )
                            } else {
                                Err(HypervisorError::Trapped(StableMemoryOutOfBounds))
                            };
                            Reply::StableWrite(StableWriteReply { result })
                        }
                        Request::StableWrite64(req) => {
                            let result = if req.data.len() <= (u64::MAX as usize) {
                                system_state_accessor.stable64_write(
                                    req.offset,
                                    0,
                                    req.data.len() as u64,
                                    &req.data,
                                )
                            } else {
                                Err(HypervisorError::Trapped(StableMemoryOutOfBounds))
                            };
                            Reply::StableWrite(StableWriteReply { result })
                        }
                        Request::CanisterCyclesBalance(_req) => {
                            let amount = system_state_accessor.canister_cycles_balance();
                            Reply::CanisterCyclesBalance(CanisterCyclesBalanceReply { amount })
                        }
                        Request::CanisterCyclesWithdraw(req) => {
                            let result = system_state_accessor.canister_cycles_withdraw(
                                req.canister_current_memory_usage,
                                req.canister_compute_allocation,
                                req.amount,
                            );
                            Reply::CanisterCyclesWithdraw(CanisterCyclesWithdrawReply { result })
                        }
                        Request::CanisterCyclesRefund(req) => {
                            system_state_accessor.canister_cycles_refund(req.cycles);
                            Reply::CanisterCyclesRefund(CanisterCyclesRefundReply {})
                        }
                        Request::SetCertifiedData(req) => {
                            system_state_accessor.set_certified_data(req.data);
                            Reply::SetCertifiedData(SetCertifiedDataReply {})
                        }
                        Request::RegisterCallback(req) => {
                            let result = system_state_accessor.register_callback(req.callback);
                            Reply::RegisterCallback(RegisterCallbackReply { result })
                        }
                        Request::UnregisterCallback(req) => {
                            system_state_accessor.unregister_callback(req.callback_id);
                            Reply::UnregisterCallback(UnregisterCallbackReply {})
                        }
                        Request::PushOutputMessage(req) => {
                            let result = system_state_accessor.push_output_request(
                                req.canister_current_memory_usage,
                                req.canister_compute_allocation,
                                req.msg,
                            );
                            Reply::PushOutputMessage(PushOutputMessageReply { result })
                        }
                        Request::CanisterStatus(_req) => {
                            let status = system_state_accessor.canister_status();
                            Reply::CanisterStatus(CanisterStatusReply { status })
                        }
                    };

                    Ok(protocol::ctlsvc::CanisterSystemCallReply { reply })
                },
            );
        rpc::Call::new_resolved(reply)
    }
}
