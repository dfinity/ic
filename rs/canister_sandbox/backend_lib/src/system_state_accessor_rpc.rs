use ic_canister_sandbox_common::{
    controller_service::ControllerService,
    protocol::{self, id::ExecId},
};
use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::StateError;
/// This module provides a way of accessing the canister system state
/// via RPC. It implements the SystemStateAccessor interface that
/// forms the back-end of the SystemApi (as far as it accesses system
/// state) and relays all methods to the replica via RPC.
use ic_system_api::SystemStateAccessor;
use ic_types::{
    messages::{CallContextId, CallbackId},
    methods::Callback,
    ComputeAllocation, Cycles, NumBytes,
};

use std::sync::Arc;

pub struct SystemStateAccessorRPC {
    exec_id: ExecId,
    controller: Arc<dyn ControllerService>,
}

impl SystemStateAccessorRPC {
    pub fn new(exec_id: ExecId, controller: Arc<dyn ControllerService>) -> Self {
        Self {
            exec_id,
            controller,
        }
    }

    fn make_call(&self, request: protocol::syscall::Request) -> protocol::syscall::Reply {
        let result = self
            .controller
            .canister_system_call(protocol::ctlsvc::CanisterSystemCallRequest {
                exec_id: self.exec_id,
                request,
            })
            .sync()
            .unwrap();
        result.reply
    }
}

impl SystemStateAccessor for SystemStateAccessorRPC {
    fn mint_cycles(&self, amount: Cycles) -> HypervisorResult<()> {
        let reply = self.make_call(protocol::syscall::Request::MintCycles(
            protocol::syscall::MintCyclesRequest { amount },
        ));
        match reply {
            protocol::syscall::Reply::MintCycles(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn msg_cycles_accept(&self, call_context_id: &CallContextId, max_amount: Cycles) -> Cycles {
        let reply = self.make_call(protocol::syscall::Request::MsgCyclesAccept(
            protocol::syscall::MsgCyclesAcceptRequest {
                call_context_id: *call_context_id,
                max_amount,
            },
        ));
        match reply {
            protocol::syscall::Reply::MsgCyclesAccept(rep) => rep.amount,
            _ => unimplemented!(),
        }
    }

    fn msg_cycles_available(&self, call_context_id: &CallContextId) -> HypervisorResult<Cycles> {
        let reply = self.make_call(protocol::syscall::Request::MsgCyclesAvailable(
            protocol::syscall::MsgCyclesAvailableRequest {
                call_context_id: *call_context_id,
            },
        ));
        match reply {
            protocol::syscall::Reply::MsgCyclesAvailable(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn canister_cycles_balance(&self) -> Cycles {
        let reply = self.make_call(protocol::syscall::Request::CanisterCyclesBalance(
            protocol::syscall::CanisterCyclesBalanceRequest {},
        ));
        match reply {
            protocol::syscall::Reply::CanisterCyclesBalance(rep) => rep.amount,
            _ => unimplemented!(),
        }
    }

    fn canister_cycles_withdraw(
        &self,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        amount: Cycles,
    ) -> HypervisorResult<()> {
        let reply = self.make_call(protocol::syscall::Request::CanisterCyclesWithdraw(
            protocol::syscall::CanisterCyclesWithdrawRequest {
                canister_current_memory_usage,
                canister_compute_allocation,
                amount,
            },
        ));
        match reply {
            protocol::syscall::Reply::CanisterCyclesWithdraw(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn canister_cycles_refund(&self, cycles: Cycles) {
        let reply = self.make_call(protocol::syscall::Request::CanisterCyclesRefund(
            protocol::syscall::CanisterCyclesRefundRequest { cycles },
        ));
        match reply {
            protocol::syscall::Reply::CanisterCyclesRefund(_rep) => {}
            _ => unimplemented!(),
        }
    }

    fn set_certified_data(&self, data: Vec<u8>) {
        let reply = self.make_call(protocol::syscall::Request::SetCertifiedData(
            protocol::syscall::SetCertifiedDataRequest { data },
        ));
        match reply {
            protocol::syscall::Reply::SetCertifiedData(_rep) => {}
            _ => unimplemented!(),
        }
    }

    fn register_callback(&self, callback: Callback) -> CallbackId {
        let reply = self.make_call(protocol::syscall::Request::RegisterCallback(
            protocol::syscall::RegisterCallbackRequest { callback },
        ));
        match reply {
            protocol::syscall::Reply::RegisterCallback(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn unregister_callback(&self, callback_id: CallbackId) -> Option<Callback> {
        let reply = self.make_call(protocol::syscall::Request::UnregisterCallback(
            protocol::syscall::UnregisterCallbackRequest { callback_id },
        ));
        match reply {
            protocol::syscall::Reply::UnregisterCallback(_rep) => None,
            _ => unimplemented!(),
        }
    }

    fn push_output_request(
        &self,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        msg: ic_types::messages::Request,
    ) -> Result<(), (StateError, ic_types::messages::Request)> {
        let reply = self.make_call(protocol::syscall::Request::PushOutputMessage(
            protocol::syscall::PushOutputMessageRequest {
                canister_current_memory_usage,
                canister_compute_allocation,
                msg,
            },
        ));
        match reply {
            protocol::syscall::Reply::PushOutputMessage(rep) => rep.result,
            _ => unimplemented!(),
        }
    }
}
