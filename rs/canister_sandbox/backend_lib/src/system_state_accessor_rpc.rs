use ic_canister_sandbox_common::{controller_service::ControllerService, protocol};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult,
    TrapCode::{HeapOutOfBounds, StableMemoryOutOfBounds},
};
use ic_replicated_state::{canister_state::system_state::CanisterStatus, StateError};
/// This module provides a way of accessing the canister system state
/// via RPC. It implements the SystemStateAccessor interface that
/// forms the back-end of the SystemApi (as far as it accesess system
/// state) and relays all methods to the replica via RPC.
use ic_system_api::SystemStateAccessor;
use ic_types::{
    messages::{CallContextId, CallbackId},
    methods::Callback,
    CanisterId, ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId,
};

use std::sync::Arc;

pub struct SystemStateAccessorRPC {
    exec_id: String,
    controller: Arc<dyn ControllerService>,
}

impl SystemStateAccessorRPC {
    pub fn new(exec_id: String, controller: Arc<dyn ControllerService>) -> Self {
        Self {
            exec_id,
            controller,
        }
    }

    fn make_call(&self, request: protocol::syscall::Request) -> protocol::syscall::Reply {
        let result = self
            .controller
            .canister_system_call(protocol::ctlsvc::CanisterSystemCallRequest {
                exec_id: self.exec_id.clone(),
                request,
            })
            .sync()
            .unwrap();
        result.reply
    }
}

impl SystemStateAccessor for SystemStateAccessorRPC {
    fn canister_id(&self) -> CanisterId {
        let reply = self.make_call(protocol::syscall::Request::CanisterId(
            protocol::syscall::CanisterIdRequest {},
        ));
        match reply {
            protocol::syscall::Reply::CanisterId(rep) => rep.canister_id,
            _ => unimplemented!(),
        }
    }

    fn controller(&self) -> PrincipalId {
        let reply = self.make_call(protocol::syscall::Request::Controller(
            protocol::syscall::ControllerRequest {},
        ));
        match reply {
            protocol::syscall::Reply::Controller(rep) => rep.controller,
            _ => unimplemented!(),
        }
    }

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

    fn stable_size(&self) -> HypervisorResult<u32> {
        let reply = self.make_call(protocol::syscall::Request::StableSize(
            protocol::syscall::StableSizeRequest {},
        ));
        match reply {
            protocol::syscall::Reply::StableSize(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn stable_grow(&self, additional_pages: u32) -> HypervisorResult<i32> {
        let reply = self.make_call(protocol::syscall::Request::StableGrow(
            protocol::syscall::StableGrowRequest { additional_pages },
        ));

        match reply {
            protocol::syscall::Reply::StableGrow(rep) => {
                eprintln!("stable_grow: Returned {:?}", &rep.result);
                rep.result
            }
            _ => unimplemented!(),
        }
    }

    /// Returns the number of instructions needed to copy `num_bytes`.
    fn get_num_instructions_from_bytes(&self, num_bytes: NumBytes) -> NumInstructions {
        let reply = self.make_call(protocol::syscall::Request::GetNumInstructionsFromBytes(
            protocol::syscall::GetNumInstructionsFromBytesRequest { num_bytes },
        ));

        match reply {
            protocol::syscall::Reply::GetNumInstructionsFromBytes(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn stable_read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let reply = self.make_call(protocol::syscall::Request::StableRead(
            protocol::syscall::StableReadRequest { offset, size },
        ));

        // We have a real API problem here -- this is checked in
        // particular order inside stable memory (report
        // "StableMemoryOutOfBounds" errors before "HeapOutOfBounds"
        // errors if both occur at the same time). However, we actually
        // can only check for heap errors here (since stable memory
        // size is not known to this process).
        // Handle the one case verified in unit test so far
        let (_, overflow) = offset.overflowing_add(size);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (upper_bound, overflow) = dst.overflowing_add(size);
        if overflow || upper_bound as usize > heap.len() || dst as usize >= heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        match reply {
            protocol::syscall::Reply::StableRead(rep) => {
                heap[(dst as usize)..(upper_bound as usize)]
                    .copy_from_slice(rep.result?.as_slice());
                Ok(())
            }
            _ => unimplemented!(),
        }
    }

    fn stable_write(&self, offset: u32, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()> {
        // Preferentially, heap check should be handled in system API
        // already (should not be passed down to stable memory writer
        // itself).
        eprintln!("SANDBOX: stable_write {} {} {}", src, size, heap.len());

        // We have a real API problem here -- this is checked in
        // particular order inside stable memory (report
        // "StableMemoryOutOfBounds" errors before "HeapOutOfBounds"
        // errors if both occur at the same time). However, we actually
        // can only check for heap errors here (since stable memory
        // size is not known to this process).
        // Handle the one case verified in unit test so far
        let (_, overflow) = offset.overflowing_add(size);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (upper_bound, overflow) = src.overflowing_add(size);
        if overflow || upper_bound as usize > heap.len() || src as usize >= heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        let data = heap[(src as usize)..(upper_bound as usize)].to_vec();
        let reply = self.make_call(protocol::syscall::Request::StableWrite(
            protocol::syscall::StableWriteRequest { offset, data },
        ));
        match reply {
            protocol::syscall::Reply::StableWrite(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn stable64_size(&self) -> HypervisorResult<u64> {
        let reply = self.make_call(protocol::syscall::Request::StableSize(
            protocol::syscall::StableSizeRequest {},
        ));
        match reply {
            protocol::syscall::Reply::StableSize64(rep) => rep.result,
            _ => unimplemented!(),
        }
    }

    fn stable64_grow(&self, additional_pages: u64) -> HypervisorResult<i64> {
        let reply = self.make_call(protocol::syscall::Request::StableGrow64(
            protocol::syscall::StableGrow64Request { additional_pages },
        ));

        match reply {
            protocol::syscall::Reply::StableGrow64(rep) => {
                eprintln!("stable64_grow: Returned {:?}", &rep.result);
                rep.result
            }
            _ => unimplemented!(),
        }
    }

    fn stable64_read(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let reply = self.make_call(protocol::syscall::Request::StableRead64(
            protocol::syscall::StableRead64Request { offset, size },
        ));

        // We have a real API problem here -- this is checked in
        // particular order inside stable memory (report
        // "StableMemoryOutOfBounds" errors before "HeapOutOfBounds"
        // errors if both occur at the same time). However, we actually
        // can only check for heap errors here (since stable memory
        // size is not known to this process).
        // Handle the one case verified in unit test so far
        let (_, overflow) = offset.overflowing_add(size as u64);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (upper_bound, overflow) = dst.overflowing_add(size);
        if overflow || upper_bound as usize > heap.len() || dst as usize >= heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        match reply {
            protocol::syscall::Reply::StableRead(rep) => {
                heap[(dst as usize)..(upper_bound as usize)]
                    .copy_from_slice(rep.result?.as_slice());
                Ok(())
            }
            _ => unimplemented!(),
        }
    }

    fn stable64_write(
        &self,
        offset: u64,
        src: u64,
        size: u64,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        // Preferentially, heap check should be handled in system API
        // already (should not be passed down to stable memory writer
        // itself).
        eprintln!("SANDBOX: stable_write {} {} {}", src, size, heap.len());

        // We have a real API problem here -- this is checked in
        // particular order inside stable memory (report
        // "StableMemoryOutOfBounds" errors before "HeapOutOfBounds"
        // errors if both occur at the same time). However, we actually
        // can only check for heap errors here (since stable memory
        // size is not known to this process).
        // Handle the one case verified in unit test so far
        let (_, overflow) = offset.overflowing_add(size as u64);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (upper_bound, overflow) = src.overflowing_add(size);
        if overflow || upper_bound as usize > heap.len() || src as usize >= heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        let data = heap[(src as usize)..(upper_bound as usize)].to_vec();
        let reply = self.make_call(protocol::syscall::Request::StableWrite64(
            protocol::syscall::StableWrite64Request { offset, data },
        ));
        match reply {
            protocol::syscall::Reply::StableWrite(rep) => rep.result,
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

    /// Current status of canister.
    fn canister_status(&self) -> CanisterStatus {
        let reply = self.make_call(protocol::syscall::Request::CanisterStatus(
            protocol::syscall::CanisterStatusRequest {},
        ));
        match reply {
            protocol::syscall::Reply::CanisterStatus(rep) => rep.status,
            _ => unimplemented!(),
        }
    }
}
