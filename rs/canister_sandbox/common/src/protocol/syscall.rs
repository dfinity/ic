use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::{
    canister_state::system_state::CanisterStatus, StableMemoryError, StateError,
};
use ic_types::{
    messages::{CallContextId, CallbackId},
    methods::Callback,
    CanisterId, ComputeAllocation, Cycles, NumBytes, PrincipalId,
};
use serde::{Deserialize, Serialize};

// Requests/Replies for syscall access to system state.

#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterIdRequest {}
#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterIdReply {
    pub canister_id: CanisterId,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ControllerRequest {}
#[derive(Serialize, Deserialize, Clone)]
pub struct ControllerReply {
    pub controller: PrincipalId,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MintCyclesRequest {
    pub amount: Cycles,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MintCyclesReply {
    pub result: HypervisorResult<()>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MsgCyclesAcceptRequest {
    pub call_context_id: CallContextId,
    pub max_amount: Cycles,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MsgCyclesAcceptReply {
    pub amount: Cycles,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MsgCyclesAvailableRequest {
    pub call_context_id: CallContextId,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct MsgCyclesAvailableReply {
    pub result: HypervisorResult<Cycles>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StableSizeRequest {}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableSizeReply {
    pub size: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StableGrowRequest {
    pub additional_pages: u32,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableGrowReply {
    pub result: i32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StableReadRequest {
    pub offset: u32,
    pub size: u32,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableReadReply {
    pub result: Result<Vec<u8>, StableMemoryError>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StableWriteRequest {
    pub offset: u32,
    pub data: Vec<u8>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableWriteReply {
    pub result: Result<(), StableMemoryError>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterCyclesBalanceRequest {}
#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterCyclesBalanceReply {
    pub amount: Cycles,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterCyclesWithdrawRequest {
    pub canister_current_memory_usage: NumBytes,
    pub canister_compute_allocation: ComputeAllocation,
    pub amount: Cycles,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterCyclesWithdrawReply {
    pub result: HypervisorResult<()>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterCyclesRefundRequest {
    pub cycles: Cycles,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterCyclesRefundReply {}

#[derive(Serialize, Deserialize, Clone)]
pub struct SetCertifiedDataRequest {
    pub data: Vec<u8>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct SetCertifiedDataReply {}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegisterCallbackRequest {
    pub callback: Callback,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegisterCallbackReply {
    pub result: HypervisorResult<CallbackId>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PushOutputMessageRequest {
    pub canister_current_memory_usage: NumBytes,
    pub canister_compute_allocation: ComputeAllocation,
    pub msg: ic_types::messages::Request,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PushOutputMessageReply {
    pub result: Result<(), (StateError, ic_types::messages::Request)>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterStatusRequest {}
#[derive(Serialize, Deserialize, Clone)]
pub struct CanisterStatusReply {
    pub status: CanisterStatus,
}

// All requests and replies bundled as enum.

#[derive(Serialize, Deserialize, Clone)]
pub enum Request {
    CanisterId(CanisterIdRequest),
    Controller(ControllerRequest),
    MintCycles(MintCyclesRequest),
    MsgCyclesAccept(MsgCyclesAcceptRequest),
    MsgCyclesAvailable(MsgCyclesAvailableRequest),
    StableSize(StableSizeRequest),
    StableGrow(StableGrowRequest),
    StableRead(StableReadRequest),
    StableWrite(StableWriteRequest),
    CanisterCyclesBalance(CanisterCyclesBalanceRequest),
    CanisterCyclesWithdraw(CanisterCyclesWithdrawRequest),
    CanisterCyclesRefund(CanisterCyclesRefundRequest),
    SetCertifiedData(SetCertifiedDataRequest),
    RegisterCallback(RegisterCallbackRequest),
    PushOutputMessage(PushOutputMessageRequest),
    CanisterStatus(CanisterStatusRequest),
}
#[derive(Serialize, Deserialize, Clone)]
pub enum Reply {
    CanisterId(CanisterIdReply),
    Controller(ControllerReply),
    MintCycles(MintCyclesReply),
    MsgCyclesAccept(MsgCyclesAcceptReply),
    MsgCyclesAvailable(MsgCyclesAvailableReply),
    StableSize(StableSizeReply),
    StableGrow(StableGrowReply),
    StableRead(StableReadReply),
    StableWrite(StableWriteReply),
    CanisterCyclesBalance(CanisterCyclesBalanceReply),
    CanisterCyclesWithdraw(CanisterCyclesWithdrawReply),
    CanisterCyclesRefund(CanisterCyclesRefundReply),
    SetCertifiedData(SetCertifiedDataReply),
    RegisterCallback(RegisterCallbackReply),
    PushOutputMessage(PushOutputMessageReply),
    CanisterStatus(CanisterStatusReply),
}
