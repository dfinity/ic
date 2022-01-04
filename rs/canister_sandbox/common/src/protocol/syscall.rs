use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::{canister_state::system_state::CanisterStatus, StateError};
use ic_types::{
    messages::{CallContextId, CallbackId},
    methods::Callback,
    CanisterId, ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId,
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
    pub result: HypervisorResult<u32>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableSize64Reply {
    pub result: HypervisorResult<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetNumInstructionsFromBytesRequest {
    pub num_bytes: NumBytes,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct GetNumInstructionsFromBytesReply {
    pub result: NumInstructions,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StableGrowRequest {
    pub additional_pages: u32,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableGrowReply {
    pub result: HypervisorResult<i32>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableGrow64Request {
    pub additional_pages: u64,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableGrow64Reply {
    pub result: HypervisorResult<i64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StableReadRequest {
    pub offset: u32,
    pub size: u32,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableRead64Request {
    pub offset: u64,
    pub size: u64,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableReadReply {
    pub result: HypervisorResult<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StableWriteRequest {
    pub offset: u32,
    pub data: Vec<u8>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableWrite64Request {
    pub offset: u64,
    pub data: Vec<u8>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct StableWriteReply {
    pub result: HypervisorResult<()>,
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
    pub result: CallbackId,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UnregisterCallbackRequest {
    pub callback_id: CallbackId,
}

// Note: upstream "unregister" function actually returns
// the callback (if one was removed) -- I do however not see a
// point returning it to the canister code, it doesn't do anything
// with it.
#[derive(Serialize, Deserialize, Clone)]
pub struct UnregisterCallbackReply {}

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
    MintCycles(MintCyclesRequest),
    MsgCyclesAccept(MsgCyclesAcceptRequest),
    MsgCyclesAvailable(MsgCyclesAvailableRequest),
    CanisterCyclesBalance(CanisterCyclesBalanceRequest),
    CanisterCyclesWithdraw(CanisterCyclesWithdrawRequest),
    CanisterCyclesRefund(CanisterCyclesRefundRequest),
    SetCertifiedData(SetCertifiedDataRequest),
    RegisterCallback(RegisterCallbackRequest),
    UnregisterCallback(UnregisterCallbackRequest),
    PushOutputMessage(PushOutputMessageRequest),
}
#[derive(Serialize, Deserialize, Clone)]
pub enum Reply {
    MintCycles(MintCyclesReply),
    MsgCyclesAccept(MsgCyclesAcceptReply),
    MsgCyclesAvailable(MsgCyclesAvailableReply),
    CanisterCyclesBalance(CanisterCyclesBalanceReply),
    CanisterCyclesWithdraw(CanisterCyclesWithdrawReply),
    CanisterCyclesRefund(CanisterCyclesRefundReply),
    SetCertifiedData(SetCertifiedDataReply),
    RegisterCallback(RegisterCallbackReply),
    UnregisterCallback(UnregisterCallbackReply),
    PushOutputMessage(PushOutputMessageReply),
}
