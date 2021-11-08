use ic_interfaces::execution_environment::{ExecutionParameters, HypervisorResult, InstanceStats};
use ic_replicated_state::{Global, NumWasmPages, PageIndex};
use ic_sys::PageBytes;
use ic_system_api::ApiType;
use ic_types::{ingress::WasmResult, methods::FuncRef, CanisterId, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

big_array! { BigArray; }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Round(pub u64);

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecInput {
    pub canister_id: CanisterId,
    pub func_ref: FuncRef,
    pub api_type: ApiType,
    pub globals: Vec<Global>,
    pub canister_current_memory_usage: NumBytes,
    pub execution_parameters: ExecutionParameters,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecOutput {
    pub wasm_result: HypervisorResult<Option<WasmResult>>,
    pub num_instructions_left: NumInstructions,
    pub instance_stats: InstanceStats,

    // Note on fields below: This is not exactly the right place --
    // they belong to "state" more than "execution". This is presently
    // owed to the fact that we are not making efforts to keep "state"
    // persistently held in sandbox process, so the fields below
    // might go away and/or move to a different place eventually.
    /// Global variables.
    pub globals: Vec<Global>,

    /// Page delta produced by this execution.
    pub page_delta: Vec<IndexedPage>,

    /// Size of memory.
    pub heap_size: NumWasmPages,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IndexedPage {
    pub index: PageIndex,
    #[serde(with = "BigArray")]
    pub data: PageBytes,
}
