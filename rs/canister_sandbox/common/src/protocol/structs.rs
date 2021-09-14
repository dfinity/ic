use ic_interfaces::execution_environment::{ExecutionParameters, HypervisorResult, InstanceStats};
use ic_replicated_state::Global;
use ic_system_api::ApiType;
use ic_types::{ingress::WasmResult, methods::FuncRef, CanisterId, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};

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
    pub globals: Vec<Global>,
    pub instance_stats: InstanceStats,
}
