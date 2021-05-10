use ic_interfaces::execution_environment::{
    HypervisorResult, InstanceStats, SubnetAvailableMemory,
};
use ic_replicated_state::Global;
use ic_system_api::ApiType;
use ic_types::{
    ingress::WasmResult, methods::FuncRef, ComputeAllocation, NumBytes, NumInstructions,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Round(pub u64);

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecInput {
    pub func_ref: FuncRef,
    pub api_type: ApiType,
    pub instructions_limit: NumInstructions,
    pub globals: Vec<Global>,
    pub canister_memory_limit: NumBytes,
    pub canister_current_memory_usage: NumBytes,
    pub subnet_available_memory: SubnetAvailableMemory,
    pub compute_allocation: ComputeAllocation,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExecOutput {
    pub wasm_result: HypervisorResult<Option<WasmResult>>,
    pub num_instructions_left: NumInstructions,
    pub globals: Vec<Global>,
    pub instance_stats: InstanceStats,
}
