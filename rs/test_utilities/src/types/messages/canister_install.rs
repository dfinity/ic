use crate::types::ids::canister_test_id;
use ic_types::{
    messages::CanisterInstallMode, CanisterId, ComputeAllocation, InstallCodeContext,
    MemoryAllocation, PrincipalId, QueryAllocation,
};

pub struct InstallCodeContextBuilder {
    ctx: InstallCodeContext,
}

impl InstallCodeContextBuilder {
    pub fn sender(mut self, sender: PrincipalId) -> Self {
        self.ctx.sender = sender;
        self
    }

    pub fn canister_id(mut self, canister_id: CanisterId) -> Self {
        self.ctx.canister_id = canister_id;
        self
    }

    pub fn wasm_module(mut self, wasm_module: Vec<u8>) -> Self {
        self.ctx.wasm_module = wasm_module;
        self
    }

    pub fn arg(mut self, arg: Vec<u8>) -> Self {
        self.ctx.arg = arg;
        self
    }

    pub fn compute_allocation(mut self, compute_allocation: ComputeAllocation) -> Self {
        self.ctx.compute_allocation = Some(compute_allocation);
        self
    }

    pub fn memory_allocation(mut self, memory_allocation: MemoryAllocation) -> Self {
        self.ctx.memory_allocation = Some(memory_allocation);
        self
    }

    pub fn query_allocation(mut self, query_allocation: QueryAllocation) -> Self {
        self.ctx.query_allocation = query_allocation;
        self
    }

    pub fn mode(mut self, mode: CanisterInstallMode) -> Self {
        self.ctx.mode = mode;
        self
    }

    pub fn build(&self) -> InstallCodeContext {
        self.ctx.clone()
    }
}

impl Default for InstallCodeContextBuilder {
    fn default() -> Self {
        Self {
            ctx: InstallCodeContext {
                sender: PrincipalId::new_user_test_id(0),
                canister_id: canister_test_id(0),
                wasm_module: wabt::wat2wasm(r#"(module (memory $memory 1 1000))"#).unwrap(),
                arg: vec![],
                compute_allocation: Some(ComputeAllocation::default()),
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
        }
    }
}
