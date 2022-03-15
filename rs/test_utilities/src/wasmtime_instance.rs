use std::sync::Arc;

use ic_embedders::{
    wasm_utils::instrumentation::{instrument, InstructionCostTable},
    wasmtime_embedder::WasmtimeInstance,
    WasmtimeEmbedder,
};
use ic_interfaces::execution_environment::{AvailableMemory, ExecutionMode, ExecutionParameters};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Global, Memory, PageMap};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ModificationTracking, SystemApiImpl,
};
use ic_types::{ComputeAllocation, NumInstructions};
use ic_wasm_types::BinaryEncodedWasm;

use crate::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time,
    state::SystemStateBuilder,
    types::ids::{canister_test_id, user_test_id},
};

pub const DEFAULT_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(5_000_000_000);

fn execution_parameters() -> ExecutionParameters {
    ExecutionParameters {
        instruction_limit: DEFAULT_NUM_INSTRUCTIONS,
        canister_memory_limit: ic_types::NumBytes::from(4 << 30),
        subnet_available_memory: AvailableMemory::new(i64::MAX / 2, i64::MAX / 2).into(),
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    }
}

pub struct WasmtimeInstanceBuilder {
    wat: String,
    globals: Vec<Global>,
}

impl Default for WasmtimeInstanceBuilder {
    fn default() -> Self {
        Self {
            wat: "".to_string(),
            globals: vec![],
        }
    }
}

impl WasmtimeInstanceBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_wat(self, wat: &str) -> Self {
        Self {
            wat: wat.to_string(),
            ..self
        }
    }

    pub fn with_globals(self, globals: Vec<Global>) -> Self {
        Self { globals, ..self }
    }

    pub fn build(self) -> WasmtimeInstance<SystemApiImpl> {
        let log = no_op_logger();
        let wasm = wabt::wat2wasm(self.wat).expect("Failed to convert wat to wasm");

        let embedder = WasmtimeEmbedder::new(ic_config::embedders::Config::default(), log.clone());
        let output =
            instrument(&BinaryEncodedWasm::new(wasm), &InstructionCostTable::new()).unwrap();

        let compiled = embedder
            .compile(&output.binary)
            .expect("Failed to compile canister wasm");

        let user_id = user_test_id(24);

        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let sandbox_safe_system_state =
            SandboxSafeSystemState::new(&system_state, cycles_account_manager);
        let api = ic_system_api::SystemApiImpl::new(
            ic_system_api::ApiType::init(mock_time(), vec![], user_id.get()),
            sandbox_safe_system_state,
            ic_types::NumBytes::from(0),
            execution_parameters(),
            Memory::default(),
            Arc::new(ic_system_api::DefaultOutOfInstructionsHandler {}),
            log,
        );

        let mut instance = embedder
            .new_instance(
                canister_test_id(1),
                &compiled,
                &self.globals,
                ic_replicated_state::NumWasmPages::from(0),
                PageMap::default(),
                ModificationTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
        instance.set_num_instructions(DEFAULT_NUM_INSTRUCTIONS);
        instance
    }
}
