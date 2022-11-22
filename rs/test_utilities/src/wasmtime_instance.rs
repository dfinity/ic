use std::convert::TryFrom;
use std::sync::Arc;

use ic_config::{flag_status::FlagStatus, subnet_config::SchedulerConfig};
use ic_embedders::{wasm_utils::compile, wasmtime_embedder::WasmtimeInstance, WasmtimeEmbedder};
use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory, SystemApi};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Global, Memory, NetworkTopology, PageMap};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ExecutionParameters, InstructionLimits,
    ModificationTracking, SystemApiImpl,
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

pub struct WasmtimeInstanceBuilder {
    wat: String,
    globals: Vec<Global>,
    api_type: ic_system_api::ApiType,
    num_instructions: NumInstructions,
    subnet_type: SubnetType,
    network_topology: NetworkTopology,
}

impl Default for WasmtimeInstanceBuilder {
    fn default() -> Self {
        Self {
            wat: "".to_string(),
            globals: vec![],
            api_type: ic_system_api::ApiType::init(mock_time(), vec![], user_test_id(24).get()),
            num_instructions: DEFAULT_NUM_INSTRUCTIONS,
            subnet_type: SubnetType::Application,
            network_topology: NetworkTopology::default(),
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

    pub fn with_api_type(self, api_type: ic_system_api::ApiType) -> Self {
        Self { api_type, ..self }
    }

    pub fn with_num_instructions(self, num_instructions: NumInstructions) -> Self {
        Self {
            num_instructions,
            ..self
        }
    }

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        Self {
            subnet_type,
            ..self
        }
    }

    pub fn build(self) -> WasmtimeInstance<SystemApiImpl> {
        let log = no_op_logger();
        let wasm = wabt::wat2wasm(self.wat).expect("Failed to convert wat to wasm");

        let config = ic_config::embedders::Config::default();
        let embedder = WasmtimeEmbedder::new(config, log.clone());
        let (compiled, result) = compile(&embedder, &BinaryEncodedWasm::new(wasm));
        result.expect("Failed to compile wat in WasmtimeInstance");

        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let dirty_page_overhead = match self.subnet_type {
            SubnetType::Application => SchedulerConfig::application_subnet(),
            SubnetType::VerifiedApplication => SchedulerConfig::verified_application_subnet(),
            SubnetType::System => SchedulerConfig::system_subnet(),
        }
        .dirty_page_overhead;

        let sandbox_safe_system_state = SandboxSafeSystemState::new(
            &system_state,
            cycles_account_manager,
            &self.network_topology,
            dirty_page_overhead,
        );
        let api = ic_system_api::SystemApiImpl::new(
            self.api_type,
            sandbox_safe_system_state,
            ic_types::NumBytes::from(0),
            ExecutionParameters {
                instruction_limits: InstructionLimits::new(
                    FlagStatus::Disabled,
                    self.num_instructions,
                    self.num_instructions,
                ),
                canister_memory_limit: ic_types::NumBytes::from(4 << 30),
                compute_allocation: ComputeAllocation::default(),
                subnet_type: self.subnet_type,
                execution_mode: ExecutionMode::Replicated,
            },
            SubnetAvailableMemory::new(i64::MAX / 2, i64::MAX / 2),
            Memory::default(),
            Arc::new(ic_system_api::DefaultOutOfInstructionsHandler {}),
            log,
        );
        let instruction_limit = api.slice_instruction_limit();
        let mut instance = embedder
            .new_instance(
                canister_test_id(1),
                &compiled,
                &self.globals,
                &Memory::new(
                    PageMap::default(),
                    ic_replicated_state::NumWasmPages::from(0),
                ),
                &Memory::new(
                    PageMap::default(),
                    ic_replicated_state::NumWasmPages::from(0),
                ),
                ModificationTracking::Track,
                api,
            )
            .map_err(|r| r.0)
            .expect("Failed to create instance");
        instance.set_instruction_counter(i64::try_from(instruction_limit.get()).unwrap());
        instance
    }
}
