use std::{convert::TryFrom, rc::Rc};

use ic_base_types::NumBytes;
use ic_config::{flag_status::FlagStatus, subnet_config::SchedulerConfig};
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::{wasm_utils::compile, wasmtime_embedder::WasmtimeInstance, WasmtimeEmbedder};
use ic_interfaces::execution_environment::{
    ExecutionMode, HypervisorError, SubnetAvailableMemory, SystemApi,
};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Global, Memory, NetworkTopology, PageMap};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ExecutionParameters, InstructionLimits,
    ModificationTracking, SystemApiImpl,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::ids::{canister_test_id, user_test_id};
use ic_types::{
    messages::RequestMetadata, time::UNIX_EPOCH, ComputeAllocation, MemoryAllocation,
    NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;

pub const DEFAULT_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(5_000_000_000);

pub struct WasmtimeInstanceBuilder {
    wasm: Vec<u8>,
    wat: String,
    globals: Option<Vec<Global>>,
    api_type: ic_system_api::ApiType,
    num_instructions: NumInstructions,
    subnet_type: SubnetType,
    network_topology: NetworkTopology,
    config: ic_config::embedders::Config,
    canister_memory_limit: NumBytes,
}

impl Default for WasmtimeInstanceBuilder {
    fn default() -> Self {
        Self {
            wasm: vec![],
            wat: "".to_string(),
            globals: None,
            api_type: ic_system_api::ApiType::init(UNIX_EPOCH, vec![], user_test_id(24).get()),
            num_instructions: DEFAULT_NUM_INSTRUCTIONS,
            subnet_type: SubnetType::Application,
            network_topology: NetworkTopology::default(),
            config: ic_config::embedders::Config::default(),
            canister_memory_limit: NumBytes::from(4 << 30), // Set to 4 GiB by default
        }
    }
}

impl WasmtimeInstanceBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(self, config: ic_config::embedders::Config) -> Self {
        Self { config, ..self }
    }

    pub fn with_wat(self, wat: &str) -> Self {
        Self {
            wat: wat.to_string(),
            ..self
        }
    }

    pub fn with_wasm(self, wasm: Vec<u8>) -> Self {
        Self { wasm, ..self }
    }

    pub fn with_globals(self, globals: Vec<Global>) -> Self {
        Self {
            globals: Some(globals),
            ..self
        }
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

    pub fn with_canister_memory_limit(self, canister_memory_limit: NumBytes) -> Self {
        Self {
            canister_memory_limit,
            ..self
        }
    }

    pub fn try_build(self) -> Result<WasmtimeInstance, (HypervisorError, SystemApiImpl)> {
        let log = no_op_logger();

        let wasm = if !self.wat.is_empty() {
            wat::parse_str(self.wat).expect("Failed to convert wat to wasm")
        } else {
            self.wasm
        };

        let embedder = WasmtimeEmbedder::new(self.config, log.clone());
        let (compiled, _result) = compile(&embedder, &BinaryEncodedWasm::new(wasm));

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
            ComputeAllocation::default(),
            RequestMetadata::new(0, UNIX_EPOCH),
            self.api_type.caller(),
            self.api_type.call_context_id(),
        );

        let subnet_memory_capacity = i64::MAX / 2;

        let api = ic_system_api::SystemApiImpl::new(
            self.api_type,
            sandbox_safe_system_state,
            ic_types::NumBytes::from(0),
            ic_types::NumBytes::from(0),
            ExecutionParameters {
                instruction_limits: InstructionLimits::new(
                    FlagStatus::Disabled,
                    self.num_instructions,
                    self.num_instructions,
                ),
                canister_memory_limit: self.canister_memory_limit,
                wasm_memory_limit: None,
                memory_allocation: MemoryAllocation::default(),
                compute_allocation: ComputeAllocation::default(),
                subnet_type: self.subnet_type,
                execution_mode: ExecutionMode::Replicated,
                subnet_memory_saturation: ResourceSaturation::default(),
            },
            SubnetAvailableMemory::new(
                subnet_memory_capacity,
                subnet_memory_capacity,
                subnet_memory_capacity,
            ),
            embedder.config().feature_flags.wasm_native_stable_memory,
            embedder.config().max_sum_exported_function_name_lengths,
            Memory::new_for_testing(),
            Memory::new_for_testing().size,
            Rc::new(ic_system_api::DefaultOutOfInstructionsHandler::new(
                self.num_instructions,
            )),
            log,
        );
        let instruction_limit = api.slice_instruction_limit();
        let instance = embedder
            .new_instance(
                canister_test_id(1),
                &compiled,
                self.globals.as_deref(),
                &Memory::new(
                    PageMap::new_for_testing(),
                    ic_replicated_state::NumWasmPages::from(0),
                ),
                &Memory::new(
                    PageMap::new_for_testing(),
                    ic_replicated_state::NumWasmPages::from(0),
                ),
                ModificationTracking::Track,
                Some(api),
            )
            .map(|mut result| {
                result.set_instruction_counter(i64::try_from(instruction_limit.get()).unwrap());
                result
            });
        instance.map_err(|(h, s)| (h, s.unwrap()))
    }

    pub fn build(self) -> WasmtimeInstance {
        let instance = self.try_build();
        instance
            .map_err(|r| r.0)
            .expect("Failed to create instance")
    }
}
