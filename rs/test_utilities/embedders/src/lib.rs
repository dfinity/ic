use std::collections::BTreeMap;
use std::{convert::TryFrom, rc::Rc};

use ic_base_types::NumBytes;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_config::subnet_config::SchedulerConfig;
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::{
    WasmtimeEmbedder,
    wasm_utils::compile,
    wasmtime_embedder::{
        WasmtimeInstance,
        system_api::{
            ApiType, DefaultOutOfInstructionsHandler, ExecutionParameters, InstructionLimits,
            ModificationTracking, SystemApiImpl, sandbox_safe_system_state::SandboxSafeSystemState,
        },
    },
};
use ic_interfaces::execution_environment::{
    ExecutionMode, HypervisorError, MessageMemoryUsage, SubnetAvailableMemory, SystemApi,
};
use ic_logger::replica_logger::no_op_logger;
use ic_management_canister_types_private::Global;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Memory, NetworkTopology, NumWasmPages, PageMap};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::ids::{canister_test_id, user_test_id};
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::{ComputeAllocation, MemoryAllocation, NumInstructions, time::UNIX_EPOCH};
use ic_wasm_types::BinaryEncodedWasm;

pub const DEFAULT_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(5_000_000_000);

pub struct WasmtimeInstanceBuilder {
    wasm: Vec<u8>,
    wat: String,
    globals: Option<Vec<Global>>,
    api_type: ApiType,
    num_instructions: NumInstructions,
    subnet_type: SubnetType,
    network_topology: NetworkTopology,
    config: ic_config::embedders::Config,
    memory_usage: NumBytes,
    environment_variables: BTreeMap<String, String>,
}

impl Default for WasmtimeInstanceBuilder {
    fn default() -> Self {
        Self {
            wasm: vec![],
            wat: "".to_string(),
            globals: None,
            api_type: ApiType::init(UNIX_EPOCH, vec![], user_test_id(24).get()),
            num_instructions: DEFAULT_NUM_INSTRUCTIONS,
            subnet_type: SubnetType::Application,
            network_topology: NetworkTopology::default(),
            config: ic_config::embedders::Config::default(),
            memory_usage: NumBytes::from(0),
            environment_variables: BTreeMap::new(),
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

    pub fn with_api_type(self, api_type: ApiType) -> Self {
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

    pub fn with_memory_usage(self, memory_usage: NumBytes) -> Self {
        Self {
            memory_usage,
            ..self
        }
    }

    pub fn with_environment_variables(
        self,
        environment_variables: BTreeMap<String, String>,
    ) -> Self {
        Self {
            environment_variables,
            ..self
        }
    }

    #[allow(clippy::result_large_err)]
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
        let system_state = SystemStateBuilder::default()
            .environment_variables(self.environment_variables)
            .build();
        let dirty_page_overhead = match self.subnet_type {
            SubnetType::Application => SchedulerConfig::application_subnet(),
            SubnetType::VerifiedApplication => SchedulerConfig::verified_application_subnet(),
            SubnetType::System => SchedulerConfig::system_subnet(),
        }
        .dirty_page_overhead;
        let subnet_available_callbacks =
            HypervisorConfig::default().subnet_callback_soft_limit as u64;
        let canister_callback_quota =
            HypervisorConfig::default().canister_guaranteed_callback_quota as u64;

        let sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
            &system_state,
            cycles_account_manager,
            &self.network_topology,
            dirty_page_overhead,
            ComputeAllocation::default(),
            subnet_available_callbacks,
            Default::default(),
            self.api_type.caller(),
            self.api_type.call_context_id(),
            CanisterCyclesCostSchedule::Normal,
        );

        let subnet_memory_capacity = i64::MAX / 2;

        let api = SystemApiImpl::new(
            self.api_type,
            sandbox_safe_system_state,
            self.memory_usage,
            MessageMemoryUsage::ZERO,
            ExecutionParameters {
                instruction_limits: InstructionLimits::new(
                    self.num_instructions,
                    self.num_instructions,
                ),
                wasm_memory_limit: None,
                memory_allocation: MemoryAllocation::default(),
                canister_guaranteed_callback_quota: canister_callback_quota,
                compute_allocation: ComputeAllocation::default(),
                subnet_type: self.subnet_type,
                execution_mode: ExecutionMode::Replicated,
                subnet_memory_saturation: ResourceSaturation::default(),
            },
            SubnetAvailableMemory::new_for_testing(
                subnet_memory_capacity,
                subnet_memory_capacity,
                subnet_memory_capacity,
            ),
            embedder.config(),
            Memory::new_for_testing(),
            NumWasmPages::from(0),
            Rc::new(DefaultOutOfInstructionsHandler::new(self.num_instructions)),
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
