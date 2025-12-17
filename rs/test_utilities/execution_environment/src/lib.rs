use ic_base_types::{NumBytes, NumSeconds, PrincipalId, SubnetId};
use ic_config::embedders::{MeteringType, StableMemoryPageLimit};
use ic_config::{
    embedders::{Config as EmbeddersConfig, WASM_MAX_SIZE},
    execution_environment::Config,
    flag_status::FlagStatus,
    subnet_config::SchedulerConfig,
    subnet_config::SubnetConfig,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_cycles_account_manager::{CyclesAccountManager, ResourceSaturation};
use ic_embedders::{
    WasmtimeEmbedder,
    wasm_utils::{compile, decoding::decode_wasm},
    wasmtime_embedder::system_api::InstructionLimits,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
pub use ic_execution_environment::ExecutionResponse;
use ic_execution_environment::{
    CompilationCostHandling, DataCertificateWithDelegationMetadata, ExecuteMessageResult,
    ExecutionEnvironment, ExecutionServicesForTesting, Hypervisor, IngressFilterMetrics,
    InternalHttpQueryHandler, RoundInstructions, RoundLimits, execute_canister,
};
use ic_interfaces::execution_environment::{
    ChainKeySettings, ExecutionMode, IngressHistoryWriter, RegistryExecutionSettings,
    SubnetAvailableMemory,
};
use ic_interfaces_state_manager::Labeled;
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::{ReplicaLogger, replica_logger::no_op_logger};
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallMode, CanisterInstallModeV2, CanisterSettingsArgs,
    CanisterSettingsArgsBuilder, CanisterStatusResultV2, CanisterStatusType,
    CanisterUpgradeOptions, EmptyBlob, InstallCodeArgs, InstallCodeArgsV2, LogVisibilityV2,
    MasterPublicKeyId, Method, Payload, ProvisionalCreateCanisterWithCyclesArgs, SchnorrAlgorithm,
    UpdateSettingsArgs,
};
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{
    CANISTER_IDS_PER_SUBNET, CanisterIdRange, RoutingTable, WellFormedError,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallContext, CanisterState, ExecutionState, ExecutionTask, InputQueueType, NetworkTopology,
    PageIndex, ReplicatedState, SubnetTopology,
    canister_state::{
        NextExecution, execution_state::SandboxMemory, execution_state::WasmExecutionMode,
        system_state::CyclesUseCase,
    },
    page_map::{
        PAGE_SIZE, PageMap, TestPageAllocatorFileDescriptorImpl,
        test_utils::base_only_storage_layout,
    },
    testing::{CanisterQueuesTesting, ReplicatedStateTesting},
};
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_types::messages::{IngressBuilder, RequestBuilder, SignedIngressBuilder};
use ic_types::batch::{CanisterCyclesCostSchedule, ChainKeyData};
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetSubnet,
};
use ic_types::messages::CertificateDelegationMetadata;
use ic_types::{
    CanisterId, Cycles, Height, NumInstructions, QueryStatsEpoch, Time, UserId,
    batch::QueryStats,
    crypto::{AlgorithmId, canister_threshold_sig::MasterPublicKey},
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        CallbackId, CanisterCall, CanisterMessage, CanisterTask,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, MessageId, Payload as ResponsePayload, Query,
        QuerySource, RequestOrResponse, Response,
    },
    time::UNIX_EPOCH,
};
use ic_types::{ExecutionRound, RegistryVersion, ReplicaVersion};
use ic_types_test_utils::ids::{node_test_id, subnet_test_id, user_test_id};
use ic_universal_canister::{UNIVERSAL_CANISTER_SERIALIZED_MODULE, UNIVERSAL_CANISTER_WASM};
use ic_wasm_types::BinaryEncodedWasm;
use maplit::{btreemap, btreeset};
use num_traits::ops::saturating::SaturatingAdd;
use prometheus::IntCounter;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::TryFrom,
    os::unix::prelude::FileExt,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tempfile::NamedTempFile;

mod wat_canister;
pub use wat_canister::{WatCanisterBuilder, WatFnCode, wat_canister, wat_fn};

const INITIAL_CANISTER_CYCLES: Cycles = Cycles::new(1_000_000_000_000);

// These are well formed example public keys.
// We need to have well formed keys for the "*_public_key" tests, otherwise crypto will
// return an error and we can't test the happy path.
const ECDSA_PUB_KEY: [u8; 33] = [
    2, 249, 172, 52, 95, 107, 230, 219, 81, 225, 197, 97, 44, 221, 181, 158, 114, 195, 208, 212,
    147, 201, 148, 209, 32, 53, 207, 19, 37, 126, 59, 31, 167,
];
const SCHNORR_BIP340_PUB_KEY: [u8; 33] = [
    3, 122, 101, 26, 46, 94, 243, 209, 239, 99, 232, 76, 76, 76, 170, 2, 159, 164, 164, 58, 52,
    122, 145, 228, 216, 74, 142, 132, 104, 83, 213, 27, 225,
];
const SCHNORR_ED29915_PUB_KEY: [u8; 32] = [
    108, 8, 36, 190, 179, 118, 33, 188, 202, 110, 236, 194, 55, 237, 27, 196, 230, 76, 156, 89,
    220, 184, 83, 68, 170, 127, 156, 200, 39, 142, 227, 31,
];
const VETKD_PUB_KEY: [u8; 96] = [
    173, 134, 232, 255, 132, 89, 18, 240, 34, 160, 131, 138, 80, 45, 118, 63, 222, 165, 71, 201,
    148, 143, 140, 178, 14, 167, 115, 141, 213, 44, 28, 56, 220, 180, 198, 202, 154, 194, 159, 154,
    198, 144, 252, 90, 215, 104, 28, 180, 25, 34, 184, 223, 251, 214, 93, 148, 191, 241, 65, 245,
    251, 91, 102, 36, 236, 204, 3, 191, 133, 15, 34, 32, 82, 223, 136, 140, 249, 177, 228, 114, 3,
    85, 109, 117, 34, 39, 28, 187, 135, 155, 46, 244, 184, 194, 191, 177,
];

/// A helper to create subnets.
pub fn generate_subnets(
    subnet_ids: Vec<SubnetId>,
    nns_subnet_id: SubnetId,
    root_key: Option<Vec<u8>>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    own_subnet_size: usize,
) -> BTreeMap<SubnetId, SubnetTopology> {
    let mut result: BTreeMap<SubnetId, SubnetTopology> = Default::default();
    for subnet_id in subnet_ids {
        let mut subnet_type = SubnetType::System;
        let mut nodes = btreeset! {};
        if subnet_id == own_subnet_id {
            subnet_type = own_subnet_type;
            // Populate network_topology of own_subnet with fake nodes to simulate subnet_size.
            for i in 0..own_subnet_size {
                nodes.insert(node_test_id(i as u64));
            }
        }
        let public_key = if subnet_id == nns_subnet_id {
            root_key.clone().unwrap_or(vec![1, 2, 3, 4])
        } else {
            vec![1, 2, 3, 4]
        };
        result.insert(
            subnet_id,
            SubnetTopology {
                public_key,
                nodes,
                subnet_type,
                subnet_features: SubnetFeatures::default(),
                chain_keys_held: BTreeSet::new(),
                cost_schedule: CanisterCyclesCostSchedule::Normal,
            },
        );
    }
    result
}

pub fn generate_network_topology(
    subnet_size: usize,
    own_subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    subnets: Vec<SubnetId>,
    routing_table: Option<RoutingTable>,
) -> NetworkTopology {
    NetworkTopology {
        nns_subnet_id,
        subnets: generate_subnets(subnets, nns_subnet_id, None, own_subnet_id, own_subnet_type, subnet_size),
        routing_table: match routing_table {
            Some(routing_table) => Arc::new(routing_table),
            None => {
                Arc::new(RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0), end: CanisterId::from(CANISTER_IDS_PER_SUBNET - 1) } => own_subnet_id,
            }).unwrap())
            }
        },
        ..Default::default()
    }
}

pub fn test_registry_settings() -> RegistryExecutionSettings {
    RegistryExecutionSettings {
        max_number_of_canisters: 0x2000,
        provisional_whitelist: ProvisionalWhitelist::Set(BTreeSet::new()),
        chain_key_settings: BTreeMap::new(),
        subnet_size: SMALL_APP_SUBNET_MAX_SIZE,
        node_ids: BTreeSet::new(),
        registry_version: RegistryVersion::default(),
        canister_cycles_cost_schedule: ic_types::batch::CanisterCyclesCostSchedule::Normal,
    }
}

/// When a universal canister is installed, but the serialized module has been
/// cached, the test setup thinks the canister was only charged for the reduced
/// compilation cost amount, when it was really charged for the full amount
/// (because it uses the change in round limits instead of what the canister was
/// actually charged). This function returns the amount needed to correct for
/// that difference.
pub fn universal_canister_compilation_cost_correction() -> NumInstructions {
    let cost = wasm_compilation_cost(&UNIVERSAL_CANISTER_WASM);
    cost - CompilationCostHandling::CountReducedAmount.adjusted_compilation_cost(cost)
}

/// Helper function to test that cycles are reserved for both
/// application and verified application subnets.
///
/// Expects a test function that takes a `SubnetType` as an argument
/// so it can be tested over the desired subnet types.
pub fn cycles_reserved_for_app_and_verified_app_subnets<T: Fn(SubnetType)>(test: T) {
    for subnet_type in [SubnetType::Application, SubnetType::VerifiedApplication] {
        test(subnet_type);
    }
}

/// A helper for execution tests.
///
/// Example usage:
/// ```no_run
/// use ic_test_utilities_execution_environment::{*};
/// let mut test = ExecutionTestBuilder::new().build();
/// let wat = r#"(module (func (export "canister_query query")))"#;
/// let canister_id = test.canister_from_wat(wat).unwrap();
/// let result = test.ingress(canister_id, "query", vec![]);
/// expect_canister_did_not_reply(result);
/// ```
pub struct ExecutionTest {
    // Mutable fields that change after message execution.

    // The current replicated state. The option type allows taking the state for
    // execution and then putting it back afterwards.
    state: Option<ReplicatedState>,
    // Monotonically increasing ingress message id.
    message_id: u64,
    // The memory available in the subnet.
    subnet_available_memory: SubnetAvailableMemory,
    // The memory reserved for executing response handlers.
    subnet_memory_reservation: NumBytes,
    // The pool of callbacks available on the subnet.
    subnet_available_callbacks: i64,
    // The number of instructions executed so far per canister.
    executed_instructions: HashMap<CanisterId, NumInstructions>,
    // The total cost of execution so far per canister.
    execution_cost: HashMap<CanisterId, Cycles>,
    // Messages to canisters on other subnets.
    xnet_messages: Vec<RequestOrResponse>,
    // Messages that couldn't be delivered to other canisters
    // due to an error in `push_input()`.
    lost_messages: Vec<RequestOrResponse>,

    // Mutable parameters of execution.
    time: Time,
    user_id: UserId,
    current_round: ExecutionRound,

    // Read-only fields.
    dirty_heap_page_overhead: u64,
    instruction_limits: InstructionLimits,
    install_code_instruction_limits: InstructionLimits,
    instruction_limit_per_query_message: NumInstructions,
    initial_canister_cycles: Cycles,
    ingress_memory_capacity: NumBytes,
    registry_settings: RegistryExecutionSettings,
    manual_execution: bool,
    caller_canister_id: Option<CanisterId>,
    chain_key_data: ChainKeyData,
    replica_version: ReplicaVersion,
    canister_snapshot_baseline_instructions: NumInstructions,

    // The actual implementation.
    exec_env: Arc<ExecutionEnvironment>,
    query_handler: InternalHttpQueryHandler,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics_registry: MetricsRegistry,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    log: ReplicaLogger,

    // Temporary files created to fake checkpoints. They are only stored so that
    // they can be properly cleaned up on test completion.
    checkpoint_files: Vec<NamedTempFile>,
}

impl ExecutionTest {
    pub fn hypervisor_deprecated(&self) -> &Hypervisor {
        self.exec_env.hypervisor_for_testing()
    }

    pub fn execution_environment(&self) -> Arc<ExecutionEnvironment> {
        Arc::clone(&self.exec_env)
    }

    pub fn dirty_heap_page_overhead(&self) -> u64 {
        self.dirty_heap_page_overhead
    }

    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn set_user_id(&mut self, user_id: UserId) {
        self.user_id = user_id
    }

    pub fn state(&self) -> &ReplicatedState {
        self.state.as_ref().unwrap()
    }

    pub fn state_mut(&mut self) -> &mut ReplicatedState {
        self.state.as_mut().unwrap()
    }

    pub fn canister_state(&self, canister_id: CanisterId) -> &CanisterState {
        self.state().canister_state(&canister_id).unwrap()
    }

    pub fn install_code_instructions_limit(&self) -> NumInstructions {
        self.install_code_instruction_limits.message()
    }

    pub fn canister_state_mut(&mut self, canister_id: CanisterId) -> &mut CanisterState {
        self.state_mut().canister_state_mut(&canister_id).unwrap()
    }

    pub fn execution_state(&self, canister_id: CanisterId) -> &ExecutionState {
        self.canister_state(canister_id)
            .execution_state
            .as_ref()
            .unwrap()
    }

    pub fn max_instructions_per_message(&self) -> NumInstructions {
        self.instruction_limits.message()
    }

    pub fn canister_wasm_execution_mode(&self, canister_id: CanisterId) -> WasmExecutionMode {
        // In case of any error or missing state, default to Wasm32.
        if let Some(state) = self.state.as_ref()
            && let Some(canister) = state.canister_state(&canister_id).as_ref()
            && let Some(execution_state) = canister.execution_state.as_ref()
        {
            return execution_state.wasm_execution_mode;
        }
        WasmExecutionMode::Wasm32
    }

    pub fn xnet_messages(&self) -> &Vec<RequestOrResponse> {
        &self.xnet_messages
    }

    pub fn get_xnet_response(&self, index: usize) -> &Arc<Response> {
        match &self.xnet_messages[index] {
            RequestOrResponse::Request(request) => {
                panic!("Expected the xnet message to be a Response, but got a Request: {request:?}")
            }
            RequestOrResponse::Response(response) => response,
        }
    }

    pub fn lost_messages(&self) -> &Vec<RequestOrResponse> {
        &self.lost_messages
    }

    pub fn subnet_size(&self) -> usize {
        self.registry_settings.subnet_size
    }

    pub fn cost_schedule(&self) -> CanisterCyclesCostSchedule {
        self.registry_settings.canister_cycles_cost_schedule
    }

    pub fn executed_instructions(&self) -> NumInstructions {
        self.executed_instructions.values().sum()
    }

    pub fn ingress_memory_capacity(&self) -> NumBytes {
        self.ingress_memory_capacity
    }

    pub fn canister_executed_instructions(&self, canister_id: CanisterId) -> NumInstructions {
        *self
            .executed_instructions
            .get(&canister_id)
            .unwrap_or(&NumInstructions::new(0))
    }

    pub fn execution_cost(&self) -> Cycles {
        Cycles::new(self.execution_cost.values().map(|x| x.get()).sum())
    }

    pub fn canister_snapshot_cost(&self, canister_id: CanisterId) -> Cycles {
        let canister = self.canister_state(canister_id);
        let new_snapshot_size = canister.snapshot_size_bytes();
        let instructions = self
            .canister_snapshot_baseline_instructions
            .saturating_add(&new_snapshot_size.get().into());
        self.cycles_account_manager.execution_cost(
            instructions,
            self.subnet_size(),
            self.cost_schedule(),
            // For the `take_canister_snapshot` operation, it does not matter if this is a Wasm64 or Wasm32 module
            // since the number of instructions charged depends on constant set fee and snapshot size
            // and Wasm64 does not bring any additional overhead for this operation.
            // The only overhead is during execution time.
            WasmExecutionMode::Wasm32,
        )
    }

    pub fn canister_execution_cost(&self, canister_id: CanisterId) -> Cycles {
        *self
            .execution_cost
            .get(&canister_id)
            .unwrap_or(&Cycles::new(0))
    }

    pub fn idle_cycles_burned_per_day(&self, canister_id: CanisterId) -> Cycles {
        let memory_usage = self.canister_state(canister_id).memory_usage();
        self.idle_cycles_burned_per_day_for_memory_usage(canister_id, memory_usage)
    }

    pub fn idle_cycles_burned_per_day_for_memory_usage(
        &self,
        canister_id: CanisterId,
        memory_usage: NumBytes,
    ) -> Cycles {
        let memory_allocation = self
            .canister_state(canister_id)
            .system_state
            .memory_allocation;
        let compute_allocation = self
            .canister_state(canister_id)
            .scheduler_state
            .compute_allocation;
        let message_memory_usage = self.canister_state(canister_id).message_memory_usage();
        self.cycles_account_manager.idle_cycles_burned_rate(
            memory_allocation,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            self.subnet_size(),
            self.cost_schedule(),
        )
    }

    pub fn freezing_threshold(&self, canister_id: CanisterId) -> Cycles {
        let canister = self.canister_state(canister_id);
        let memory_usage = canister.memory_usage();
        let message_memory_usage = canister.message_memory_usage();
        let memory_allocation = canister.system_state.memory_allocation;
        let compute_allocation = canister.scheduler_state.compute_allocation;
        let freeze_threshold = canister.system_state.freeze_threshold;
        self.cycles_account_manager.freeze_threshold_cycles(
            freeze_threshold,
            memory_allocation,
            memory_usage,
            message_memory_usage,
            compute_allocation,
            self.subnet_size(),
            self.cost_schedule(),
            canister.system_state.reserved_balance(),
        )
    }

    pub fn call_fee<S: ToString>(&self, method_name: S, payload: &[u8]) -> Cycles {
        self.cycles_account_manager
            .xnet_call_performed_fee(self.subnet_size(), self.cost_schedule())
            + self.cycles_account_manager.xnet_call_bytes_transmitted_fee(
                NumBytes::from((payload.len() + method_name.to_string().len()) as u64),
                self.subnet_size(),
                self.cost_schedule(),
            )
    }

    pub fn max_response_fee(&self) -> Cycles {
        self.cycles_account_manager.xnet_call_bytes_transmitted_fee(
            MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            self.subnet_size(),
            self.cost_schedule(),
        )
    }

    pub fn reply_fee(&self, payload: &[u8]) -> Cycles {
        self.cycles_account_manager.xnet_call_bytes_transmitted_fee(
            NumBytes::from(payload.len() as u64),
            self.subnet_size(),
            self.cost_schedule(),
        )
    }

    pub fn reject_fee<S: ToString>(&self, reject_message: S) -> Cycles {
        let bytes = reject_message.to_string().len() + std::mem::size_of::<RejectCode>();
        self.cycles_account_manager.xnet_call_bytes_transmitted_fee(
            NumBytes::from(bytes as u64),
            self.subnet_size(),
            self.cost_schedule(),
        )
    }

    pub fn canister_creation_fee(&self) -> Cycles {
        self.cycles_account_manager
            .canister_creation_fee(self.subnet_size(), self.cost_schedule())
    }

    pub fn http_request_fee(
        &self,
        request_size: NumBytes,
        response_size_limit: Option<NumBytes>,
    ) -> Cycles {
        self.cycles_account_manager.http_request_fee(
            request_size,
            response_size_limit,
            self.subnet_size(),
            self.cost_schedule(),
        )
    }

    pub fn reduced_wasm_compilation_fee(&self, wasm: &[u8]) -> Cycles {
        let cost = wasm_compilation_cost(wasm);
        self.convert_instructions_to_cycles(
            cost - CompilationCostHandling::CountReducedAmount.adjusted_compilation_cost(cost),
            WasmExecutionMode::Wasm32, // In this case it does not matter if it is a Wasm64 or Wasm32 canister.
        )
    }

    pub fn convert_instructions_to_cycles(
        &self,
        instructions: NumInstructions,
        mode: WasmExecutionMode,
    ) -> Cycles {
        self.cycles_account_manager()
            .convert_instructions_to_cycles(instructions, mode)
    }

    pub fn install_code_reserved_execution_cycles(&self) -> Cycles {
        let num_instructions = self.install_code_instruction_limits.message();
        self.cycles_account_manager.execution_cost(
            num_instructions,
            self.subnet_size(),
            self.cost_schedule(),
            WasmExecutionMode::Wasm32, // For this test, we can assume a Wasm32 execution.
        )
    }

    pub fn subnet_available_memory(&self) -> SubnetAvailableMemory {
        self.subnet_available_memory
    }

    pub fn set_available_execution_memory(&mut self, execution_memory: i64) {
        self.subnet_available_memory = SubnetAvailableMemory::new_for_testing(
            execution_memory,
            self.subnet_available_memory
                .get_guaranteed_response_message_memory(),
            self.subnet_available_memory
                .get_wasm_custom_sections_memory(),
        );
    }

    pub fn subnet_available_callbacks(&self) -> i64 {
        self.subnet_available_callbacks
    }

    pub fn set_subnet_available_callbacks(&mut self, callbacks: i64) {
        self.subnet_available_callbacks = callbacks
    }

    pub fn metrics_registry(&self) -> &MetricsRegistry {
        &self.metrics_registry
    }

    pub fn cycles_account_manager(&self) -> &CyclesAccountManager {
        &self.cycles_account_manager
    }

    pub fn time(&self) -> Time {
        self.time
    }

    pub fn advance_time(&mut self, duration: std::time::Duration) {
        self.time += duration;
    }

    pub fn ingress_status(&self, message_id: &MessageId) -> IngressStatus {
        self.state().get_ingress_status(message_id).clone()
    }

    pub fn ingress_result(&self, message_id: &MessageId) -> Result<WasmResult, UserError> {
        match self.ingress_state(message_id) {
            IngressState::Completed(res) => Ok(res),
            IngressState::Failed(err) => Err(err),
            status => panic!("Unexpected ingress status: {:?}", status),
        }
    }

    pub fn ingress_state(&self, message_id: &MessageId) -> IngressState {
        match self.ingress_status(message_id) {
            IngressStatus::Known { state, .. } => state,
            IngressStatus::Unknown => unreachable!("Expected a known ingress status."),
        }
    }

    pub fn get_call_context(
        &self,
        canister_id: CanisterId,
        callback_id: CallbackId,
    ) -> &CallContext {
        match self.canister_state(canister_id).status() {
            CanisterStatusType::Stopping => {
                panic!("Canister status is not running");
            }
            CanisterStatusType::Running | CanisterStatusType::Stopped => {
                let call_context_manager = self
                    .canister_state(canister_id)
                    .system_state
                    .call_context_manager()
                    .unwrap();
                let callback = call_context_manager
                    .callback(callback_id)
                    .expect("Unknown callback id.");
                call_context_manager
                    .call_context(callback.call_context_id)
                    .expect("Unknown call context id.")
            }
        }
    }

    /// Sends a `create_canister` message to the IC management canister.
    /// Consider using higher-level helpers like `canister_from_wat()`.
    pub fn create_canister(&mut self, cycles: Cycles) -> CanisterId {
        let args = ProvisionalCreateCanisterWithCyclesArgs::new(Some(cycles.get()), None);
        let result =
            self.subnet_message(Method::ProvisionalCreateCanisterWithCycles, args.encode());
        CanisterIdRecord::decode(&get_reply(result))
            .unwrap()
            .get_canister_id()
    }

    /// Deletes the specified canister.
    pub fn delete_canister(&mut self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        let payload = CanisterIdRecord::from(canister_id).encode();
        self.subnet_message(Method::DeleteCanister, payload)
    }

    pub fn create_canister_with_allocation(
        &mut self,
        cycles: Cycles,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
    ) -> Result<CanisterId, UserError> {
        self.create_canister_with_settings(
            cycles,
            CanisterSettingsArgsBuilder::new()
                .with_maybe_compute_allocation(compute_allocation)
                .with_maybe_memory_allocation(memory_allocation)
                .build(),
        )
    }

    pub fn create_canister_with_settings(
        &mut self,
        cycles: Cycles,
        settings: CanisterSettingsArgs,
    ) -> Result<CanisterId, UserError> {
        let mut args = ProvisionalCreateCanisterWithCyclesArgs::new(Some(cycles.get()), None);
        args.settings = Some(settings);

        let result =
            self.subnet_message(Method::ProvisionalCreateCanisterWithCycles, args.encode());

        match result {
            Ok(WasmResult::Reply(data)) => {
                Ok(CanisterIdRecord::decode(&data).unwrap().get_canister_id())
            }
            Ok(WasmResult::Reject(error)) => {
                panic!("Expected reply, got: {error:?}");
            }
            Err(error) => Err(error),
        }
    }

    /// Updates the compute and memory allocations of the given canister.
    pub fn canister_update_allocations_settings(
        &mut self,
        canister_id: CanisterId,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_maybe_compute_allocation(compute_allocation)
                .with_maybe_memory_allocation(memory_allocation)
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    /// Updates the controller of the given canister.
    pub fn canister_update_controller(
        &mut self,
        canister_id: CanisterId,
        controllers: Vec<PrincipalId>,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_controllers(controllers)
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    /// Updates the reserved cycles limit of the canister.
    pub fn canister_update_reserved_cycles_limit(
        &mut self,
        canister_id: CanisterId,
        reserved_cycles_limit: Cycles,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_reserved_cycles_limit(reserved_cycles_limit.get())
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    pub fn canister_update_wasm_memory_limit(
        &mut self,
        canister_id: CanisterId,
        wasm_memory_limit: NumBytes,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_wasm_memory_limit(wasm_memory_limit.get())
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    pub fn canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        &mut self,
        canister_id: CanisterId,
        wasm_memory_limit: NumBytes,
        wasm_memory_threshold: NumBytes,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_wasm_memory_limit(wasm_memory_limit.get())
                .with_wasm_memory_threshold(wasm_memory_threshold.get())
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    /// Sends an `install_code` message to the IC management canister.
    /// Consider using higher-level helpers like `canister_from_wat()`.
    pub fn install_code(&mut self, args: InstallCodeArgs) -> Result<WasmResult, UserError> {
        self.subnet_message(Method::InstallCode, args.encode())
    }

    pub fn install_code_v2(&mut self, args: InstallCodeArgsV2) -> Result<WasmResult, UserError> {
        self.subnet_message(Method::InstallCode, args.encode())
    }

    /// Sends an `install_code` message to the IC management canister with DTS.
    /// Similar to `subnet_message()`but does not check the ingress status of
    /// the response as the subnet message execution may not finish immediately.
    pub fn dts_install_code(&mut self, args: InstallCodeArgs) -> MessageId {
        let message_id = self.subnet_message_raw(Method::InstallCode, args.encode());
        self.execute_subnet_message();
        message_id
    }

    /// Sends an `uninstall_code` message to the IC management canister.
    pub fn uninstall_code(&mut self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        let payload = CanisterIdRecord::from(canister_id).encode();
        self.subnet_message(Method::UninstallCode, payload)
    }

    /// Starts running the given canister.
    /// Consider using higher-level helpers like `canister_from_wat()`.
    pub fn start_canister(&mut self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        let payload = CanisterIdRecord::from(canister_id).encode();
        self.subnet_message(Method::StartCanister, payload)
    }

    /// Changes the state of the given canister to stopping if it was previously running.
    pub fn stop_canister(&mut self, canister_id: CanisterId) -> MessageId {
        let payload = CanisterIdRecord::from(canister_id).encode();
        let message_id = self.subnet_message_raw(Method::StopCanister, payload);
        self.execute_subnet_message();
        message_id
    }

    /// Stops stopping canisters that no longer have open call contexts.
    pub fn process_stopping_canisters(&mut self) {
        let state = self
            .exec_env
            .process_stopping_canisters(self.state.take().unwrap());
        self.state = Some(state);
    }

    /// Returns the canister status by canister id.
    pub fn canister_status(
        &mut self,
        canister_id: CanisterId,
    ) -> Result<CanisterStatusResultV2, UserError> {
        let payload = CanisterIdRecord::from(canister_id).encode();
        let result = self.subnet_message(Method::CanisterStatus, payload);
        match result {
            Ok(WasmResult::Reply(bytes)) => Ok(CanisterStatusResultV2::decode(&bytes).unwrap()),
            Ok(WasmResult::Reject(err)) => panic!("Unexpected reject: {}", err),
            Err(err) => Err(err),
        }
    }

    /// Updates the settings of the given canister.
    pub fn update_settings(
        &mut self,
        canister_id: CanisterId,
        settings: CanisterSettingsArgs,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings,
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    /// Updates the freezing threshold of the given canister.
    pub fn update_freezing_threshold(
        &mut self,
        canister_id: CanisterId,
        freezing_threshold: NumSeconds,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_freezing_threshold(freezing_threshold.get())
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    /// Sets the controller of the canister to the given principal.
    pub fn set_controller(
        &mut self,
        canister_id: CanisterId,
        controller: PrincipalId,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![controller])
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    /// Sets the log visibility of the canister.
    pub fn set_log_visibility(
        &mut self,
        canister_id: CanisterId,
        log_visibility: LogVisibilityV2,
    ) -> Result<WasmResult, UserError> {
        let payload = UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_log_visibility(log_visibility)
                .build(),
            sender_canister_version: None,
        }
        .encode();
        self.subnet_message(Method::UpdateSettings, payload)
    }

    /// Installs the given Wasm binary in the given canister.
    pub fn install_canister(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        self.install_canister_with_args(canister_id, wasm_binary, vec![])
    }

    /// Installs the given Wasm binary in the given canister with the given init args.
    pub fn install_canister_with_args(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
        args: Vec<u8>,
    ) -> Result<(), UserError> {
        let args =
            InstallCodeArgs::new(CanisterInstallMode::Install, canister_id, wasm_binary, args);
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Installs the given Wasm binary in the given canister using `InstallCodeArgsV2`
    pub fn install_canister_v2(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgsV2::new(
            CanisterInstallModeV2::Install,
            canister_id,
            wasm_binary,
            vec![],
        );
        let result = self.install_code_v2(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Re-installs the given canister with the given Wasm binary.
    pub fn reinstall_canister(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        self.reinstall_canister_with_args(canister_id, wasm_binary, vec![])
    }

    /// Re-installs the given canister with the given Wasm binary and the given init args.
    pub fn reinstall_canister_with_args(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
        args: Vec<u8>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Reinstall,
            canister_id,
            wasm_binary,
            args,
        );
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    pub fn reinstall_canister_v2(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgsV2::new(
            CanisterInstallModeV2::Reinstall,
            canister_id,
            wasm_binary,
            vec![],
        );
        let result = self.install_code_v2(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Upgrades the given canister with the given Wasm binary.
    pub fn upgrade_canister(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        self.upgrade_canister_with_args(canister_id, wasm_binary, vec![])
    }

    /// Upgrades the given canister with the given Wasm binary and post-upgrade args.
    pub fn upgrade_canister_with_args(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
        args: Vec<u8>,
    ) -> Result<(), UserError> {
        let args =
            InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister_id, wasm_binary, args);
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Upgrades the given canister with the given Wasm binary and
    /// upgrade options.
    pub fn upgrade_canister_v2(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
        upgrade_options: CanisterUpgradeOptions,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgsV2::new(
            CanisterInstallModeV2::Upgrade(Some(upgrade_options)),
            canister_id,
            wasm_binary,
            vec![],
        );
        let result = self.install_code_v2(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Installs the given canister with the given Wasm binary with DTS.
    pub fn dts_upgrade_canister(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> MessageId {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister_id,
            wasm_binary,
            vec![],
        );
        self.dts_install_code(args)
    }

    pub fn upgrade_canister_with_allocation(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister_id,
            wasm_binary,
            vec![],
        );
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Creates a canister with the given balance and installs the Wasm binary.
    pub fn canister_from_cycles_and_binary(
        &mut self,
        initial_cycles: Cycles,
        wasm_binary: Vec<u8>,
    ) -> Result<CanisterId, UserError> {
        let canister_id = self.create_canister(initial_cycles);
        self.install_canister(canister_id, wasm_binary)?;
        Ok(canister_id)
    }

    /// Creates a canister with the given balance and installs the Wasm module
    /// given in the textual representation.
    pub fn canister_from_cycles_and_wat<S: ToString>(
        &mut self,
        initial_cycles: Cycles,
        wat: S,
    ) -> Result<CanisterId, UserError> {
        self.canister_from_cycles_and_binary(
            initial_cycles,
            wat::parse_str(wat.to_string()).unwrap(),
        )
    }

    /// Creates a canister and installs the Wasm binary.
    pub fn canister_from_binary(&mut self, wasm_binary: Vec<u8>) -> Result<CanisterId, UserError> {
        self.canister_from_cycles_and_binary(self.initial_canister_cycles, wasm_binary)
    }

    /// Creates a canister and installs the Wasm module given in the textual
    /// representation.
    pub fn canister_from_wat<S: ToString>(&mut self, wat: S) -> Result<CanisterId, UserError> {
        self.canister_from_cycles_and_wat(self.initial_canister_cycles, wat)
    }

    pub fn create_canister_with_default_cycles(&mut self) -> CanisterId {
        self.create_canister(self.initial_canister_cycles)
    }

    /// Creates and installs a universal canister.
    pub fn universal_canister(&mut self) -> Result<CanisterId, UserError> {
        self.canister_from_binary(UNIVERSAL_CANISTER_WASM.to_vec())
    }

    /// Creates and installs a universal canister with cycles
    pub fn universal_canister_with_cycles(
        &mut self,
        cycles: Cycles,
    ) -> Result<CanisterId, UserError> {
        self.canister_from_cycles_and_binary(cycles, UNIVERSAL_CANISTER_WASM.to_vec())
    }

    /// Sends an ingress message to the given canister to call an update or a
    /// query method. In the latter case the query runs in update context.
    ///
    /// The behaviour depends on the `self.manual_execution` flag which can be
    /// set using `with_manual_execution()` of the builder.
    /// When the flag is turned off, the function automatically inducts and executes
    /// all messages until there are no more new messages.
    /// Otherwise, the function enqueues the ingress message without executing it.
    pub fn ingress<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        check_ingress_status(self.ingress_raw(canister_id, method_name, method_payload).1)
    }

    /// Sends an ingress message to the given canister to call an update or a
    /// query method. In the latter case the query runs in update context.
    /// Returns a raw `IngressStatus` without checking if it is completed.
    ///
    /// The behaviour depends on the `self.manual_execution` flag which can be
    /// set using `with_manual_execution()` of the builder.
    /// When the flag is turned off, the function automatically inducts and executes
    /// all messages until there are no more new messages.
    /// Otherwise, the function enqueues the ingress message without executing it.
    pub fn ingress_raw<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> (MessageId, IngressStatus) {
        let mut state = self.state.take().unwrap();
        let ingress_id = self.next_message_id();
        let ingress = IngressBuilder::new()
            .message_id(ingress_id.clone())
            .source(self.user_id)
            .receiver(canister_id)
            .method_name(method_name)
            .method_payload(method_payload)
            .build();
        state
            .canister_state_mut(&canister_id)
            .unwrap()
            .push_ingress(ingress.clone());
        self.ingress_history_writer.set_status(
            &mut state,
            ingress.message_id,
            IngressStatus::Known {
                receiver: ingress.receiver.get(),
                user_id: ingress.source,
                time: self.time,
                state: IngressState::Received,
            },
        );
        self.state = Some(state);
        if !self.manual_execution {
            self.execute_all();
        }
        (ingress_id.clone(), self.ingress_status(&ingress_id))
    }

    /// Executes a canister task method of the given canister.
    pub fn canister_task(&mut self, canister_id: CanisterId, task: CanisterTask) {
        let mut state = self.state.take().unwrap();
        let compute_allocation_used = state.total_compute_allocation();
        let mut canister = state.take_canister_state(&canister_id).unwrap();
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let mut round_limits = RoundLimits {
            instructions: RoundInstructions::from(i64::MAX),
            subnet_available_memory: self.subnet_available_memory,
            subnet_available_callbacks: self.subnet_available_callbacks,
            compute_allocation_used,
            subnet_memory_reservation: self.subnet_memory_reservation,
        };
        match task {
            CanisterTask::Heartbeat => {
                canister
                    .system_state
                    .task_queue
                    .enqueue(ExecutionTask::Heartbeat);
            }
            CanisterTask::GlobalTimer => {
                canister
                    .system_state
                    .task_queue
                    .enqueue(ExecutionTask::GlobalTimer);
            }
            CanisterTask::OnLowWasmMemory => {
                // Set `OnLowWasmMemoryHookStatus` to `ConditionNotSatisfied`.
                canister
                    .system_state
                    .task_queue
                    .remove(ExecutionTask::OnLowWasmMemory);
                // Set `OnLowWasmMemoryHookStatus` to `Ready`.
                canister
                    .system_state
                    .task_queue
                    .enqueue(ExecutionTask::OnLowWasmMemory);
            }
        }
        let result = execute_canister(
            &self.exec_env,
            canister,
            self.instruction_limits.clone(),
            self.instruction_limit_per_query_message,
            Arc::clone(&network_topology),
            self.time,
            &mut round_limits,
            self.subnet_size(),
            self.cost_schedule(),
        );
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.subnet_available_callbacks = round_limits.subnet_available_callbacks;
        state.put_canister_state(result.canister);
        state.metadata.heap_delta_estimate += result.heap_delta;
        self.state = Some(state);
        self.update_execution_stats(
            canister_id,
            self.instruction_limits.message(),
            result.instructions_used.unwrap(),
        );
    }

    /// Executes a query sent by the system in the given canister.
    pub fn system_query<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let state = Arc::new(self.state.take().unwrap());

        let query = Query {
            source: QuerySource::System,
            receiver: canister_id,
            method_name: method_name.to_string(),
            method_payload,
        };

        let result = self.query_handler.query(
            query,
            Labeled::new(Height::from(0), Arc::clone(&state)),
            None,
            true,
        );

        self.state = Some(Arc::try_unwrap(state).unwrap());
        result
    }

    /// Executes a non-replicated query on the latest state.
    pub fn non_replicated_query<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.non_replicated_query_with_certificate_delegation_metadata(
            canister_id,
            method_name,
            method_payload,
            /*certificate_delegation_metadata=*/ None,
        )
    }

    /// Executes a non-replicated query on the latest state.
    pub fn non_replicated_query_with_certificate_delegation_metadata<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
        certificate_delegation_metadata: Option<CertificateDelegationMetadata>,
    ) -> Result<WasmResult, UserError> {
        let state = Arc::new(self.state.take().unwrap());

        let query = Query {
            source: QuerySource::User {
                user_id: self.user_id,
                ingress_expiry: 0,
                nonce: None,
            },
            receiver: canister_id,
            method_name: method_name.to_string(),
            method_payload,
        };
        let result = self.query(
            query,
            Arc::clone(&state),
            vec![],
            certificate_delegation_metadata,
        );

        self.state = Some(Arc::try_unwrap(state).unwrap());
        result
    }

    pub fn execute_response(
        &mut self,
        canister_id: CanisterId,
        response: Response,
    ) -> ExecutionResponse {
        let mut state = self.state.take().unwrap();
        let compute_allocation_used = state.total_compute_allocation();
        let canister = state.take_canister_state(&canister_id).unwrap();
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let mut round_limits = RoundLimits {
            instructions: RoundInstructions::from(i64::MAX),
            subnet_available_memory: self.subnet_available_memory,
            subnet_available_callbacks: self.subnet_available_callbacks,
            compute_allocation_used,
            subnet_memory_reservation: self.subnet_memory_reservation,
        };
        let result = self.exec_env.execute_canister_response(
            canister,
            Arc::new(response),
            self.instruction_limits.clone(),
            UNIX_EPOCH,
            network_topology,
            &mut round_limits,
            self.subnet_size(),
            self.cost_schedule(),
        );
        let (canister, response, instructions_used, heap_delta) = match result {
            ExecuteMessageResult::Finished {
                canister,
                response,
                instructions_used,
                heap_delta,
                call_duration: _,
            } => (canister, response, instructions_used, heap_delta),
            ExecuteMessageResult::Paused { .. } => {
                unreachable!("Unexpected paused execution")
            }
        };
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.subnet_available_callbacks = round_limits.subnet_available_callbacks;

        state.metadata.heap_delta_estimate += heap_delta;
        self.update_execution_stats(
            canister_id,
            self.instruction_limits.message(),
            instructions_used,
        );
        state.put_canister_state(canister);
        self.state = Some(state);
        response
    }

    /// A low-level helper to send subnet messages to the IC management canister.
    /// Execution of the message is started immediately after.
    /// Check the ingress status of the response.
    pub fn subnet_message<S: ToString>(
        &mut self,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let ingress_id = self.subnet_message_raw(method_name, method_payload);
        self.execute_subnet_message();
        check_ingress_status(self.ingress_status(&ingress_id))
    }

    /// A low-level helper to send a subnet messages to the IC management canister.
    pub fn subnet_message_raw<S: ToString>(
        &mut self,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> MessageId {
        let mut state = self.state.take().unwrap();

        let message_id = self.next_message_id();

        match &mut self.registry_settings.provisional_whitelist {
            ProvisionalWhitelist::Set(ids) => {
                ids.insert(self.user_id.get());
            }
            ProvisionalWhitelist::All => {}
        };

        let message = IngressBuilder::new()
            .message_id(message_id.clone())
            .source(self.user_id)
            .receiver(CanisterId::ic_00())
            .method_name(method_name)
            .method_payload(method_payload)
            .build();

        state.subnet_queues_mut().push_ingress(message.clone());

        self.ingress_history_writer.set_status(
            &mut state,
            message.message_id,
            IngressStatus::Known {
                receiver: message.receiver.get(),
                user_id: message.source,
                time: self.time,
                state: IngressState::Received,
            },
        );

        self.state = Some(state);

        message_id
    }

    /// Executes a single subnet message from the subnet input queue.
    /// Return a progress flag indicating if the message was executed or not.
    pub fn execute_subnet_message(&mut self) -> bool {
        let mut state = self.state.take().unwrap();
        let compute_allocation_used = state.total_compute_allocation();
        let message = match state.pop_subnet_input() {
            Some(message) => message,
            None => {
                self.state = Some(state);
                return false;
            }
        };
        let maybe_canister_id = get_canister_id_if_install_code(message.clone());
        let mut round_limits = RoundLimits {
            instructions: RoundInstructions::from(i64::MAX),
            subnet_available_memory: self.subnet_available_memory,
            subnet_available_callbacks: self.subnet_available_callbacks,
            compute_allocation_used,
            subnet_memory_reservation: self.subnet_memory_reservation,
        };

        let (new_state, instructions_used) = self.exec_env.execute_subnet_message(
            message,
            state,
            self.install_code_instruction_limits.clone(),
            &mut mock_random_number_generator(),
            &self.chain_key_data,
            &self.replica_version,
            &self.registry_settings,
            self.current_round,
            &mut round_limits,
        );
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.subnet_available_callbacks = round_limits.subnet_available_callbacks;
        self.state = Some(new_state);
        if let Some(canister_id) = maybe_canister_id
            && let Some(instructions_used) = instructions_used
        {
            self.update_execution_stats(
                canister_id,
                self.install_code_instruction_limits.message(),
                instructions_used,
            );
        }
        true
    }

    /// Inducts and executes all pending messages.
    pub fn execute_all(&mut self) {
        loop {
            self.induct_messages();
            let executed_any = self.execute_messages();
            if !executed_any {
                break;
            }
        }
    }

    // Executes all pending messages.
    // Returns a flag indicating whether any message was executed or not.
    fn execute_messages(&mut self) -> bool {
        let mut executed_any = false;
        while self.execute_subnet_message() {
            executed_any = true;
        }
        let mut state = self.state.take().unwrap();
        let compute_allocation_used = state.total_compute_allocation();
        let mut canisters = state.take_canister_states();
        let canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
        let mut round_limits = RoundLimits {
            instructions: RoundInstructions::from(i64::MAX),
            subnet_available_memory: self.subnet_available_memory,
            subnet_available_callbacks: self.subnet_available_callbacks,
            compute_allocation_used,
            subnet_memory_reservation: self.subnet_memory_reservation,
        };
        for canister_id in canister_ids {
            let network_topology = Arc::new(state.metadata.network_topology.clone());
            let mut canister = canisters.remove(&canister_id).unwrap();
            loop {
                match canister.next_execution() {
                    NextExecution::None | NextExecution::ContinueInstallCode => {
                        break;
                    }
                    NextExecution::StartNew | NextExecution::ContinueLong => {}
                }
                let result = execute_canister(
                    &self.exec_env,
                    canister,
                    self.instruction_limits.clone(),
                    self.instruction_limit_per_query_message,
                    Arc::clone(&network_topology),
                    self.time,
                    &mut round_limits,
                    self.subnet_size(),
                    self.cost_schedule(),
                );
                state.metadata.heap_delta_estimate += result.heap_delta;
                self.subnet_available_memory = round_limits.subnet_available_memory;
                if let Some(instructions_used) = result.instructions_used {
                    self.update_execution_stats(
                        canister_id,
                        self.instruction_limits.message(),
                        instructions_used,
                    );
                }
                canister = result.canister;
                if let Some(ir) = result.ingress_status {
                    self.ingress_history_writer
                        .set_status(&mut state, ir.0, ir.1);
                };
                executed_any = true;
            }
            canisters.insert(canister_id, canister);
        }
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.subnet_available_callbacks = round_limits.subnet_available_callbacks;
        state.put_canister_states(canisters);
        self.state = Some(state);
        executed_any
    }

    /// Executes a pending message of the given canister and bumps state().time().
    pub fn execute_message(&mut self, canister_id: CanisterId) {
        self.execute_slice(canister_id);
        self.state.as_mut().unwrap().metadata.batch_time += std::time::Duration::from_secs(1);
        while self.canister_state(canister_id).next_execution() == NextExecution::ContinueLong
            || self.canister_state(canister_id).next_execution()
                == NextExecution::ContinueInstallCode
        {
            self.execute_slice(canister_id);
            self.state.as_mut().unwrap().metadata.batch_time += std::time::Duration::from_secs(1);
        }
    }

    /// Executes a slice of the given canister.
    pub fn execute_slice(&mut self, canister_id: CanisterId) {
        let mut state = self.state.take().unwrap();
        let compute_allocation_used = state.total_compute_allocation();
        let mut canisters = state.take_canister_states();
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let mut canister = canisters.remove(&canister_id).unwrap();
        match canister.next_execution() {
            NextExecution::None => {
                canisters.insert(canister_id, canister);
                state.put_canister_states(canisters);
            }
            NextExecution::ContinueInstallCode => {
                canisters.insert(canister_id, canister);
                state.put_canister_states(canisters);
                let mut round_limits = RoundLimits {
                    instructions: RoundInstructions::from(i64::MAX),
                    subnet_available_memory: self.subnet_available_memory,
                    subnet_available_callbacks: self.subnet_available_callbacks,
                    compute_allocation_used,
                    subnet_memory_reservation: self.subnet_memory_reservation,
                };
                let (new_state, instructions_used) = self.exec_env.resume_install_code(
                    state,
                    &canister_id,
                    self.install_code_instruction_limits.clone(),
                    &mut round_limits,
                    self.subnet_size(),
                );
                state = new_state;
                self.subnet_available_memory = round_limits.subnet_available_memory;
                self.subnet_available_callbacks = round_limits.subnet_available_callbacks;
                if let Some(instructions_used) = instructions_used {
                    self.update_execution_stats(
                        canister_id,
                        self.install_code_instruction_limits.message(),
                        instructions_used,
                    );
                }
            }
            NextExecution::StartNew | NextExecution::ContinueLong => {
                let mut round_limits = RoundLimits {
                    instructions: RoundInstructions::from(i64::MAX),
                    subnet_available_memory: self.subnet_available_memory,
                    subnet_available_callbacks: self.subnet_available_callbacks,
                    compute_allocation_used,
                    subnet_memory_reservation: self.subnet_memory_reservation,
                };
                let result = execute_canister(
                    &self.exec_env,
                    canister,
                    self.instruction_limits.clone(),
                    self.instruction_limit_per_query_message,
                    Arc::clone(&network_topology),
                    self.time,
                    &mut round_limits,
                    self.subnet_size(),
                    self.cost_schedule(),
                );
                state.metadata.heap_delta_estimate += result.heap_delta;
                self.subnet_available_memory = round_limits.subnet_available_memory;
                self.subnet_available_callbacks = round_limits.subnet_available_callbacks;
                if let Some(instructions_used) = result.instructions_used {
                    self.update_execution_stats(
                        canister_id,
                        self.instruction_limits.message(),
                        instructions_used,
                    );
                }
                canister = result.canister;
                if let Some(ir) = result.ingress_status {
                    self.ingress_history_writer
                        .set_status(&mut state, ir.0, ir.1);
                };
                canisters.insert(canister_id, canister);
                state.put_canister_states(canisters);
            }
        }
        self.state = Some(state);
    }

    /// Aborts all paused executions.
    pub fn abort_all_paused_executions(&mut self) {
        let mut state = self.state.take().unwrap();
        self.exec_env
            .abort_all_paused_executions(&mut state, &self.log);
        self.state = Some(state);
    }

    // Increments the executed instructions and the execution cost counters.
    fn update_execution_stats(
        &mut self,
        canister_id: CanisterId,
        limit: NumInstructions,
        executed: NumInstructions,
    ) {
        let left = limit - executed;
        let mgr = &self.cycles_account_manager;
        *self
            .executed_instructions
            .entry(canister_id)
            .or_insert(NumInstructions::new(0)) += limit - left;

        let is_wasm64_execution = self.canister_wasm_execution_mode(canister_id);

        // Ideally we would simply add `execution_cost(limit - left)`
        // but that leads to small precision errors because 1 Cycle = 0.4 Instructions.
        let fixed_cost = mgr.execution_cost(
            NumInstructions::from(0),
            self.subnet_size(),
            self.cost_schedule(),
            is_wasm64_execution,
        );
        let instruction_cost = mgr.execution_cost(
            limit,
            self.subnet_size(),
            self.cost_schedule(),
            is_wasm64_execution,
        ) - mgr.execution_cost(
            left,
            self.subnet_size(),
            self.cost_schedule(),
            is_wasm64_execution,
        );

        *self
            .execution_cost
            .entry(canister_id)
            .or_insert(Cycles::new(0)) += instruction_cost + fixed_cost;
    }

    /// Inducts messages between canisters and pushes all cross-net messages to
    /// `self.xnet_messages`.
    pub fn induct_messages(&mut self) {
        let mut state = self.state.take().unwrap();
        let mut subnet_available_guaranteed_response_memory = self
            .subnet_available_memory
            .get_guaranteed_response_message_memory();
        let output_messages = get_output_messages(&mut state);
        let mut canisters = state.take_canister_states();
        for (canister_id, message) in output_messages {
            match canisters.get_mut(&canister_id) {
                Some(dest_canister) => {
                    let result = dest_canister.push_input(
                        message.clone(),
                        &mut subnet_available_guaranteed_response_memory,
                        state.metadata.own_subnet_type,
                        InputQueueType::LocalSubnet,
                    );
                    if result.is_err() {
                        self.lost_messages.push(message);
                    }
                }
                None => {
                    if canister_id.get() == state.metadata.own_subnet_id.get() {
                        state
                            .subnet_queues_mut()
                            .push_input(message, InputQueueType::LocalSubnet)
                            .unwrap();
                    } else {
                        self.xnet_messages.push(message);
                    }
                }
            };
        }
        state.put_canister_states(canisters);
        self.state = Some(state);
    }

    /// Injects a call to the IC management canister originating from the
    /// canister specified by `self.caller_canister_id`.
    ///
    /// Note: if you need to call `ic00` from the same subnet, then consider
    /// performing the real call using the universal canister.
    pub fn inject_call_to_ic00<S: ToString>(
        &mut self,
        method_name: S,
        method_payload: Vec<u8>,
        payment: Cycles,
    ) {
        let caller_canister_id = self.caller_canister_id.unwrap();
        self.state_mut()
            .subnet_queues_mut()
            .push_input(
                RequestBuilder::new()
                    .sender(caller_canister_id)
                    .receiver(CanisterId::ic_00())
                    .method_name(method_name)
                    .method_payload(method_payload)
                    .payment(payment)
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
    }

    /// Asks the canister if it is willing to accept the ingress message.
    pub fn should_accept_ingress_message<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<(), UserError> {
        let ingress = SignedIngressBuilder::new()
            .sender(self.user_id())
            .canister_id(canister_id)
            .method_name(method_name)
            .method_payload(method_payload)
            .build();
        self.exec_env.should_accept_ingress_message(
            Arc::new(self.state().clone()),
            &ProvisionalWhitelist::new_empty(),
            &ingress,
            ExecutionMode::NonReplicated,
            &IngressFilterMetrics::new(&MetricsRegistry::new()),
        )
    }

    /// A low-level helper to generate the next message id.
    fn next_message_id(&mut self) -> MessageId {
        let message_id = self.message_id;
        self.message_id += 1;
        MessageId::try_from(&[&[0; 24][..], &message_id.to_be_bytes()[..]].concat()[..]).unwrap()
    }

    /// Executes a query call on the given state.
    ///
    /// Consider to use the simplified `non_replicated_query()` instead.
    pub fn query(
        &self,
        query: Query,
        state: Arc<ReplicatedState>,
        data_certificate: Vec<u8>,
        certificate_delegation_metadata: Option<CertificateDelegationMetadata>,
    ) -> Result<WasmResult, UserError> {
        // We always pass 0 as the height to the query handler, because we don't run consensus
        // in these tests and therefore there isn't any height.
        //
        // Currently, this height is only used for query stats collection and it doesn't matter which one we pass in here.
        // Even if consensus was running, it could be that all queries are actually running at height 0. The state passed in to
        // the query handler shouldn't have the height encoded, so there shouldn't be a mismatch between the two.
        let data_certificate_with_delegation_metadata = DataCertificateWithDelegationMetadata {
            data_certificate,
            certificate_delegation_metadata,
        };
        self.query_handler.query(
            query,
            Labeled::new(Height::from(0), state),
            Some(data_certificate_with_delegation_metadata),
            true,
        )
    }

    /// Returns a reference to the query handler of this test.
    ///
    /// Note that the return type is `Any` so that the caller is forced to
    /// downcast to the concrete type of the query handler and be able to
    /// access private fields in query handler related tests.
    pub fn query_handler(&self) -> &dyn std::any::Any {
        &self.query_handler
    }

    /// Returns a mutable reference to the query handler of this test.
    ///
    /// Note that the return type is `Any` so that the caller is forced to
    /// downcast to the concrete type of the query handler and be able to
    /// access private fields in query handler related tests.
    pub fn query_handler_mut(&mut self) -> &mut dyn std::any::Any {
        &mut self.query_handler
    }

    pub fn checkpoint_canister_memories(&mut self) {
        let fd_factory = Arc::new(TestPageAllocatorFileDescriptorImpl::new());
        let mut new_checkpoint_files = vec![];
        for canister_state in self.state_mut().canisters_iter_mut() {
            let es = match canister_state.execution_state.as_mut() {
                Some(es) => es,
                None => break,
            };

            // Handle heap memory
            let mut checkpoint_file = NamedTempFile::new().unwrap();
            let path = checkpoint_file.path().to_owned();
            let num_pages = es.wasm_memory.size.get() * 16;
            for i in 0..num_pages {
                let contents = es.wasm_memory.page_map.get_page(PageIndex::from(i as u64));
                checkpoint_file
                    .as_file_mut()
                    .write_at(contents, (i * PAGE_SIZE) as u64)
                    .unwrap();
            }
            let factory = Arc::clone(&fd_factory);
            es.wasm_memory.page_map = PageMap::open(
                Box::new(base_only_storage_layout(path)),
                Height::new(0),
                factory,
            )
            .unwrap();
            *es.wasm_memory.sandbox_memory.lock().unwrap() = SandboxMemory::Unsynced;
            new_checkpoint_files.push(checkpoint_file);

            // Handle stable memory
            let mut checkpoint_file = NamedTempFile::new().unwrap();
            let path = checkpoint_file.path().to_owned();
            let num_pages = es.stable_memory.size.get() * 16;
            for i in 0..num_pages {
                let contents = es
                    .stable_memory
                    .page_map
                    .get_page(PageIndex::from(i as u64));
                checkpoint_file
                    .as_file_mut()
                    .write_at(contents, (i * PAGE_SIZE) as u64)
                    .unwrap();
            }
            let factory = Arc::clone(&fd_factory);
            es.stable_memory.page_map = PageMap::open(
                Box::new(base_only_storage_layout(path)),
                Height::new(0),
                factory,
            )
            .unwrap();
            *es.stable_memory.sandbox_memory.lock().unwrap() = SandboxMemory::Unsynced;
            new_checkpoint_files.push(checkpoint_file);
        }
        self.checkpoint_files.extend(new_checkpoint_files);
    }

    pub fn query_stats_for_testing(&self, canister_id: &CanisterId) -> Option<QueryStats> {
        self.query_handler.query_stats_for_testing(canister_id)
    }

    pub fn query_stats_set_epoch_for_testing(&mut self, epoch: QueryStatsEpoch) {
        self.query_handler.query_stats_set_epoch_for_testing(epoch);
    }

    pub fn get_own_subnet_id(&self) -> SubnetId {
        self.cycles_account_manager.get_subnet_id()
    }

    pub fn subnet_memory_saturation(&self) -> ResourceSaturation {
        self.exec_env
            .subnet_memory_saturation(&self.subnet_available_memory)
    }

    pub fn expected_storage_reservation_cycles(
        &self,
        subnet_memory_saturation: &ResourceSaturation,
        allocated_bytes: NumBytes,
    ) -> Cycles {
        self.cycles_account_manager.storage_reservation_cycles(
            allocated_bytes,
            subnet_memory_saturation,
            self.subnet_size(),
            self.cost_schedule(),
        )
    }

    pub fn prepayment_for_response_execution(&self, mode: WasmExecutionMode) -> Cycles {
        self.cycles_account_manager
            .prepayment_for_response_execution(self.subnet_size(), self.cost_schedule(), mode)
    }

    pub fn refund_for_response_transmission(&self, response: &ResponsePayload) -> Cycles {
        let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
        let prepayment_for_response_transmission = self
            .cycles_account_manager
            .prepayment_for_response_transmission(self.subnet_size(), self.cost_schedule());
        self.cycles_account_manager
            .refund_for_response_transmission(
                &no_op_logger(),
                &no_op_counter,
                response,
                prepayment_for_response_transmission,
                self.subnet_size(),
                self.cost_schedule(),
            )
    }

    pub fn consume_cycles(&mut self, canister_id: CanisterId, cycles: Cycles) {
        let cost_schedule = self.cost_schedule();
        let cycles_account_manager = self.cycles_account_manager.clone();
        let system_state = &mut self.canister_state_mut(canister_id).system_state;
        cycles_account_manager
            .consume_with_threshold(
                system_state,
                cycles,
                Cycles::zero(),
                CyclesUseCase::Memory,
                false,
                cost_schedule,
            )
            .unwrap();
    }

    pub fn online_split_state(&mut self, subnet_id: SubnetId, other_subnet_id: SubnetId) {
        let state = self.state.take().unwrap();

        // Reset the split marker, just in case.
        // state.metadata.subnet_split_from = None;

        let state_after_split = state.online_split(subnet_id, other_subnet_id).unwrap();
        self.state = Some(state_after_split);
    }
}

/// A builder for `ExecutionTest`.
///
/// Invariant: `subnet_config` must match the `subnet_type`. If `subnet_type` is
/// updated, then `subnet_config` must be updated accordingly.
pub struct ExecutionTestBuilder {
    execution_config: Config,
    subnet_config: SubnetConfig,
    nns_subnet_id: SubnetId,
    root_key: Option<Vec<u8>>,
    own_subnet_id: SubnetId,
    caller_subnet_id: Option<SubnetId>,
    subnet_type: SubnetType,
    log: ReplicaLogger,
    caller_canister_id: Option<CanisterId>,
    ecdsa_signature_fee: Option<Cycles>,
    schnorr_signature_fee: Option<Cycles>,
    chain_keys_enabled_status: BTreeMap<MasterPublicKeyId, bool>,
    initial_canister_cycles: Cycles,
    registry_settings: RegistryExecutionSettings,
    manual_execution: bool,
    subnet_features: String,
    bitcoin_get_successors_follow_up_responses: BTreeMap<CanisterId, Vec<Vec<u8>>>,
    time: Time,
    current_round: ExecutionRound,
    replica_version: ReplicaVersion,
    precompiled_universal_canister: bool,
    cost_schedule: CanisterCyclesCostSchedule,
}

impl Default for ExecutionTestBuilder {
    fn default() -> Self {
        let subnet_type = SubnetType::Application;
        let mut subnet_config = SubnetConfig::new(subnet_type);
        subnet_config.scheduler_config.scheduler_cores = 2;
        Self {
            execution_config: Config {
                rate_limiting_of_instructions: FlagStatus::Disabled,
                canister_sandboxing_flag: FlagStatus::Enabled,
                composite_queries: FlagStatus::Enabled,
                ..Config::default()
            },
            subnet_config,
            nns_subnet_id: subnet_test_id(2),
            root_key: None,
            own_subnet_id: subnet_test_id(1),
            caller_subnet_id: None,
            subnet_type,
            log: no_op_logger(),
            caller_canister_id: None,
            ecdsa_signature_fee: None,
            schnorr_signature_fee: None,
            chain_keys_enabled_status: Default::default(),
            initial_canister_cycles: INITIAL_CANISTER_CYCLES,
            registry_settings: test_registry_settings(),
            manual_execution: false,
            subnet_features: String::default(),
            bitcoin_get_successors_follow_up_responses: BTreeMap::default(),
            time: UNIX_EPOCH,
            current_round: ExecutionRound::new(1),
            replica_version: ReplicaVersion::default(),
            precompiled_universal_canister: true,
            cost_schedule: CanisterCyclesCostSchedule::Normal,
        }
    }
}

impl ExecutionTestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cost_schedule(self, cost_schedule: CanisterCyclesCostSchedule) -> Self {
        Self {
            cost_schedule,
            ..self
        }
    }

    pub fn with_execution_config(self, execution_config: Config) -> Self {
        Self {
            execution_config,
            ..self
        }
    }

    pub fn with_nns_subnet_id(self, nns_subnet_id: SubnetId) -> Self {
        Self {
            nns_subnet_id,
            ..self
        }
    }

    pub fn with_root_key(self, root_key: Vec<u8>) -> Self {
        Self {
            root_key: Some(root_key),
            ..self
        }
    }
    pub fn with_own_subnet_id(self, own_subnet_id: SubnetId) -> Self {
        Self {
            own_subnet_id,
            ..self
        }
    }

    /// Ensures that the routing table is set up properly to allow inject a fake
    /// call from the given subnet/canister. See `inject_call_to_ic00()`.
    pub fn with_caller(self, subnet_id: SubnetId, canister_id: CanisterId) -> Self {
        Self {
            caller_subnet_id: Some(subnet_id),
            caller_canister_id: Some(canister_id),
            ..self
        }
    }

    pub fn with_subnet_type(mut self, subnet_type: SubnetType) -> Self {
        self.subnet_type = subnet_type;
        // If `subnet_type` is updated, then we need to update the subnet config
        // to match it.
        self.subnet_config = SubnetConfig::new(subnet_type);
        self
    }

    pub fn with_subnet_id(self, principal_id: PrincipalId) -> Self {
        Self {
            own_subnet_id: SubnetId::new(principal_id),
            ..self
        }
    }

    pub fn with_max_query_call_graph_instructions(
        mut self,
        max_query_call_graph_instructions: NumInstructions,
    ) -> Self {
        self.execution_config.max_query_call_graph_instructions = max_query_call_graph_instructions;
        self
    }

    pub fn with_log(self, log: ReplicaLogger) -> Self {
        Self { log, ..self }
    }

    pub fn with_ecdsa_signature_fee(self, ecdsa_signing_fee: u128) -> Self {
        Self {
            ecdsa_signature_fee: Some(Cycles::new(ecdsa_signing_fee)),
            ..self
        }
    }

    pub fn with_schnorr_signature_fee(self, schnorr_signature_fee: u128) -> Self {
        Self {
            schnorr_signature_fee: Some(Cycles::new(schnorr_signature_fee)),
            ..self
        }
    }

    pub fn with_chain_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.chain_keys_enabled_status.insert(key_id, true);
        self
    }

    pub fn with_disabled_chain_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.chain_keys_enabled_status.insert(key_id, false);
        self
    }

    pub fn with_instruction_limit(mut self, limit: u64) -> Self {
        self.subnet_config
            .scheduler_config
            .max_instructions_per_message = NumInstructions::from(limit);
        self
    }

    pub fn with_slice_instruction_limit(mut self, limit: u64) -> Self {
        self.subnet_config
            .scheduler_config
            .max_instructions_per_slice = NumInstructions::from(limit);
        self
    }

    pub fn with_instruction_limit_per_query_message(mut self, limit: u64) -> Self {
        self.subnet_config
            .scheduler_config
            .max_instructions_per_query_message = NumInstructions::from(limit);
        self
    }

    pub fn with_install_code_instruction_limit(mut self, limit: u64) -> Self {
        self.subnet_config
            .scheduler_config
            .max_instructions_per_install_code = NumInstructions::from(limit);
        self
    }

    pub fn with_install_code_slice_instruction_limit(mut self, limit: u64) -> Self {
        self.subnet_config
            .scheduler_config
            .max_instructions_per_install_code_slice = NumInstructions::from(limit);
        self
    }

    pub fn with_initial_canister_cycles(self, initial_canister_cycles: u128) -> Self {
        Self {
            initial_canister_cycles: Cycles::new(initial_canister_cycles),
            ..self
        }
    }

    pub fn with_subnet_execution_memory(mut self, subnet_execution_memory: u64) -> Self {
        self.execution_config.subnet_memory_capacity = NumBytes::from(subnet_execution_memory);
        self
    }

    pub fn with_subnet_memory_reservation(mut self, subnet_memory_reservation: u64) -> Self {
        self.execution_config.subnet_memory_reservation = NumBytes::from(subnet_memory_reservation);
        self
    }

    pub fn with_subnet_memory_threshold(mut self, subnet_memory_threshold: u64) -> Self {
        self.execution_config.subnet_memory_threshold = NumBytes::from(subnet_memory_threshold);
        self
    }

    pub fn with_subnet_guaranteed_response_message_memory(
        mut self,
        subnet_guaranteed_response_message_memory: u64,
    ) -> Self {
        self.execution_config
            .guaranteed_response_message_memory_capacity =
            NumBytes::from(subnet_guaranteed_response_message_memory);
        self
    }

    pub fn with_subnet_wasm_custom_sections_memory(
        mut self,
        subnet_wasm_custom_sections_memory: u64,
    ) -> Self {
        self.execution_config
            .subnet_wasm_custom_sections_memory_capacity =
            NumBytes::from(subnet_wasm_custom_sections_memory);
        self
    }

    pub fn with_canister_callback_quota(mut self, canister_callback_quota: usize) -> Self {
        self.execution_config.canister_guaranteed_callback_quota = canister_callback_quota;
        self
    }

    pub fn with_subnet_features(self, subnet_features: &str) -> Self {
        Self {
            subnet_features: String::from(subnet_features),
            ..self
        }
    }

    pub fn with_max_number_of_canisters(self, max_number_of_canisters: u64) -> Self {
        Self {
            registry_settings: RegistryExecutionSettings {
                max_number_of_canisters,
                ..self.registry_settings
            },
            ..self
        }
    }

    pub fn with_manual_execution(self) -> Self {
        Self {
            manual_execution: true,
            ..self
        }
    }

    pub fn with_rate_limiting_of_instructions(mut self) -> Self {
        self.execution_config.rate_limiting_of_instructions = FlagStatus::Enabled;
        self
    }

    pub fn with_canister_sandboxing_disabled(mut self) -> Self {
        self.execution_config.canister_sandboxing_flag = FlagStatus::Disabled;
        self
    }

    pub fn without_composite_queries(mut self) -> Self {
        self.execution_config.composite_queries = FlagStatus::Disabled;
        self
    }

    pub fn with_query_caching_disabled(mut self) -> Self {
        self.execution_config.query_caching = FlagStatus::Disabled;
        self
    }

    pub fn with_query_cache_capacity(mut self, capacity_bytes: u64) -> Self {
        self.execution_config.query_cache_capacity = capacity_bytes.into();
        self
    }

    pub fn with_query_cache_max_expiry_time(mut self, max_expiry_time: Duration) -> Self {
        self.execution_config.query_cache_max_expiry_time = max_expiry_time;
        self
    }

    pub fn with_query_cache_data_certificate_expiry_time(mut self, time: Duration) -> Self {
        self.execution_config
            .query_cache_data_certificate_expiry_time = time;
        self
    }

    pub fn with_query_stats(mut self) -> Self {
        self.execution_config.query_stats_aggregation = FlagStatus::Enabled;
        self
    }

    pub fn with_allocatable_compute_capacity_in_percent(
        mut self,
        allocatable_compute_capacity_in_percent: usize,
    ) -> Self {
        self.execution_config
            .allocatable_compute_capacity_in_percent = allocatable_compute_capacity_in_percent;
        self
    }

    pub fn with_provisional_whitelist_all(mut self) -> Self {
        self.registry_settings.provisional_whitelist = ProvisionalWhitelist::All;
        self
    }

    pub fn with_bitcoin_testnet_canister_id(mut self, canister: Option<CanisterId>) -> Self {
        self.execution_config.bitcoin.testnet_canister_id = canister;
        self
    }

    pub fn with_bitcoin_mainnet_canister_id(mut self, canister: Option<CanisterId>) -> Self {
        self.execution_config.bitcoin.mainnet_canister_id = canister;
        self
    }

    pub fn with_bitcoin_privileged_access(mut self, canister: CanisterId) -> Self {
        self.execution_config
            .bitcoin
            .privileged_access
            .push(canister);
        self
    }

    pub fn with_bitcoin_follow_up_responses(
        mut self,
        canister: CanisterId,
        follow_up_responses: Vec<Vec<u8>>,
    ) -> Self {
        self.bitcoin_get_successors_follow_up_responses
            .insert(canister, follow_up_responses);
        self
    }

    pub fn with_cost_to_compile_wasm_instruction(mut self, cost: u64) -> Self {
        self.execution_config
            .embedders_config
            .cost_to_compile_wasm_instruction = cost.into();
        self
    }

    pub fn build_with_routing_table_for_specified_ids(self) -> ExecutionTest {
        let routing_table =
            get_routing_table_with_specified_ids_allocation_range(self.own_subnet_id).unwrap();
        self.build_common(Arc::new(routing_table))
    }

    pub fn with_stable_memory_dirty_page_limit(
        mut self,
        stable_memory_dirty_page_limit: StableMemoryPageLimit,
    ) -> Self {
        self.execution_config
            .embedders_config
            .stable_memory_dirty_page_limit = stable_memory_dirty_page_limit;

        self
    }

    pub fn with_stable_memory_access_limit(
        mut self,
        stable_memory_access_limit: StableMemoryPageLimit,
    ) -> Self {
        self.execution_config
            .embedders_config
            .stable_memory_accessed_page_limit = stable_memory_access_limit;

        self
    }

    pub fn with_max_canister_http_requests_in_flight(
        mut self,
        max_canister_http_requests_in_flight: usize,
    ) -> Self {
        self.execution_config.max_canister_http_requests_in_flight =
            max_canister_http_requests_in_flight;
        self
    }

    pub fn with_max_wasm_memory_size(mut self, wasm_memory_size: NumBytes) -> Self {
        self.execution_config.embedders_config.max_wasm_memory_size = wasm_memory_size;
        self
    }

    pub fn with_max_wasm64_memory_size(mut self, wasm_memory_size: NumBytes) -> Self {
        self.execution_config
            .embedders_config
            .max_wasm64_memory_size = wasm_memory_size;
        self
    }

    pub fn with_metering_type(mut self, metering_type: MeteringType) -> Self {
        self.execution_config.embedders_config.metering_type = metering_type;
        self
    }

    pub fn with_time(mut self, time: Time) -> Self {
        self.time = time;
        self
    }

    pub fn with_resource_saturation_scaling(mut self, scaling: usize) -> Self {
        self.subnet_config.scheduler_config.scheduler_cores = scaling;
        // If scaling == 1, i.e. a single core is requested in the test, DTS must
        // be disabled by setting the slice limit to be equal to the message limit.
        if scaling == 1 {
            self.subnet_config
                .scheduler_config
                .max_instructions_per_slice = self
                .subnet_config
                .scheduler_config
                .max_instructions_per_message;
            self.subnet_config
                .scheduler_config
                .max_instructions_per_install_code_slice = self
                .subnet_config
                .scheduler_config
                .max_instructions_per_install_code;
        }
        self
    }

    pub fn with_heap_delta_rate_limit(mut self, heap_delta_rate_limit: NumBytes) -> Self {
        self.subnet_config.scheduler_config.heap_delta_rate_limit = heap_delta_rate_limit;
        self
    }

    pub fn with_max_dirty_pages_optimization_embedder_config(mut self, no_pages: usize) -> Self {
        self.execution_config
            .embedders_config
            .max_dirty_pages_without_optimization = no_pages;
        self
    }

    pub fn with_replica_version(mut self, replica_version: ReplicaVersion) -> Self {
        self.replica_version = replica_version;
        self
    }

    pub fn with_precompiled_universal_canister(
        mut self,
        precompiled_universal_canister: bool,
    ) -> Self {
        self.precompiled_universal_canister = precompiled_universal_canister;
        self
    }

    pub fn with_max_snapshots_per_canister(mut self, max_snapshots_per_canister: usize) -> Self {
        self.execution_config.max_number_of_snapshots_per_canister = max_snapshots_per_canister;
        self
    }

    pub fn with_snapshot_metadata_download(mut self) -> Self {
        self.execution_config.canister_snapshot_download = FlagStatus::Enabled;
        self
    }

    pub fn with_snapshot_metadata_upload(mut self) -> Self {
        self.execution_config.canister_snapshot_upload = FlagStatus::Enabled;
        self
    }

    pub fn with_environment_variables_flag(
        mut self,
        environment_variables_flag: FlagStatus,
    ) -> Self {
        self.execution_config.environment_variables = environment_variables_flag;
        self
    }

    pub fn build(self) -> ExecutionTest {
        let own_range = CanisterIdRange {
            start: CanisterId::from(CANISTER_IDS_PER_SUBNET),
            end: CanisterId::from(2 * CANISTER_IDS_PER_SUBNET - 1),
        };

        let routing_table = Arc::new(match self.caller_canister_id {
            None => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0), end: CanisterId::from(CANISTER_IDS_PER_SUBNET - 1) } => self.own_subnet_id,
            }).unwrap(),
            Some(caller_canister) => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: caller_canister, end: caller_canister } => self.caller_subnet_id.unwrap(),
                own_range => self.own_subnet_id,
            }).unwrap_or_else(|_| panic!("Unable to create routing table - sender canister {caller_canister} is in the range {own_range:?}")),
        });

        self.build_common(routing_table)
    }

    fn build_common(mut self, routing_table: Arc<RoutingTable>) -> ExecutionTest {
        let mut state = ReplicatedState::new(self.own_subnet_id, self.subnet_type);

        let mut subnets = vec![self.own_subnet_id, self.nns_subnet_id];
        subnets.extend(self.caller_subnet_id.iter().copied());
        state.metadata.network_topology.subnets = generate_subnets(
            subnets,
            self.nns_subnet_id,
            self.root_key,
            self.own_subnet_id,
            self.subnet_type,
            self.registry_settings.subnet_size,
        );
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = self.nns_subnet_id;
        state.metadata.init_allocation_ranges_if_empty().unwrap();
        state.metadata.bitcoin_get_successors_follow_up_responses =
            self.bitcoin_get_successors_follow_up_responses;

        // On a single core scheduler, DTS must be disabled.
        if self.subnet_config.scheduler_config.scheduler_cores == 1 {
            assert_eq!(
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_message,
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_slice,
                "On a single core scheduler, DTS must be disabled by setting max_instructions_per_message == max_instructions_per_slice"
            );
            assert_eq!(
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_install_code,
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_install_code_slice,
                "On a single core scheduler, DTS must be disabled by setting max_instructions_per_install_code == max_instructions_per_install_code_slice"
            );
        }

        if self.subnet_features.is_empty() {
            state.metadata.own_subnet_features = SubnetFeatures::default();
        } else {
            state.metadata.own_subnet_features =
                SubnetFeatures::from_str(&self.subnet_features).unwrap();
        }

        let metrics_registry = MetricsRegistry::new();

        if let Some(ecdsa_signature_fee) = self.ecdsa_signature_fee {
            self.subnet_config
                .cycles_account_manager_config
                .ecdsa_signature_fee = ecdsa_signature_fee;
        }
        if let Some(schnorr_signature_fee) = self.schnorr_signature_fee {
            self.subnet_config
                .cycles_account_manager_config
                .schnorr_signature_fee = schnorr_signature_fee;
        }
        for (key_id, is_enabled) in &self.chain_keys_enabled_status {
            // Populate the chain key settings
            self.registry_settings.chain_key_settings.insert(
                key_id.clone(),
                ChainKeySettings {
                    max_queue_size: 20,
                    pre_signatures_to_create_in_advance: 5,
                },
            );

            if *is_enabled {
                state
                    .metadata
                    .network_topology
                    .chain_key_enabled_subnets
                    .insert(key_id.clone(), vec![self.own_subnet_id]);
            }
            state
                .metadata
                .network_topology
                .subnets
                .get_mut(&self.own_subnet_id)
                .unwrap()
                .chain_keys_held
                .insert(key_id.clone());
        }

        state.metadata.network_topology.bitcoin_mainnet_canister_id =
            self.execution_config.bitcoin.mainnet_canister_id;

        state.metadata.network_topology.bitcoin_testnet_canister_id =
            self.execution_config.bitcoin.testnet_canister_id;

        let chain_key_subnet_public_keys = self
            .chain_keys_enabled_status
            .into_keys()
            .map(|key_id| match key_id {
                MasterPublicKeyId::Ecdsa(_) => (
                    key_id,
                    MasterPublicKey {
                        algorithm_id: AlgorithmId::EcdsaSecp256k1,
                        public_key: ECDSA_PUB_KEY.to_vec(),
                    },
                ),
                MasterPublicKeyId::Schnorr(ref schnorr) => match schnorr.algorithm {
                    SchnorrAlgorithm::Bip340Secp256k1 => (
                        key_id,
                        MasterPublicKey {
                            algorithm_id: AlgorithmId::SchnorrSecp256k1,
                            public_key: SCHNORR_BIP340_PUB_KEY.to_vec(),
                        },
                    ),
                    SchnorrAlgorithm::Ed25519 => (
                        key_id,
                        MasterPublicKey {
                            algorithm_id: AlgorithmId::Ed25519,
                            public_key: SCHNORR_ED29915_PUB_KEY.to_vec(),
                        },
                    ),
                },
                MasterPublicKeyId::VetKd(_) => (
                    key_id,
                    MasterPublicKey {
                        algorithm_id: AlgorithmId::VetKD,
                        public_key: VETKD_PUB_KEY.to_vec(),
                    },
                ),
            })
            .collect::<BTreeMap<_, _>>();

        let nidkg_ids = chain_key_subnet_public_keys
            .keys()
            .flat_map(|key_id| {
                if let MasterPublicKeyId::VetKd(vetkd_key_id) = key_id {
                    let nidkg_id = NiDkgId {
                        start_block_height: Height::new(0),
                        dealer_subnet: self.own_subnet_id,
                        dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(
                            vetkd_key_id.clone(),
                        )),
                        target_subnet: NiDkgTargetSubnet::Local,
                    };
                    Some((
                        NiDkgMasterPublicKeyId::VetKd(vetkd_key_id.clone()),
                        nidkg_id,
                    ))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<_, _>>();

        let dirty_page_overhead = match self.subnet_type {
            SubnetType::Application => SchedulerConfig::application_subnet().dirty_page_overhead,
            SubnetType::System => SchedulerConfig::system_subnet().dirty_page_overhead,
            SubnetType::VerifiedApplication => {
                SchedulerConfig::verified_application_subnet().dirty_page_overhead
            }
        };

        let dirty_heap_page_overhead = match self.execution_config.embedders_config.metering_type {
            MeteringType::New => dirty_page_overhead.get(),
            _ => 0,
        };

        let (completed_execution_messages_tx, _) = tokio::sync::mpsc::channel(1);
        let state_manager = Arc::new(FakeStateManager::new());

        let execution_services = ExecutionServicesForTesting::setup_execution(
            self.log.clone(),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            self.execution_config.clone(),
            self.subnet_config.clone(),
            state_manager.clone(),
            state_manager.get_fd_factory(),
            completed_execution_messages_tx,
            state_manager.tmp(),
            None,
        );

        if self.precompiled_universal_canister {
            execution_services
                .execution_environment
                .compilation_cache_insert_for_testing(
                    UNIVERSAL_CANISTER_WASM.to_vec(),
                    bincode::deserialize(&UNIVERSAL_CANISTER_SERIALIZED_MODULE)
                        .expect("Failed to deserialize universal canister module"),
                )
        }

        state.set_own_cost_schedule(self.cost_schedule);
        self.registry_settings.canister_cycles_cost_schedule = self.cost_schedule;
        let subnet_available_memory = execution_services
            .execution_environment
            .scaled_subnet_available_memory(&state);
        let subnet_memory_reservation = execution_services
            .execution_environment
            .scaled_subnet_memory_reservation();
        ExecutionTest {
            state: Some(state),
            message_id: 0,
            executed_instructions: HashMap::new(),
            execution_cost: HashMap::new(),
            xnet_messages: vec![],
            lost_messages: vec![],
            subnet_available_memory,
            subnet_memory_reservation,
            subnet_available_callbacks: self.execution_config.subnet_callback_soft_limit as i64,
            time: self.time,
            dirty_heap_page_overhead,
            instruction_limits: InstructionLimits::new(
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_message,
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_slice,
            ),
            install_code_instruction_limits: InstructionLimits::new(
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_install_code,
                self.subnet_config
                    .scheduler_config
                    .max_instructions_per_install_code_slice,
            ),
            ingress_memory_capacity: self.execution_config.ingress_history_memory_capacity,
            instruction_limit_per_query_message: self
                .subnet_config
                .scheduler_config
                .max_instructions_per_query_message,
            initial_canister_cycles: self.initial_canister_cycles,
            registry_settings: self.registry_settings,
            user_id: user_test_id(1),
            caller_canister_id: self.caller_canister_id,
            exec_env: execution_services.execution_environment,
            query_handler: execution_services.query_execution_service,
            cycles_account_manager: execution_services.cycles_account_manager,
            metrics_registry,
            ingress_history_writer: execution_services.ingress_history_writer,
            manual_execution: self.manual_execution,
            chain_key_data: ChainKeyData {
                master_public_keys: chain_key_subnet_public_keys,
                nidkg_ids,
                ..Default::default()
            },
            current_round: self.current_round,
            log: self.log,
            checkpoint_files: vec![],
            replica_version: self.replica_version,
            canister_snapshot_baseline_instructions: self
                .subnet_config
                .scheduler_config
                .canister_snapshot_baseline_instructions,
        }
    }
}

/// Extracts the reply data from a successful Wasm execution result.
/// Panics if the result is a reject or an error.
pub fn get_reply(result: Result<WasmResult, UserError>) -> Vec<u8> {
    match result {
        Ok(WasmResult::Reply(data)) => data,
        Ok(WasmResult::Reject(msg)) => unreachable!("Expected reply, got reject: {}", msg),
        Err(err) => unreachable!("Expected reply, got error: {:?}", err),
    }
}

/// Extracts the reject message from a failed Wasm execution result.
/// Panics if the result is a successful reply or an error.
pub fn get_reject(result: Result<WasmResult, UserError>) -> String {
    match result {
        Ok(WasmResult::Reject(msg)) => msg,
        Ok(WasmResult::Reply(data)) => unreachable!("Expected reject, got reply: {:?}", data),
        Err(err) => unreachable!("Expected reject, got error: {:?}", err),
    }
}

/// Expects that the canister did not reply (i.e., `CanisterDidNotReply` error).
/// Panics if the result is not an error with that specific code.
pub fn expect_canister_did_not_reply(result: Result<WasmResult, UserError>) {
    match result {
        Err(err) if err.code() == ErrorCode::CanisterDidNotReply => {}
        _ => unreachable!("Expected CanisterDidNotReply error, got {:?}", result),
    }
}

/// Checks that the ingress status corresponds to a completed outcome and
/// extracts it.
pub fn check_ingress_status(ingress_status: IngressStatus) -> Result<WasmResult, UserError> {
    match ingress_status {
        IngressStatus::Unknown
        | IngressStatus::Known {
            state: IngressState::Received,
            ..
        }
        | IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
        | IngressStatus::Known {
            state: IngressState::Done,
            ..
        } => unreachable!("Unexpected ingress status: {:?}", ingress_status),
        IngressStatus::Known {
            state: IngressState::Completed(result),
            ..
        } => Ok(result),
        IngressStatus::Known {
            state: IngressState::Failed(error),
            ..
        } => Err(error),
    }
}

pub fn get_output_messages(state: &mut ReplicatedState) -> Vec<(CanisterId, RequestOrResponse)> {
    let mut output: Vec<(CanisterId, RequestOrResponse)> = vec![];
    let output_iter = state.output_into_iter();

    for msg in output_iter {
        output.push((msg.receiver(), msg));
    }
    output
}

fn get_canister_id_if_install_code(message: CanisterMessage) -> Option<CanisterId> {
    let message = match message {
        CanisterMessage::Response(_) => return None,
        CanisterMessage::Request(request) => CanisterCall::Request(request),
        CanisterMessage::Ingress(ingress) => CanisterCall::Ingress(ingress),
    };
    if message.method_name() != "install_code" {
        return None;
    }
    match InstallCodeArgsV2::decode(message.method_payload()) {
        Err(_) => None,
        Ok(args) => Some(CanisterId::try_from(args.canister_id).unwrap()),
    }
}

pub fn wat_compilation_cost(wat: &str) -> NumInstructions {
    let wasm = BinaryEncodedWasm::new(wat::parse_str(wat).unwrap());
    let config = EmbeddersConfig::default();
    let (_, serialized_module) = compile(&WasmtimeEmbedder::new(config, no_op_logger()), &wasm)
        .1
        .unwrap();
    serialized_module.compilation_cost
}

pub fn wasm_compilation_cost(wasm: &[u8]) -> NumInstructions {
    let wasm = decode_wasm(WASM_MAX_SIZE, Arc::new(wasm.to_vec())).unwrap();
    let config = EmbeddersConfig::default();
    let (_, serialized_module) = compile(&WasmtimeEmbedder::new(config, no_op_logger()), &wasm)
        .1
        .unwrap();
    serialized_module.compilation_cost
}

// This function copies the behavior of the actual logging cost computation in
// rs/embedders/src/wasmtime_embedder/linker.rs.
fn logging_charge_bytes(message_num_bytes: usize) -> usize {
    const TEST_DEFAULT_LOG_MEMORY_LIMIT: usize = 4 * 1024;
    const TEST_BYTE_TRANSMISSION_COST_FACTOR: usize = 50;
    let capacity = TEST_DEFAULT_LOG_MEMORY_LIMIT;
    let remaining_space = capacity;
    let allocated_num_bytes = message_num_bytes.min(capacity);
    let transmitted_num_bytes = message_num_bytes.min(remaining_space);
    2 * allocated_num_bytes + TEST_BYTE_TRANSMISSION_COST_FACTOR * transmitted_num_bytes
}

/// Helper function to compute the cost of logging during `debug_print` and `trap`.
pub fn bytes_and_logging_cost(num_bytes: usize) -> usize {
    num_bytes + logging_charge_bytes(num_bytes)
}

/// Create a routing table with an allocation range for the creation of canisters with specified Canister IDs.
/// /// It is only used for tests for ProvisionalCreateCanisterWithCycles when specified ID is provided.
pub fn get_routing_table_with_specified_ids_allocation_range(
    subnet_id: SubnetId,
) -> Result<RoutingTable, WellFormedError> {
    let specified_ids_range_start: u64 = 0;
    let specified_ids_range_end: u64 = u64::MAX / 2;

    let specified_ids_range = CanisterIdRange {
        start: CanisterId::from(specified_ids_range_start),
        end: CanisterId::from(specified_ids_range_end),
    };

    let subnets_allocation_range_start =
        ((specified_ids_range_end / CANISTER_IDS_PER_SUBNET) + 2) * CANISTER_IDS_PER_SUBNET;
    let subnets_allocation_range_end = subnets_allocation_range_start + CANISTER_IDS_PER_SUBNET - 1;

    let subnets_allocation_range = CanisterIdRange {
        start: CanisterId::from(subnets_allocation_range_start),
        end: CanisterId::from(subnets_allocation_range_end),
    };
    let mut routing_table = RoutingTable::default();
    routing_table.insert(specified_ids_range, subnet_id)?;
    routing_table.insert(subnets_allocation_range, subnet_id)?;
    Ok(routing_table)
}

/// Due to the `scale(cost) != scale(prepay) - scale(prepay - cost)`,
/// we can't always compare the Cycles precisely.
#[macro_export]
macro_rules! assert_delta {
    ($x:expr_2021, $y:expr_2021, $d:expr_2021) => {
        // As Cycles use saturating sub, we can't just subtract $x from $y
        if !($x >= $y && $x - $y <= $d) && !($x < $y && $y - $x <= $d) {
            assert_eq!($x, $y, "delta: `{:?}`", $d);
        }
    };
}

fn mock_random_number_generator() -> Box<ReproducibleRng> {
    Box::new(ReproducibleRng::from_seed_for_debugging([0u8; 32]))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn assert_delta() {
        assert_delta!(Cycles::new(10), Cycles::new(10), Cycles::new(0));
        assert_delta!(Cycles::new(0), Cycles::new(0), Cycles::new(0));
        assert_delta!(Cycles::new(0), Cycles::new(0), Cycles::new(10));

        assert_delta!(Cycles::new(0), Cycles::new(10), Cycles::new(10));
        assert_delta!(Cycles::new(10), Cycles::new(0), Cycles::new(10));
    }

    #[test]
    #[should_panic]
    fn assert_delta_panics_x_lt_y() {
        assert_delta!(Cycles::new(0), Cycles::new(10), Cycles::new(9));
    }

    #[test]
    #[should_panic]
    fn assert_delta_panics_x_gt_y() {
        assert_delta!(Cycles::new(10), Cycles::new(0), Cycles::new(9));
    }
}
