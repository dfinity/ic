use ic_base_types::{NumBytes, NumSeconds, PrincipalId, SubnetId};
use ic_config::embedders::{MeteringType, StableMemoryPageLimit};
use ic_config::{
    embedders::{Config as EmbeddersConfig, WASM_MAX_SIZE},
    execution_environment::Config,
    flag_status::FlagStatus,
    subnet_config::SchedulerConfig,
    subnet_config::SubnetConfig,
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::{
    wasm_utils::{compile, decoding::decode_wasm},
    WasmtimeEmbedder,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
pub use ic_execution_environment::ExecutionResponse;
use ic_execution_environment::{
    execute_canister, CompilationCostHandling, ExecuteMessageResult, ExecutionEnvironment,
    Hypervisor, IngressFilterMetrics, IngressHistoryWriterImpl, InternalHttpQueryHandler,
    RoundInstructions, RoundLimits,
};
use ic_interfaces::execution_environment::{
    ChainKeySettings, ExecutionMode, IngressHistoryWriter, RegistryExecutionSettings,
    SubnetAvailableMemory,
};
use ic_interfaces_state_manager::Labeled;
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInstallMode, CanisterInstallModeV2, CanisterSettingsArgs,
    CanisterSettingsArgsBuilder, CanisterStatusType, CanisterUpgradeOptions, EmptyBlob,
    InstallCodeArgs, InstallCodeArgsV2, LogVisibilityV2, MasterPublicKeyId, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs, UpdateSettingsArgs,
};
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{
    CanisterIdRange, RoutingTable, WellFormedError, CANISTER_IDS_PER_SUBNET,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::{execution_state::SandboxMemory, NextExecution},
    page_map::{
        test_utils::base_only_storage_layout, PageMap, TestPageAllocatorFileDescriptorImpl,
        PAGE_SIZE,
    },
    testing::{CanisterQueuesTesting, ReplicatedStateTesting},
    CallContext, CanisterState, ExecutionState, ExecutionTask, InputQueueType, NetworkTopology,
    PageIndex, ReplicatedState, SubnetTopology,
};
use ic_system_api::InstructionLimits;
use ic_test_utilities::{crypto::mock_random_number_generator, state_manager::FakeStateManager};
use ic_test_utilities_types::messages::{IngressBuilder, RequestBuilder, SignedIngressBuilder};
use ic_types::{
    batch::QueryStats,
    crypto::{canister_threshold_sig::MasterPublicKey, AlgorithmId},
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{
        CallbackId, CanisterCall, CanisterMessage, CanisterTask, MessageId, Query, QuerySource,
        RequestOrResponse, Response, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
    },
    time::UNIX_EPOCH,
    CanisterId, Cycles, Height, NumInstructions, QueryStatsEpoch, Time, UserId,
};
use ic_types_test_utils::ids::{node_test_id, subnet_test_id, user_test_id};
use ic_universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_wasm_types::BinaryEncodedWasm;
use maplit::{btreemap, btreeset};
use std::convert::TryFrom;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};
use std::{os::unix::prelude::FileExt, str::FromStr};
use tempfile::NamedTempFile;

mod wat_canister;
pub use wat_canister::{wat_canister, wat_fn, WatCanisterBuilder, WatFnCode};

const INITIAL_CANISTER_CYCLES: Cycles = Cycles::new(1_000_000_000_000);

/// A helper to create subnets.
pub fn generate_subnets(
    subnet_ids: Vec<SubnetId>,
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
        result.insert(
            subnet_id,
            SubnetTopology {
                public_key: vec![1, 2, 3, 4],
                nodes,
                subnet_type,
                subnet_features: SubnetFeatures::default(),
                idkg_keys_held: BTreeSet::new(),
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
        subnets: generate_subnets(subnets, own_subnet_id, own_subnet_type, subnet_size),
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
    }
}

/// When a universal canister is installed, but the serialized module has been
/// cached, the test setup thinks the canister was only charged for the reduced
/// compilation cost amount, when it was really charged for the full amount
/// (because it uses the change in round limits instead of what the canister was
/// actually charged). This function returns the amount needed to correct for
/// that difference.
pub fn universal_canister_compilation_cost_correction() -> NumInstructions {
    let cost = wasm_compilation_cost(UNIVERSAL_CANISTER_WASM);
    cost - CompilationCostHandling::CountReducedAmount.adjusted_compilation_cost(cost)
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
/// assert_empty_reply(result);
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

    // Read-only fields.
    dirty_heap_page_overhead: u64,
    instruction_limits: InstructionLimits,
    install_code_instruction_limits: InstructionLimits,
    instruction_limit_without_dts: NumInstructions,
    initial_canister_cycles: Cycles,
    ingress_memory_capacity: NumBytes,
    registry_settings: RegistryExecutionSettings,
    manual_execution: bool,
    caller_canister_id: Option<CanisterId>,
    idkg_subnet_public_keys: BTreeMap<MasterPublicKeyId, MasterPublicKey>,

    // The actual implementation.
    exec_env: ExecutionEnvironment,
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

    pub fn execution_environment(&self) -> &ExecutionEnvironment {
        &self.exec_env
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

    pub fn xnet_messages(&self) -> &Vec<RequestOrResponse> {
        &self.xnet_messages
    }

    pub fn get_xnet_response(&self, index: usize) -> &Arc<Response> {
        match &self.xnet_messages[index] {
            RequestOrResponse::Request(request) => {
                panic!(
                    "Expected the xnet message to be a Response, but got a Request: {:?}",
                    request
                )
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

    pub fn canister_execution_cost(&self, canister_id: CanisterId) -> Cycles {
        *self
            .execution_cost
            .get(&canister_id)
            .unwrap_or(&Cycles::new(0))
    }

    pub fn idle_cycles_burned_per_day(&self, canister_id: CanisterId) -> Cycles {
        let memory_usage = self.execution_state(canister_id).memory_usage()
            + self
                .canister_state(canister_id)
                .canister_history_memory_usage();
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
            canister.system_state.reserved_balance(),
        )
    }

    pub fn call_fee<S: ToString>(&self, method_name: S, payload: &[u8]) -> Cycles {
        self.cycles_account_manager
            .xnet_call_performed_fee(self.subnet_size())
            + self.cycles_account_manager.xnet_call_bytes_transmitted_fee(
                NumBytes::from((payload.len() + method_name.to_string().len()) as u64),
                self.subnet_size(),
            )
    }

    pub fn max_response_fee(&self) -> Cycles {
        self.cycles_account_manager.xnet_call_bytes_transmitted_fee(
            MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            self.subnet_size(),
        )
    }

    pub fn reply_fee(&self, payload: &[u8]) -> Cycles {
        self.cycles_account_manager.xnet_call_bytes_transmitted_fee(
            NumBytes::from(payload.len() as u64),
            self.subnet_size(),
        )
    }

    pub fn reject_fee<S: ToString>(&self, reject_message: S) -> Cycles {
        let bytes = reject_message.to_string().len() + std::mem::size_of::<RejectCode>();
        self.cycles_account_manager
            .xnet_call_bytes_transmitted_fee(NumBytes::from(bytes as u64), self.subnet_size())
    }

    pub fn canister_creation_fee(&self) -> Cycles {
        self.cycles_account_manager
            .canister_creation_fee(self.subnet_size())
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
        )
    }

    pub fn reduced_wasm_compilation_fee(&self, wasm: &[u8]) -> Cycles {
        let cost = wasm_compilation_cost(wasm);
        self.cycles_account_manager()
            .convert_instructions_to_cycles(
                cost - CompilationCostHandling::CountReducedAmount.adjusted_compilation_cost(cost),
            )
    }

    pub fn install_code_reserved_execution_cycles(&self) -> Cycles {
        let num_instructions = self.install_code_instruction_limits.message();
        self.cycles_account_manager
            .execution_cost(num_instructions, self.subnet_size())
    }

    pub fn subnet_available_memory(&self) -> SubnetAvailableMemory {
        self.subnet_available_memory
    }

    pub fn set_subnet_available_memory(&mut self, memory: SubnetAvailableMemory) {
        self.subnet_available_memory = memory
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
        self.state().get_ingress_status(message_id)
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
                panic!("Expected reply, got: {:?}", error);
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
    pub fn canister_status(&mut self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        let payload = CanisterIdRecord::from(canister_id).encode();
        self.subnet_message(Method::CanisterStatus, payload)
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
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister_id,
            wasm_binary,
            vec![],
            None,
            None,
        );
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
            None,
            None,
        );
        let result = self.install_code_v2(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    pub fn install_canister_with_allocation(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister_id,
            wasm_binary,
            vec![],
            compute_allocation,
            memory_allocation,
        );
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Re-installs the given canister with the given Wasm binary.
    pub fn reinstall_canister(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Reinstall,
            canister_id,
            wasm_binary,
            vec![],
            None,
            None,
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
            None,
            None,
        );
        let result = self.install_code_v2(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob.encode()), result);
        Ok(())
    }

    /// Installs the given canister with the given Wasm binary.
    pub fn upgrade_canister(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister_id,
            wasm_binary,
            vec![],
            None,
            None,
        );
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
            None,
            None,
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
            None,
            None,
        );
        self.dts_install_code(args)
    }

    pub fn upgrade_canister_with_allocation(
        &mut self,
        canister_id: CanisterId,
        wasm_binary: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
    ) -> Result<(), UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister_id,
            wasm_binary,
            vec![],
            compute_allocation,
            memory_allocation,
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
            .push_ingress(ingress);
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
            compute_allocation_used,
        };
        let instruction_limits = InstructionLimits::new(
            FlagStatus::Disabled,
            self.instruction_limit_without_dts,
            self.instruction_limit_without_dts,
        );
        match task {
            CanisterTask::Heartbeat => {
                canister
                    .system_state
                    .task_queue
                    .push_front(ExecutionTask::Heartbeat);
            }
            CanisterTask::GlobalTimer => {
                canister
                    .system_state
                    .task_queue
                    .push_front(ExecutionTask::GlobalTimer);
            }
            CanisterTask::OnLowWasmMemory => {
                canister
                    .system_state
                    .task_queue
                    .push_front(ExecutionTask::OnLowWasmMemory);
            }
        }
        let result = execute_canister(
            &self.exec_env,
            canister,
            instruction_limits,
            self.instruction_limit_without_dts,
            Arc::clone(&network_topology),
            self.time,
            &mut round_limits,
            self.subnet_size(),
        );
        self.subnet_available_memory = round_limits.subnet_available_memory;
        state.put_canister_state(result.canister);
        state.metadata.heap_delta_estimate += result.heap_delta;
        self.state = Some(state);
        self.update_execution_stats(
            canister_id,
            self.instruction_limits.message(),
            result.instructions_used.unwrap(),
        );
    }

    /// Executes an anonymous query in the given canister.
    pub fn anonymous_query<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let state = Arc::new(self.state.take().unwrap());

        let query = Query {
            source: QuerySource::Anonymous,
            receiver: canister_id,
            method_name: method_name.to_string(),
            method_payload,
        };

        let result = self.query_handler.query(
            query,
            Labeled::new(Height::from(0), Arc::clone(&state)),
            data_certificate,
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
        let state = Arc::new(self.state.take().unwrap());

        let query = Query {
            source: QuerySource::User {
                user_id: user_test_id(0),
                ingress_expiry: 0,
                nonce: None,
            },
            receiver: canister_id,
            method_name: method_name.to_string(),
            method_payload,
        };
        let result = self.query(query, Arc::clone(&state), vec![]);

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
            compute_allocation_used,
        };
        let result = self.exec_env.execute_canister_response(
            canister,
            Arc::new(response),
            self.instruction_limits.clone(),
            UNIX_EPOCH,
            network_topology,
            &mut round_limits,
            self.subnet_size(),
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

        state.subnet_queues_mut().push_ingress(message);

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
            compute_allocation_used,
        };

        let (new_state, instructions_used) = self.exec_env.execute_subnet_message(
            message,
            state,
            self.install_code_instruction_limits.clone(),
            &mut mock_random_number_generator(),
            &self.idkg_subnet_public_keys,
            &self.registry_settings,
            &mut round_limits,
        );
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.state = Some(new_state);
        if let Some(canister_id) = maybe_canister_id {
            if let Some(instructions_used) = instructions_used {
                self.update_execution_stats(
                    canister_id,
                    self.install_code_instruction_limits.message(),
                    instructions_used,
                );
            }
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
            compute_allocation_used,
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
                    self.instruction_limit_without_dts,
                    Arc::clone(&network_topology),
                    self.time,
                    &mut round_limits,
                    self.subnet_size(),
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
                    compute_allocation_used,
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
                    compute_allocation_used,
                };
                let result = execute_canister(
                    &self.exec_env,
                    canister,
                    self.instruction_limits.clone(),
                    self.instruction_limit_without_dts,
                    Arc::clone(&network_topology),
                    self.time,
                    &mut round_limits,
                    self.subnet_size(),
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
        // Ideally we would simply add `execution_cost(limit - left)`
        // but that leads to small precision errors because 1 Cycle = 0.4 Instructions.
        let fixed_cost = mgr.execution_cost(NumInstructions::from(0), self.subnet_size());
        let instruction_cost = mgr.execution_cost(limit, self.subnet_size())
            - mgr.execution_cost(left, self.subnet_size());
        *self
            .execution_cost
            .entry(canister_id)
            .or_insert(Cycles::new(0)) += instruction_cost + fixed_cost;
    }

    /// Inducts messages between canisters and pushes all cross-net messages to
    /// `self.xnet_messages`.
    pub fn induct_messages(&mut self) {
        let mut state = self.state.take().unwrap();
        let mut subnet_available_memory = self.subnet_available_memory.get_message_memory();
        let output_messages = get_output_messages(&mut state);
        let mut canisters = state.take_canister_states();
        for (canister_id, message) in output_messages {
            match canisters.get_mut(&canister_id) {
                Some(dest_canister) => {
                    let result = dest_canister.push_input(
                        message.clone(),
                        &mut subnet_available_memory,
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
            ingress.content(),
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
    ) -> Result<WasmResult, UserError> {
        // We always pass 0 as the height to the query handler, because we don't run consensus
        // in these tests and therefore there isn't any height.
        //
        // Currently, this height is only used for query stats collection and it doesn't matter which one we pass in here.
        // Even if consensus was running, it could be that all queries are actually running at height 0. The state passed in to
        // the query handler shouldn't have the height encoded, so there shouldn't be a mismatch between the two.
        self.query_handler.query(
            query,
            Labeled::new(Height::from(0), state),
            data_certificate,
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
            es.wasm_memory.page_map =
                PageMap::open(&base_only_storage_layout(path), Height::new(0), factory).unwrap();
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
            es.stable_memory.page_map =
                PageMap::open(&base_only_storage_layout(path), Height::new(0), factory).unwrap();
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
}

/// A builder for `ExecutionTest`.
pub struct ExecutionTestBuilder {
    execution_config: Config,
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    caller_subnet_id: Option<SubnetId>,
    subnet_type: SubnetType,
    log: ReplicaLogger,
    caller_canister_id: Option<CanisterId>,
    ecdsa_signature_fee: Option<Cycles>,
    schnorr_signature_fee: Option<Cycles>,
    idkg_keys_with_signing_enabled: BTreeMap<MasterPublicKeyId, bool>,
    instruction_limit: NumInstructions,
    slice_instruction_limit: NumInstructions,
    install_code_instruction_limit: NumInstructions,
    install_code_slice_instruction_limit: NumInstructions,
    instruction_limit_without_dts: NumInstructions,
    initial_canister_cycles: Cycles,
    registry_settings: RegistryExecutionSettings,
    manual_execution: bool,
    subnet_features: String,
    bitcoin_get_successors_follow_up_responses: BTreeMap<CanisterId, Vec<Vec<u8>>>,
    time: Time,
    resource_saturation_scaling: usize,
    heap_delta_rate_limit: NumBytes,
    upload_wasm_chunk_instructions: NumInstructions,
    canister_snapshot_baseline_instructions: NumInstructions,
}

impl Default for ExecutionTestBuilder {
    fn default() -> Self {
        let subnet_type = SubnetType::Application;
        let scheduler_config = SubnetConfig::new(subnet_type).scheduler_config;
        Self {
            execution_config: Config {
                rate_limiting_of_instructions: FlagStatus::Disabled,
                canister_sandboxing_flag: FlagStatus::Enabled,
                composite_queries: FlagStatus::Disabled,
                allocatable_compute_capacity_in_percent: 100,
                ..Config::default()
            },
            nns_subnet_id: subnet_test_id(2),
            own_subnet_id: subnet_test_id(1),
            caller_subnet_id: None,
            subnet_type,
            log: no_op_logger(),
            caller_canister_id: None,
            ecdsa_signature_fee: None,
            schnorr_signature_fee: None,
            idkg_keys_with_signing_enabled: Default::default(),
            instruction_limit: scheduler_config.max_instructions_per_message,
            slice_instruction_limit: scheduler_config.max_instructions_per_slice,
            install_code_instruction_limit: scheduler_config.max_instructions_per_install_code,
            install_code_slice_instruction_limit: scheduler_config
                .max_instructions_per_install_code_slice,
            instruction_limit_without_dts: scheduler_config
                .max_instructions_per_message_without_dts,
            initial_canister_cycles: INITIAL_CANISTER_CYCLES,
            registry_settings: test_registry_settings(),
            manual_execution: false,
            subnet_features: String::default(),
            bitcoin_get_successors_follow_up_responses: BTreeMap::default(),
            time: UNIX_EPOCH,
            resource_saturation_scaling: 1,
            heap_delta_rate_limit: scheduler_config.heap_delta_rate_limit,
            upload_wasm_chunk_instructions: scheduler_config.upload_wasm_chunk_instructions,
            canister_snapshot_baseline_instructions: scheduler_config
                .canister_snapshot_baseline_instructions,
        }
    }
}

impl ExecutionTestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_nns_subnet_id(self, nns_subnet_id: SubnetId) -> Self {
        Self {
            nns_subnet_id,
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

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        Self {
            subnet_type,
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

    pub fn with_idkg_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.idkg_keys_with_signing_enabled.insert(key_id, true);
        self
    }

    pub fn with_signing_disabled_idkg_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.idkg_keys_with_signing_enabled.insert(key_id, false);
        self
    }

    pub fn with_instruction_limit(self, limit: u64) -> Self {
        Self {
            instruction_limit: NumInstructions::from(limit),
            ..self
        }
    }

    pub fn with_slice_instruction_limit(self, limit: u64) -> Self {
        Self {
            slice_instruction_limit: NumInstructions::from(limit),
            ..self
        }
    }

    pub fn with_instruction_limit_without_dts(self, limit: u64) -> Self {
        Self {
            instruction_limit_without_dts: NumInstructions::from(limit),
            ..self
        }
    }

    pub fn with_install_code_instruction_limit(self, limit: u64) -> Self {
        Self {
            install_code_instruction_limit: NumInstructions::from(limit),
            ..self
        }
    }

    pub fn with_install_code_slice_instruction_limit(self, limit: u64) -> Self {
        Self {
            install_code_slice_instruction_limit: NumInstructions::from(limit),
            ..self
        }
    }

    pub fn with_initial_canister_cycles(self, initial_canister_cycles: u128) -> Self {
        Self {
            initial_canister_cycles: Cycles::new(initial_canister_cycles),
            ..self
        }
    }

    pub fn with_subnet_execution_memory(mut self, subnet_execution_memory: i64) -> Self {
        self.execution_config.subnet_memory_capacity =
            NumBytes::from(subnet_execution_memory as u64);
        self
    }

    pub fn with_subnet_memory_reservation(mut self, subnet_memory_reservation: i64) -> Self {
        self.execution_config.subnet_memory_reservation =
            NumBytes::from(subnet_memory_reservation as u64);
        self
    }

    pub fn with_subnet_memory_threshold(mut self, subnet_memory_threshold: i64) -> Self {
        self.execution_config.subnet_memory_threshold =
            NumBytes::from(subnet_memory_threshold as u64);
        self
    }

    pub fn with_subnet_message_memory(mut self, subnet_message_memory: i64) -> Self {
        self.execution_config.subnet_message_memory_capacity =
            NumBytes::from(subnet_message_memory as u64);
        self
    }

    pub fn with_subnet_wasm_custom_sections_memory(
        mut self,
        subnet_wasm_custom_sections_memory: i64,
    ) -> Self {
        self.execution_config
            .subnet_wasm_custom_sections_memory_capacity =
            NumBytes::from(subnet_wasm_custom_sections_memory as u64);
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

    pub fn with_deterministic_time_slicing_disabled(mut self) -> Self {
        self.execution_config.deterministic_time_slicing = FlagStatus::Disabled;
        self
    }

    pub fn with_canister_sandboxing_disabled(mut self) -> Self {
        self.execution_config.canister_sandboxing_flag = FlagStatus::Disabled;
        self
    }

    pub fn with_composite_queries(mut self) -> Self {
        self.execution_config.composite_queries = FlagStatus::Enabled;
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

    pub fn with_wasm64(mut self) -> Self {
        self.execution_config.embedders_config.feature_flags.wasm64 = FlagStatus::Enabled;
        self
    }

    pub fn with_metering_type(mut self, metering_type: MeteringType) -> Self {
        self.execution_config.embedders_config.metering_type = metering_type;
        self
    }

    pub fn with_non_native_stable(mut self) -> Self {
        self.execution_config
            .embedders_config
            .feature_flags
            .wasm_native_stable_memory = FlagStatus::Disabled;
        self
    }

    pub fn with_snapshots(mut self, status: FlagStatus) -> Self {
        self.execution_config.canister_snapshots = status;
        self
    }

    pub fn with_best_effort_responses(mut self, status: FlagStatus) -> Self {
        self.execution_config
            .embedders_config
            .feature_flags
            .best_effort_responses = status;
        self
    }

    pub fn with_ic00_compute_initial_i_dkg_dealings(mut self, status: FlagStatus) -> Self {
        self.execution_config.ic00_compute_initial_i_dkg_dealings = status;
        self
    }

    pub fn with_ic00_schnorr_public_key(mut self, status: FlagStatus) -> Self {
        self.execution_config.ic00_schnorr_public_key = status;
        self
    }

    pub fn with_ic00_sign_with_schnorr(mut self, status: FlagStatus) -> Self {
        self.execution_config.ic00_sign_with_schnorr = status;
        self
    }

    pub fn with_time(mut self, time: Time) -> Self {
        self.time = time;
        self
    }

    pub fn with_resource_saturation_scaling(mut self, scaling: usize) -> Self {
        self.resource_saturation_scaling = scaling;
        self
    }

    pub fn with_heap_delta_rate_limit(mut self, heap_delta_rate_limit: NumBytes) -> Self {
        self.heap_delta_rate_limit = heap_delta_rate_limit;
        self
    }

    pub fn with_max_dirty_pages_optimization_embedder_config(mut self, no_pages: usize) -> Self {
        self.execution_config
            .embedders_config
            .max_dirty_pages_without_optimization = no_pages;
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
            }).unwrap_or_else(|_| panic!("Unable to create routing table - sender canister {} is in the range {:?}", caller_canister, own_range)),
        });

        self.build_common(routing_table)
    }

    fn build_common(mut self, routing_table: Arc<RoutingTable>) -> ExecutionTest {
        let mut state = ReplicatedState::new(self.own_subnet_id, self.subnet_type);

        let mut subnets = vec![self.own_subnet_id, self.nns_subnet_id];
        subnets.extend(self.caller_subnet_id.iter().copied());
        state.metadata.network_topology.subnets = generate_subnets(
            subnets,
            self.own_subnet_id,
            self.subnet_type,
            self.registry_settings.subnet_size,
        );
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = self.nns_subnet_id;
        state.metadata.init_allocation_ranges_if_empty().unwrap();
        state.metadata.bitcoin_get_successors_follow_up_responses =
            self.bitcoin_get_successors_follow_up_responses;

        if self.subnet_features.is_empty() {
            state.metadata.own_subnet_features = SubnetFeatures::default();
        } else {
            state.metadata.own_subnet_features =
                SubnetFeatures::from_str(&self.subnet_features).unwrap();
        }

        let metrics_registry = MetricsRegistry::new();

        let mut config = SubnetConfig::new(self.subnet_type).cycles_account_manager_config;
        if let Some(ecdsa_signature_fee) = self.ecdsa_signature_fee {
            config.ecdsa_signature_fee = ecdsa_signature_fee;
        }
        if let Some(schnorr_signature_fee) = self.schnorr_signature_fee {
            config.schnorr_signature_fee = schnorr_signature_fee;
        }
        for (key_id, is_signing_enabled) in &self.idkg_keys_with_signing_enabled {
            // Populate hte chain key settings
            self.registry_settings.chain_key_settings.insert(
                key_id.clone(),
                ChainKeySettings {
                    max_queue_size: 20,
                    pre_signatures_to_create_in_advance: 5,
                },
            );

            if *is_signing_enabled {
                state
                    .metadata
                    .network_topology
                    .idkg_signing_subnets
                    .insert(key_id.clone(), vec![self.own_subnet_id]);
            }
            state
                .metadata
                .network_topology
                .subnets
                .get_mut(&self.own_subnet_id)
                .unwrap()
                .idkg_keys_held
                .insert(key_id.clone());
        }

        state.metadata.network_topology.bitcoin_mainnet_canister_id =
            self.execution_config.bitcoin.mainnet_canister_id;

        state.metadata.network_topology.bitcoin_testnet_canister_id =
            self.execution_config.bitcoin.testnet_canister_id;

        let idkg_subnet_public_keys = self
            .idkg_keys_with_signing_enabled
            .into_keys()
            .map(|key_id| match key_id {
                MasterPublicKeyId::Ecdsa(_) => (
                    key_id,
                    MasterPublicKey {
                        algorithm_id: AlgorithmId::EcdsaSecp256k1,
                        public_key: b"abababab".to_vec(),
                    },
                ),
                MasterPublicKeyId::Schnorr(_) => (
                    key_id,
                    MasterPublicKey {
                        algorithm_id: AlgorithmId::SchnorrSecp256k1,
                        public_key: b"cdcdcdcd".to_vec(),
                    },
                ),
            })
            .collect();

        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            self.instruction_limit,
            self.subnet_type,
            self.own_subnet_id,
            config,
        ));
        let config = self.execution_config.clone();

        let dirty_page_overhead = match self.subnet_type {
            SubnetType::Application => SchedulerConfig::application_subnet().dirty_page_overhead,
            SubnetType::System => SchedulerConfig::system_subnet().dirty_page_overhead,
            SubnetType::VerifiedApplication => {
                SchedulerConfig::verified_application_subnet().dirty_page_overhead
            }
        };

        let dirty_heap_page_overhead = match config.embedders_config.metering_type {
            MeteringType::New => dirty_page_overhead.get(),
            _ => 0,
        };

        let hypervisor = Hypervisor::new(
            config.clone(),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            self.log.clone(),
            Arc::clone(&cycles_account_manager),
            dirty_page_overhead,
            Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        );
        let hypervisor = Arc::new(hypervisor);
        let (completed_execution_messages_tx, _) = tokio::sync::mpsc::channel(1);
        let state_reader = Arc::new(FakeStateManager::new());
        let ingress_history_writer = IngressHistoryWriterImpl::new(
            config.clone(),
            self.log.clone(),
            &metrics_registry,
            completed_execution_messages_tx,
            state_reader,
        );
        let ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>> =
            Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironment::new(
            self.log.clone(),
            Arc::clone(&hypervisor),
            Arc::clone(&ingress_history_writer),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            // Compute capacity for 2-core scheduler is 100%
            // TODO(RUN-319): the capacity should be defined based on actual `scheduler_cores`
            100,
            config.clone(),
            Arc::clone(&cycles_account_manager),
            self.resource_saturation_scaling,
            Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            self.heap_delta_rate_limit,
            self.upload_wasm_chunk_instructions,
            self.canister_snapshot_baseline_instructions,
        );
        let (query_stats_collector, _) =
            ic_query_stats::init_query_stats(self.log.clone(), &config, &metrics_registry);

        let query_handler = InternalHttpQueryHandler::new(
            self.log.clone(),
            hypervisor,
            self.subnet_type,
            config.clone(),
            &metrics_registry,
            self.instruction_limit_without_dts,
            Arc::clone(&cycles_account_manager),
            query_stats_collector,
        );
        ExecutionTest {
            state: Some(state),
            message_id: 0,
            executed_instructions: HashMap::new(),
            execution_cost: HashMap::new(),
            xnet_messages: vec![],
            lost_messages: vec![],
            subnet_available_memory: SubnetAvailableMemory::new(
                self.execution_config.subnet_memory_capacity.get() as i64
                    - self.execution_config.subnet_memory_reservation.get() as i64,
                self.execution_config.subnet_message_memory_capacity.get() as i64,
                self.execution_config
                    .subnet_wasm_custom_sections_memory_capacity
                    .get() as i64,
            ),
            time: self.time,
            dirty_heap_page_overhead,
            instruction_limits: InstructionLimits::new(
                self.execution_config.deterministic_time_slicing,
                self.instruction_limit,
                self.slice_instruction_limit,
            ),
            install_code_instruction_limits: InstructionLimits::new(
                self.execution_config.deterministic_time_slicing,
                self.install_code_instruction_limit,
                self.install_code_slice_instruction_limit,
            ),
            ingress_memory_capacity: config.ingress_history_memory_capacity,
            instruction_limit_without_dts: self.instruction_limit_without_dts,
            initial_canister_cycles: self.initial_canister_cycles,
            registry_settings: self.registry_settings,
            user_id: user_test_id(1),
            caller_canister_id: self.caller_canister_id,
            exec_env,
            query_handler,
            cycles_account_manager,
            metrics_registry,
            ingress_history_writer,
            manual_execution: self.manual_execution,
            idkg_subnet_public_keys,
            log: self.log,
            checkpoint_files: vec![],
        }
    }
}

/// A helper to extract the reply from an execution result.
pub fn get_reply(result: Result<WasmResult, UserError>) -> Vec<u8> {
    match result {
        Ok(WasmResult::Reply(data)) => data,
        Ok(WasmResult::Reject(error)) => {
            unreachable!("Expected reply, got: {:?}", error);
        }
        Err(error) => {
            unreachable!("Expected reply, got: {:?}", error);
        }
    }
}

/// A helper to assert that execution was successful and produced no reply.
pub fn assert_empty_reply(result: Result<WasmResult, UserError>) {
    match result {
        Err(err) if err.code() == ErrorCode::CanisterDidNotReply => {}
        _ => unreachable!("Expected empty reply, got {:?}", result),
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
    ($x:expr, $y:expr, $d:expr) => {
        // As Cycles use saturating sub, we can't just subtract $x from $y
        if !($x >= $y && $x - $y <= $d) && !($x < $y && $y - $x <= $d) {
            assert_eq!($x, $y, "delta: `{:?}`", $d);
        }
    };
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
