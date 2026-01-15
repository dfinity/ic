use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    convert::{TryFrom, TryInto},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ic_base_types::{CanisterId, NumBytes, PrincipalId, SubnetId};
use ic_config::{
    embedders::Config as HypervisorConfig,
    flag_status::FlagStatus,
    subnet_config::{SchedulerConfig, SubnetConfig},
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::{
    CompilationCache, CompilationResult, WasmExecutionInput,
    wasm_executor::{
        CanisterStateChanges, ExecutionStateChanges, PausedWasmExecution, SliceExecutionOutput,
        WasmExecutionResult, WasmExecutor,
    },
    wasmtime_embedder::system_api::{
        ApiType, ExecutionParameters,
        sandbox_safe_system_state::{SandboxSafeSystemState, SystemStateModifications},
    },
};
use ic_error_types::UserError;
use ic_interfaces::execution_environment::{
    ChainKeySettings, ExecutionRoundSummary, ExecutionRoundType, HypervisorError, HypervisorResult,
    InstanceStats, MessageMemoryUsage, RegistryExecutionSettings, Scheduler, SystemApiCallCounters,
    WasmExecutionOutput,
};
use ic_logger::{ReplicaLogger, replica_logger::no_op_logger};
use ic_management_canister_types_private::{
    CanisterInstallMode, CanisterStatusType, IC_00, InstallCodeArgs, MasterPublicKeyId, Method,
    Payload,
};
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState, ExecutionState, ExportedFunctions, InputQueueType, Memory, ReplicatedState,
    canister_state::execution_state::{self, WasmExecutionMode, WasmMetadata},
    page_map::TestPageAllocatorFileDescriptorImpl,
    testing::{CanisterQueuesTesting, ReplicatedStateTesting},
};
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_execution_environment::{generate_subnets, test_registry_settings};
use ic_test_utilities_state::CanisterStateBuilder;
use ic_test_utilities_types::{
    ids::{canister_test_id, subnet_test_id, user_test_id},
    messages::{RequestBuilder, SignedIngressBuilder},
};
use ic_types::{
    CanisterTimer, ComputeAllocation, Cycles, ExecutionRound, MemoryAllocation, NumInstructions,
    Randomness, ReplicaVersion, Time, UserId,
    batch::{AvailablePreSignatures, CanisterCyclesCostSchedule, ChainKeyData},
    consensus::idkg::IDkgMasterPublicKeyId,
    crypto::{AlgorithmId, canister_threshold_sig::MasterPublicKey},
    ingress::{IngressState, IngressStatus},
    messages::{
        CallContextId, Ingress, MessageId, NO_DEADLINE, Request, RequestOrResponse, Response,
    },
    methods::{Callback, FuncRef, SystemMethod, WasmClosure, WasmMethod},
};
use ic_wasm_types::CanisterModule;
use maplit::btreemap;
use std::time::Duration;

use crate::{ExecutionServicesForTesting, RoundLimits, as_round_instructions};

use super::SchedulerImpl;
use crate::metrics::MeasurementScope;
use ic_crypto_prng::{Csprng, RandomnessPurpose::ExecutionThread};
use ic_types::time::UNIX_EPOCH;

/// A helper for the scheduler tests. It comes with its own Wasm executor that
/// fakes execution of Wasm code for performance, so it can process thousands
/// of messages in milliseconds.
///
/// See the comments of `TestMessage` for the description on how to create
/// fake ingress messages and inter-canister call messages.
///
/// Example usages of the test helper:
/// ```
/// let mut test = SchedulerTestBuilder::new().build();
/// let canister_id = test.create_canister();
/// let message = ingress(50);
/// test.send_ingress(canister_id, message);
/// test.execute_round(ExecutionRoundType::OrdinaryRound);
/// ```
pub(crate) struct SchedulerTest {
    // The current replicated state. The option type allows taking the state for
    // execution and then putting it back afterwards.
    state: Option<ReplicatedState>,
    // Monotonically increasing counter used during canister creation.
    next_canister_id: u64,
    // Monotonically increasing counter that specifies the current round.
    round: ExecutionRound,
    /// Round summary collected form the last DKG summary block.
    round_summary: Option<ExecutionRoundSummary>,
    // The amount of cycles that new canisters have by default.
    initial_canister_cycles: Cycles,
    // The id of the user that sends ingress messages.
    user_id: UserId,
    // The id of a canister that is guaranteed to be xnet.
    xnet_canister_id: CanisterId,
    // The actual scheduler.
    scheduler: SchedulerImpl,
    // The fake Wasm executor.
    wasm_executor: Arc<TestWasmExecutor>,
    // Registry Execution Settings.
    registry_settings: RegistryExecutionSettings,
    // Metrics Registry.
    metrics_registry: MetricsRegistry,
    // Chain key subnet public keys.
    chain_key_subnet_public_keys: BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    // Available pre-signatures.
    idkg_pre_signatures: BTreeMap<IDkgMasterPublicKeyId, AvailablePreSignatures>,
    // Version of the running replica, not the registry's Entry
    replica_version: ReplicaVersion,
}

impl std::fmt::Debug for SchedulerTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchedulerTest").finish()
    }
}

impl SchedulerTest {
    pub fn state(&self) -> &ReplicatedState {
        self.state.as_ref().unwrap()
    }

    pub fn state_mut(&mut self) -> &mut ReplicatedState {
        self.state.as_mut().unwrap()
    }

    pub fn canister_state(&self, canister_id: CanisterId) -> &CanisterState {
        self.state().canister_state(&canister_id).unwrap()
    }

    pub fn metrics_registry(&self) -> &MetricsRegistry {
        &self.metrics_registry
    }

    pub fn canister_state_mut(&mut self, canister_id: CanisterId) -> &mut CanisterState {
        self.state_mut().canister_state_mut(&canister_id).unwrap()
    }

    pub fn ingress_queue_size(&self, canister_id: CanisterId) -> usize {
        self.canister_state(canister_id)
            .system_state
            .queues()
            .ingress_queue_size()
    }

    pub fn subnet_ingress_queue_size(&self) -> usize {
        self.state().subnet_queues().ingress_queue_size()
    }

    pub fn last_round(&self) -> ExecutionRound {
        ExecutionRound::new(self.round.get().max(1) - 1)
    }

    pub fn advance_to_round(&mut self, round: ExecutionRound) {
        self.round = round;
    }

    pub fn scheduler(&self) -> &SchedulerImpl {
        &self.scheduler
    }

    pub fn xnet_canister_id(&self) -> CanisterId {
        self.xnet_canister_id
    }

    pub fn registry_settings(&self) -> &RegistryExecutionSettings {
        &self.registry_settings
    }

    pub fn set_cost_schedule(&mut self, cost_schedule: CanisterCyclesCostSchedule) {
        if let Some(state) = self.state.as_mut() {
            state.set_own_cost_schedule(cost_schedule);
        }
        self.registry_settings.canister_cycles_cost_schedule = cost_schedule;
    }

    /// Returns how many instructions were executed by a canister on a thread
    /// and in an execution round. The order of elements is important and
    /// matches the execution order for a fixed thread.
    pub fn executed_schedule(&self) -> Vec<(ExecutionRound, CanisterId, NumInstructions)> {
        let wasm_executor = self.wasm_executor.core.lock().unwrap();
        wasm_executor.schedule.clone()
    }

    pub fn create_canister(&mut self) -> CanisterId {
        self.create_canister_with(
            self.initial_canister_cycles,
            ComputeAllocation::zero(),
            MemoryAllocation::default(),
            None,
            None,
            None,
        )
    }

    pub fn execution_cost(&self, num_instructions: NumInstructions) -> Cycles {
        use ic_replicated_state::canister_state::execution_state::WasmExecutionMode;
        self.scheduler.cycles_account_manager.execution_cost(
            num_instructions,
            self.subnet_size(),
            self.state.as_ref().unwrap().get_own_cost_schedule(),
            WasmExecutionMode::Wasm32,
        )
    }

    /// Creates a canister with the given balance and allocations.
    /// The `system_task` parameter can be used to optionally enable the
    /// heartbeat by passing `Some(SystemMethod::CanisterHeartbeat)`.
    /// In that case the heartbeat execution must be specified before each
    /// round using `expect_heartbeat()`.
    pub fn create_canister_with_controller(
        &mut self,
        cycles: Cycles,
        compute_allocation: ComputeAllocation,
        memory_allocation: MemoryAllocation,
        system_task: Option<SystemMethod>,
        time_of_last_allocation_charge: Option<Time>,
        status: Option<CanisterStatusType>,
        controller: Option<PrincipalId>,
    ) -> CanisterId {
        let canister_id = self.next_canister_id();
        let wasm_source = system_task
            .map(|x| x.to_string().as_bytes().to_vec())
            .unwrap_or_default();
        let time_of_last_allocation_charge =
            time_of_last_allocation_charge.map_or(UNIX_EPOCH, |time| time);
        let controller = controller.unwrap_or(self.user_id.get());
        let mut canister_state = CanisterStateBuilder::new()
            .with_canister_id(canister_id)
            .with_cycles(cycles)
            .with_controller(controller)
            .with_compute_allocation(compute_allocation)
            .with_memory_allocation(memory_allocation.pre_allocated_bytes())
            .with_wasm(wasm_source.clone())
            .with_freezing_threshold(100)
            .with_time_of_last_allocation_charge(time_of_last_allocation_charge)
            .with_status(status.unwrap_or(CanisterStatusType::Running))
            .build();
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        canister_state.execution_state = Some(
            wasm_executor
                .create_execution_state(CanisterModule::new(wasm_source), canister_id)
                .unwrap()
                .0,
        );
        canister_state
            .system_state
            .controllers
            .insert(self.xnet_canister_id.get());
        self.state
            .as_mut()
            .unwrap()
            .put_canister_state(canister_state);
        canister_id
    }

    /// Creates a canister with the given balance and allocations.
    /// The `system_task` parameter can be used to optionally enable the
    /// heartbeat by passing `Some(SystemMethod::CanisterHeartbeat)`.
    /// In that case the heartbeat execution must be specified before each
    /// round using `expect_heartbeat()`.
    pub fn create_canister_with(
        &mut self,
        cycles: Cycles,
        compute_allocation: ComputeAllocation,
        memory_allocation: MemoryAllocation,
        system_task: Option<SystemMethod>,
        time_of_last_allocation_charge: Option<Time>,
        status: Option<CanisterStatusType>,
    ) -> CanisterId {
        self.create_canister_with_controller(
            cycles,
            compute_allocation,
            memory_allocation,
            system_task,
            time_of_last_allocation_charge,
            status,
            None,
        )
    }

    pub fn send_ingress(&mut self, canister_id: CanisterId, message: TestMessage) -> MessageId {
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        let mut state = self.state.take().unwrap();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        let message_id = wasm_executor.push_ingress(
            canister_id,
            canister,
            message,
            Time::from_nanos_since_unix_epoch(u64::MAX / 2),
        );
        self.state = Some(state);
        message_id
    }

    pub fn send_ingress_with_expiry(
        &mut self,
        canister_id: CanisterId,
        message: TestMessage,
        expiry_time: Time,
    ) -> MessageId {
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        let mut state = self.state.take().unwrap();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        let message_id = wasm_executor.push_ingress(canister_id, canister, message, expiry_time);
        self.state = Some(state);
        message_id
    }

    pub fn ingress_status(&self, message_id: &MessageId) -> IngressStatus {
        self.state
            .as_ref()
            .unwrap()
            .get_ingress_status(message_id)
            .clone()
    }

    pub fn ingress_error(&self, message_id: &MessageId) -> UserError {
        match self.ingress_status(message_id) {
            IngressStatus::Known { state, .. } => match state {
                IngressState::Failed(error) => error,
                IngressState::Received
                | IngressState::Completed(_)
                | IngressState::Processing
                | IngressState::Done => unreachable!("Unexpected ingress state: {:?}", state),
            },
            IngressStatus::Unknown => unreachable!("Expected message to finish."),
        }
    }

    pub fn ingress_state(&self, message_id: &MessageId) -> IngressState {
        match self.ingress_status(message_id) {
            IngressStatus::Known { state, .. } => state,
            IngressStatus::Unknown => unreachable!("Expected a known ingress status."),
        }
    }

    /// Injects a call to the management canister.
    /// Note that this function doesn't support `InstallCode`
    /// messages, because for such messages we additionally need to know
    /// how many instructions the corresponding Wasm execution needs.
    /// See `inject_install_code_call_to_ic00()`.
    ///
    /// Use `get_responses_to_injected_calls()` to obtain the response
    /// after round execution.
    pub fn inject_call_to_ic00<S: ToString>(
        &mut self,
        method_name: S,
        method_payload: Vec<u8>,
        payment: Cycles,
        caller: CanisterId,
        input_type: InputQueueType,
    ) {
        assert!(
            method_name.to_string() != Method::InstallCode.to_string(),
            "Use `inject_install_code_call_to_ic00()`."
        );

        self.state_mut()
            .subnet_queues_mut()
            .push_input(
                RequestBuilder::new()
                    .sender(caller)
                    .receiver(CanisterId::ic_00())
                    .method_name(method_name)
                    .method_payload(method_payload)
                    .payment(payment)
                    .build()
                    .into(),
                input_type,
            )
            .unwrap();
    }

    /// Injects an ingress to the management canister.
    pub fn inject_ingress_to_ic00<S: ToString>(
        &mut self,
        method_name: S,
        method_payload: Vec<u8>,
        expiry_time: Time,
    ) {
        let ingress_id = {
            let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
            wasm_executor.next_message_id()
        };
        self.state_mut().subnet_queues_mut().push_ingress(
            (
                SignedIngressBuilder::new()
                    .canister_id(IC_00)
                    .method_name(method_name)
                    .method_payload(method_payload)
                    .nonce(ingress_id as u64)
                    .expiry_time(expiry_time)
                    .build(),
                None,
            )
                .into(),
        );
    }

    /// Similar to `inject_call_to_ic00()` but supports `InstallCode` messages.
    /// Example usage:
    /// ```text
    /// let upgrade = TestInstallCode::Upgrade {
    ///     pre_upgrade: instructions(10),
    ///     start: instructions(20),
    ///     post_upgrade: instructions(30),
    /// };
    /// test.inject_install_code_call_to_ic00(canister, upgrade);
    /// ```
    ///
    /// Use `get_responses_to_injected_calls()` to obtain the response
    /// after round execution.
    pub fn inject_install_code_call_to_ic00(
        &mut self,
        target: CanisterId,
        install_code: TestInstallCode,
    ) {
        let wasm_module = wat::parse_str("(module)").unwrap();

        let (mode, test_message) = match install_code {
            TestInstallCode::Install { init } => (CanisterInstallMode::Install, init),
            TestInstallCode::Reinstall { init } => (CanisterInstallMode::Reinstall, init),
            TestInstallCode::Upgrade { post_upgrade } => {
                (CanisterInstallMode::Upgrade, post_upgrade)
            }
        };

        let message_id = {
            let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
            wasm_executor.push_install_code(test_message)
        };

        let message_payload = InstallCodeArgs {
            mode,
            canister_id: target.get(),
            wasm_module,
            arg: encode_message_id_as_payload(message_id),
            sender_canister_version: None,
        };

        let caller = self.xnet_canister_id();
        self.state_mut()
            .subnet_queues_mut()
            .push_input(
                RequestBuilder::new()
                    .sender(caller)
                    .receiver(CanisterId::ic_00())
                    .method_name(Method::InstallCode)
                    .method_payload(message_payload.encode())
                    .build()
                    .into(),
                InputQueueType::RemoteSubnet,
            )
            .unwrap();
    }

    /// Returns all responses from the management canister to
    /// `self.xnet_canister_id()`.
    pub fn get_responses_to_injected_calls(&mut self) -> Vec<Response> {
        let mut output: Vec<Response> = vec![];
        let xnet_canister_id = self.xnet_canister_id;
        let subnet_queue = self.state_mut().subnet_queues_mut();

        while let Some(msg) = subnet_queue.pop_canister_output(&xnet_canister_id) {
            match msg {
                RequestOrResponse::Request(request) => {
                    panic!(
                        "Expected the xnet message to be a Response, but got a Request: {request:?}"
                    )
                }
                RequestOrResponse::Response(response) => {
                    output.push((*response).clone());
                }
            }
        }
        output
    }

    /// Specifies heartbeat execution for the next round.
    pub fn expect_heartbeat(&mut self, canister_id: CanisterId, system_task: TestMessage) {
        assert!(
            self.canister_state(canister_id)
                .execution_state
                .as_ref()
                .unwrap()
                .exports_method(&WasmMethod::System(SystemMethod::CanisterHeartbeat)),
            "The canister should be created with \
             `create_canister_with(.., Some(SystemMethod::CanisterHeartbeat))`"
        );
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        wasm_executor.push_system_task(canister_id, system_task);
    }

    pub fn expect_global_timer(&mut self, canister_id: CanisterId, system_task: TestMessage) {
        assert!(
            self.canister_state(canister_id)
                .execution_state
                .as_ref()
                .unwrap()
                .exports_method(&WasmMethod::System(SystemMethod::CanisterGlobalTimer)),
            "The canister should be created with \
             `create_canister_with(.., Some(SystemMethod::CanisterGlobalTimer))`"
        );
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        wasm_executor.push_system_task(canister_id, system_task);
    }

    pub fn execute_round(&mut self, round_type: ExecutionRoundType) {
        let state = self.state.take().unwrap();
        let state = self.scheduler.execute_round(
            state,
            Randomness::from([0; 32]),
            ChainKeyData {
                master_public_keys: self.chain_key_subnet_public_keys.clone(),
                idkg_pre_signatures: self.idkg_pre_signatures.clone(),
                nidkg_ids: BTreeMap::new(),
            },
            &self.replica_version,
            self.round,
            self.round_summary.clone(),
            round_type,
            self.registry_settings(),
        );
        self.state = Some(state);
        self.increment_round();
    }

    /// Executes ordinary rounds until there is no more progress,
    /// calling closure `f` after each round.
    pub fn execute_all_with<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Self),
    {
        let mut number_of_executed_slices = 0;
        loop {
            self.execute_round(ExecutionRoundType::OrdinaryRound);
            f(self);
            let prev_number_of_executed_slices = number_of_executed_slices;
            number_of_executed_slices = self.executed_schedule().len();
            if prev_number_of_executed_slices == number_of_executed_slices {
                break;
            }
        }
    }

    pub fn drain_subnet_messages(&mut self) -> ReplicatedState {
        let state = self.state.take().unwrap();
        let compute_allocation_used = state.total_compute_allocation();
        let mut csprng = Csprng::from_seed_and_purpose(
            &Randomness::from([0; 32]),
            &ExecutionThread(self.scheduler.config.scheduler_cores as u32),
        );
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                self.scheduler.config.max_instructions_per_round / 16,
            ),
            subnet_available_memory: self
                .scheduler
                .exec_env
                .scaled_subnet_available_memory(&state),
            subnet_available_callbacks: self.scheduler.exec_env.subnet_available_callbacks(&state),
            compute_allocation_used,
            subnet_memory_reservation: self.scheduler.exec_env.scaled_subnet_memory_reservation(),
        };
        let measurements = MeasurementScope::root(&self.scheduler.metrics.round_subnet_queue);
        self.scheduler.drain_subnet_queues(
            state,
            &mut csprng,
            self.round,
            &mut round_limits,
            &measurements,
            self.registry_settings(),
            &self.replica_version,
            &ChainKeyData::default(),
        )
    }

    pub fn charge_for_resource_allocations(&mut self) {
        let subnet_size = self.subnet_size();
        self.scheduler
            .charge_canisters_for_resource_allocation_and_usage(
                self.state.as_mut().unwrap(),
                subnet_size,
            )
    }

    pub fn induct_messages_on_same_subnet(&mut self) {
        self.scheduler
            .induct_messages_on_same_subnet(self.state.as_mut().unwrap());
    }

    fn increment_round(&mut self) {
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        self.round = ExecutionRound::new(self.round.get() + 1);
        wasm_executor.round = self.round;
    }

    fn next_canister_id(&mut self) -> CanisterId {
        let canister_id = canister_test_id(self.next_canister_id);
        self.next_canister_id += 1;
        canister_id
    }

    pub(crate) fn set_canister_global_timer(&mut self, canister: CanisterId, time: Time) {
        let canister_state = self.canister_state_mut(canister);
        canister_state.system_state.global_timer = CanisterTimer::Active(time);
    }

    pub(crate) fn set_time(&mut self, time: Time) {
        self.state_mut().metadata.batch_time = time;
    }

    pub fn subnet_size(&self) -> usize {
        self.registry_settings.subnet_size
    }

    pub fn ecdsa_signature_fee(&self) -> Cycles {
        self.scheduler.cycles_account_manager.ecdsa_signature_fee(
            self.registry_settings.subnet_size,
            self.state().get_own_cost_schedule(),
        )
    }

    pub fn schnorr_signature_fee(&self) -> Cycles {
        self.scheduler.cycles_account_manager.schnorr_signature_fee(
            self.registry_settings.subnet_size,
            self.state().get_own_cost_schedule(),
        )
    }

    pub fn http_request_fee(
        &self,
        request_size: NumBytes,
        response_size_limit: Option<NumBytes>,
    ) -> Cycles {
        self.scheduler.cycles_account_manager.http_request_fee(
            request_size,
            response_size_limit,
            self.subnet_size(),
            self.state.as_ref().unwrap().get_own_cost_schedule(),
        )
    }

    pub fn memory_cost(&self, bytes: NumBytes, duration: Duration) -> Cycles {
        self.scheduler.cycles_account_manager.memory_cost(
            bytes,
            duration,
            self.subnet_size(),
            self.state.as_ref().unwrap().get_own_cost_schedule(),
        )
    }

    pub(crate) fn deliver_pre_signatures(
        &mut self,
        idkg_pre_signatures: BTreeMap<IDkgMasterPublicKeyId, AvailablePreSignatures>,
    ) {
        self.idkg_pre_signatures = idkg_pre_signatures;
    }

    pub fn online_split_state(&mut self, subnet_id: SubnetId, other_subnet_id: SubnetId) {
        let mut state = self.state.take().unwrap();

        // Reset the split marker, just in case.
        state.metadata.subnet_split_from = None;

        let state_after_split = state.online_split(subnet_id, other_subnet_id).unwrap();
        self.state = Some(state_after_split);
    }
}

/// A builder for `SchedulerTest`.
pub(crate) struct SchedulerTestBuilder {
    own_subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    subnet_type: SubnetType,
    batch_time: Time,
    scheduler_config: SchedulerConfig,
    hypervisor_config: HypervisorConfig,
    initial_canister_cycles: Cycles,
    subnet_guaranteed_response_message_memory: u64,
    subnet_callback_soft_limit: usize,
    canister_guaranteed_callback_quota: usize,
    registry_settings: RegistryExecutionSettings,
    allocatable_compute_capacity_in_percent: usize,
    rate_limiting_of_instructions: bool,
    rate_limiting_of_heap_delta: bool,
    log: ReplicaLogger,
    master_public_key_ids: Vec<MasterPublicKeyId>,
    metrics_registry: MetricsRegistry,
    round_summary: Option<ExecutionRoundSummary>,
    replica_version: ReplicaVersion,
}

impl Default for SchedulerTestBuilder {
    fn default() -> Self {
        let subnet_type = SubnetType::Application;
        let scheduler_config = SubnetConfig::new(subnet_type).scheduler_config;
        let config = ic_config::execution_environment::Config::default();
        Self {
            own_subnet_id: subnet_test_id(1),
            nns_subnet_id: subnet_test_id(2),
            subnet_type,
            batch_time: UNIX_EPOCH,
            scheduler_config,
            hypervisor_config: config.embedders_config,
            initial_canister_cycles: Cycles::new(1_000_000_000_000_000_000),
            subnet_guaranteed_response_message_memory: config
                .guaranteed_response_message_memory_capacity
                .get(),
            subnet_callback_soft_limit: config.subnet_callback_soft_limit,
            canister_guaranteed_callback_quota: config.canister_guaranteed_callback_quota,
            registry_settings: test_registry_settings(),
            allocatable_compute_capacity_in_percent: 100,
            rate_limiting_of_instructions: false,
            rate_limiting_of_heap_delta: false,
            log: no_op_logger(),
            master_public_key_ids: vec![],
            metrics_registry: MetricsRegistry::new(),
            round_summary: None,
            replica_version: ReplicaVersion::default(),
        }
    }
}

impl SchedulerTestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        let scheduler_config = SubnetConfig::new(subnet_type).scheduler_config;
        Self {
            subnet_type,
            scheduler_config,
            ..self
        }
    }

    pub fn with_subnet_guaranteed_response_message_memory(
        self,
        subnet_guaranteed_response_message_memory: u64,
    ) -> Self {
        Self {
            subnet_guaranteed_response_message_memory,
            ..self
        }
    }

    pub fn with_subnet_callback_soft_limit(self, subnet_callback_soft_limit: usize) -> Self {
        Self {
            subnet_callback_soft_limit,
            ..self
        }
    }

    pub fn with_canister_guaranteed_callback_quota(
        self,
        canister_guaranteed_callback_quota: usize,
    ) -> Self {
        Self {
            canister_guaranteed_callback_quota,
            ..self
        }
    }

    pub fn with_scheduler_config(self, scheduler_config: SchedulerConfig) -> Self {
        Self {
            scheduler_config,
            ..self
        }
    }

    pub fn with_rate_limiting_of_instructions(self) -> Self {
        Self {
            rate_limiting_of_instructions: true,
            ..self
        }
    }

    pub fn with_rate_limiting_of_heap_delta(self) -> Self {
        Self {
            rate_limiting_of_heap_delta: true,
            ..self
        }
    }

    pub fn with_chain_key(self, key_id: MasterPublicKeyId) -> Self {
        Self {
            master_public_key_ids: vec![key_id],
            ..self
        }
    }

    pub fn with_chain_keys(self, master_public_key_ids: Vec<MasterPublicKeyId>) -> Self {
        Self {
            master_public_key_ids,
            ..self
        }
    }

    pub fn with_store_pre_signatures_in_state(mut self, status: FlagStatus) -> Self {
        self.scheduler_config.store_pre_signatures_in_state = status;
        self
    }

    pub fn with_batch_time(self, batch_time: Time) -> Self {
        Self { batch_time, ..self }
    }

    #[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
    pub fn with_round_summary(self, round_summary: ExecutionRoundSummary) -> Self {
        Self {
            round_summary: Some(round_summary),
            ..self
        }
    }

    pub fn with_replica_version(self, replica_version: ReplicaVersion) -> Self {
        Self {
            replica_version,
            ..self
        }
    }

    pub fn build(self) -> SchedulerTest {
        let first_xnet_canister = u64::MAX / 2;
        let routing_table = Arc::new(
            RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0x0), end: CanisterId::from(first_xnet_canister) } => self.own_subnet_id,
            }).unwrap()
        );

        let mut state = ReplicatedState::new(self.own_subnet_id, self.subnet_type);

        let mut registry_settings = self.registry_settings;

        state.metadata.network_topology.subnets = generate_subnets(
            vec![self.own_subnet_id, self.nns_subnet_id],
            self.nns_subnet_id,
            None,
            self.own_subnet_id,
            self.subnet_type,
            registry_settings.subnet_size,
        );
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = self.nns_subnet_id;
        state.metadata.batch_time = self.batch_time;

        let subnet_config = SubnetConfig::new(self.subnet_type);
        for key_id in &self.master_public_key_ids {
            state
                .metadata
                .network_topology
                .chain_key_enabled_subnets
                .insert(key_id.clone(), vec![self.own_subnet_id]);
            state
                .metadata
                .network_topology
                .subnets
                .get_mut(&self.own_subnet_id)
                .unwrap()
                .chain_keys_held
                .insert(key_id.clone());

            registry_settings.chain_key_settings.insert(
                key_id.clone(),
                ChainKeySettings {
                    max_queue_size: 20,
                    pre_signatures_to_create_in_advance: key_id
                        .requires_pre_signatures()
                        .then_some(5),
                },
            );
        }
        let chain_key_subnet_public_keys: BTreeMap<_, _> = self
            .master_public_key_ids
            .into_iter()
            .map(|key_id| {
                (
                    key_id,
                    MasterPublicKey {
                        algorithm_id: AlgorithmId::Secp256k1,
                        public_key: b"abababab".to_vec(),
                    },
                )
            })
            .collect();

        let cycles_account_manager = CyclesAccountManager::new(
            self.scheduler_config.max_instructions_per_message,
            self.subnet_type,
            self.own_subnet_id,
            subnet_config.cycles_account_manager_config,
        );
        let cycles_account_manager = Arc::new(cycles_account_manager);
        let rate_limiting_of_instructions = if self.rate_limiting_of_instructions {
            FlagStatus::Enabled
        } else {
            FlagStatus::Disabled
        };
        let rate_limiting_of_heap_delta = if self.rate_limiting_of_heap_delta {
            FlagStatus::Enabled
        } else {
            FlagStatus::Disabled
        };
        let config = ic_config::execution_environment::Config {
            allocatable_compute_capacity_in_percent: self.allocatable_compute_capacity_in_percent,
            guaranteed_response_message_memory_capacity: NumBytes::from(
                self.subnet_guaranteed_response_message_memory,
            ),
            subnet_callback_soft_limit: self.subnet_callback_soft_limit,
            canister_guaranteed_callback_quota: self.canister_guaranteed_callback_quota,
            rate_limiting_of_instructions,
            rate_limiting_of_heap_delta,
            ..ic_config::execution_environment::Config::default()
        };
        let wasm_executor = Arc::new(TestWasmExecutor::new(
            Arc::clone(&cycles_account_manager),
            registry_settings.subnet_size,
        ));
        let (completed_execution_messages_tx, _) = tokio::sync::mpsc::channel(1);
        let state_manager = Arc::new(FakeStateManager::new());

        let execution_services = ExecutionServicesForTesting::setup_execution(
            self.log.clone(),
            &self.metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            config.clone(),
            subnet_config.clone(),
            state_manager.clone(),
            state_manager.get_fd_factory(),
            completed_execution_messages_tx,
            state_manager.tmp(),
            Some(wasm_executor.clone()),
        );

        let scheduler = SchedulerImpl::new(
            self.scheduler_config,
            self.hypervisor_config,
            self.own_subnet_id,
            execution_services.ingress_history_writer,
            execution_services.execution_environment,
            execution_services.cycles_account_manager,
            &self.metrics_registry,
            self.log,
            rate_limiting_of_heap_delta,
            rate_limiting_of_instructions,
            Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        );

        SchedulerTest {
            state: Some(state),
            next_canister_id: 0,
            round: ExecutionRound::new(0),
            round_summary: self.round_summary,
            initial_canister_cycles: self.initial_canister_cycles,
            user_id: user_test_id(1),
            xnet_canister_id: canister_test_id(first_xnet_canister),
            scheduler,
            wasm_executor,
            registry_settings,
            metrics_registry: self.metrics_registry,
            chain_key_subnet_public_keys,
            idkg_pre_signatures: BTreeMap::new(),
            replica_version: self.replica_version,
        }
    }
}

/// A test message specifies the results returned when the message is executed
/// by the fake Wasm executor:
/// - the number of instructions consumed by execution.
/// - the number of dirty pages produced by execution.
/// - outgoing calls to other canisters produced by execution.
///
/// A test message can be constructed using the helper functions defined below:
/// - `ingress(5)`: a message that uses 5 instructions.
/// - `ingress(5).dirty_pages(1): a message that uses 5 instructions and
///   modifies one page.
/// - `ingress(5).call(other_side(callee, 3), on_response(8))`: a message
///   that uses 5 instructions and calls a canister with id `callee`.
///   The called message uses 3 instructions. The response handler  uses
///   8 instructions.
#[derive(Clone, Debug)]
pub(crate) struct TestMessage {
    // The canister id is optional and is inferred from the context if not
    // provided.
    canister: Option<CanisterId>,
    // The number of instructions that execution of this message will use.
    instructions: NumInstructions,
    // The number of 4KiB pages that execution of this message will writes to.
    dirty_pages: usize,
    // The outgoing calls that will be produced by execution of this message.
    calls: Vec<TestCall>,
}

impl TestMessage {
    pub fn dirty_pages(self, dirty_pages: usize) -> TestMessage {
        Self {
            dirty_pages,
            ..self
        }
    }

    pub fn call(mut self, other_side: TestMessage, on_response: TestMessage) -> TestMessage {
        self.calls.push(TestCall {
            other_side,
            on_response,
        });
        self
    }
}

// An internal helper struct to store the description of an inter-canister call.
#[derive(Clone, Debug)]
struct TestCall {
    // The message to execute on the callee side.
    other_side: TestMessage,
    // The response handler to execute on the caller side.
    on_response: TestMessage,
}

/// Description of an `install_code` message.
///
/// Note that the `start` and `canister_preupgrade` methods are not supported
/// due to limitation of the testing framework that relies on the incoming
/// payload to keep track of test message.
#[derive(Clone, Debug)]
pub(crate) enum TestInstallCode {
    Install { init: TestMessage },
    Reinstall { init: TestMessage },
    Upgrade { post_upgrade: TestMessage },
}

/// A helper to create an ingress test message. Note that the canister id is not
/// needed and will be specified by the function that enqueues the ingress.
pub(crate) fn ingress(instructions: u64) -> TestMessage {
    TestMessage {
        canister: None,
        instructions: NumInstructions::from(instructions),
        dirty_pages: 0,
        calls: vec![],
    }
}

/// A helper to create the test message of the callee.
pub(crate) fn other_side(callee: CanisterId, instructions: u64) -> TestMessage {
    TestMessage {
        canister: Some(callee),
        instructions: NumInstructions::from(instructions),
        dirty_pages: 0,
        calls: vec![],
    }
}

/// A helper to create the test message for handling the response of a call.
/// Note that the canister id is not needed and is inferred from the context.
pub(crate) fn on_response(instructions: u64) -> TestMessage {
    TestMessage {
        canister: None,
        instructions: NumInstructions::from(instructions),
        dirty_pages: 0,
        calls: vec![],
    }
}

/// A generic helper to describe a phase like `start`, `init`, `pre_upgrade`,
/// `post_upgrade` of an install code message.
pub(crate) fn instructions(instructions: u64) -> TestMessage {
    TestMessage {
        canister: None,
        instructions: NumInstructions::from(instructions),
        dirty_pages: 0,
        calls: vec![],
    }
}

// A wrapper around the fake Wasm executor.
// This wrapper is needs to guaranteed thread-safety.
struct TestWasmExecutor {
    core: Mutex<TestWasmExecutorCore>,
}

impl TestWasmExecutor {
    fn new(cycles_account_manager: Arc<CyclesAccountManager>, subnet_size: usize) -> Self {
        Self {
            core: Mutex::new(TestWasmExecutorCore::new(
                cycles_account_manager,
                subnet_size,
            )),
        }
    }
}

impl WasmExecutor for TestWasmExecutor {
    // The entry point of the Wasm executor.
    //
    // It finds the test message corresponding to the given input and "executes"
    // it by interpreting its description.
    fn execute(
        self: Arc<Self>,
        input: WasmExecutionInput,
        execution_state: &ExecutionState,
    ) -> (Option<CompilationResult>, WasmExecutionResult) {
        let (message_id, message, call_context_id) = {
            let mut guard = self.core.lock().unwrap();
            guard.take_message(&input)
        };
        let execution = TestPausedWasmExecution {
            message_id,
            message,
            sandbox_safe_system_state: input.sandbox_safe_system_state,
            execution_parameters: input.execution_parameters,
            canister_current_memory_usage: input.canister_current_memory_usage,
            canister_current_message_memory_usage: input.canister_current_message_memory_usage,
            call_context_id,
            instructions_executed: NumInstructions::from(0),
            executor: Arc::clone(&self),
        };
        let result = Box::new(execution).resume(execution_state);
        (None, result)
    }

    fn create_execution_state(
        &self,
        canister_module: CanisterModule,
        _canister_root: PathBuf,
        canister_id: CanisterId,
        _compilation_cache: Arc<CompilationCache>,
    ) -> HypervisorResult<(ExecutionState, NumInstructions, Option<CompilationResult>)> {
        let mut guard = self.core.lock().unwrap();
        guard.create_execution_state(canister_module, canister_id)
    }
}

// A fake Wasm executor that works as follows:
// - The test helper registers incoming test messages with this executor.
// - Each registered test message has a unique `u32` id.
// - For each registered test message, the corresponding real message
//   is created such that the test message id is encoded in the real message:
//   either in the payload (for calls) or in the environment of the callback
//   (for reply/reject).
// - In the `execute` function, the executor looks up the corresponding
//   test message and interprets its description.
struct TestWasmExecutorCore {
    messages: HashMap<u32, TestMessage>,
    system_tasks: HashMap<CanisterId, VecDeque<TestMessage>>,
    schedule: Vec<(ExecutionRound, CanisterId, NumInstructions)>,
    next_message_id: u32,
    round: ExecutionRound,
    subnet_size: usize,
    cycles_account_manager: Arc<CyclesAccountManager>,
}

impl TestWasmExecutorCore {
    fn new(cycles_account_manager: Arc<CyclesAccountManager>, subnet_size: usize) -> Self {
        Self {
            messages: HashMap::new(),
            system_tasks: HashMap::new(),
            schedule: vec![],
            next_message_id: 0,
            round: ExecutionRound::new(0),
            cycles_account_manager,
            subnet_size,
        }
    }

    // Advances progress of the given paused execution by executing one slice.
    fn execute_slice(
        &mut self,
        mut paused: Box<TestPausedWasmExecution>,
        execution_state: &ExecutionState,
    ) -> WasmExecutionResult {
        let canister_id = paused.sandbox_safe_system_state.canister_id();

        let message_limit = paused.execution_parameters.instruction_limits.message();
        let slice_limit = paused.execution_parameters.instruction_limits.slice();
        let instructions_to_execute =
            paused.message.instructions.min(message_limit) - paused.instructions_executed;

        let is_last_slice = instructions_to_execute <= slice_limit;
        if !is_last_slice {
            paused.instructions_executed += slice_limit;
            let slice = SliceExecutionOutput {
                executed_instructions: slice_limit,
            };
            self.schedule.push((self.round, canister_id, slice_limit));
            return WasmExecutionResult::Paused(slice, paused);
        }

        paused.instructions_executed += instructions_to_execute;

        if paused.message.instructions > message_limit {
            let slice = SliceExecutionOutput {
                executed_instructions: instructions_to_execute,
            };
            let output = WasmExecutionOutput {
                wasm_result: Err(HypervisorError::InstructionLimitExceeded(message_limit)),
                num_instructions_left: NumInstructions::from(0),
                allocated_bytes: NumBytes::from(0),
                allocated_guaranteed_response_message_bytes: NumBytes::from(0),
                new_memory_usage: None,
                new_message_memory_usage: None,
                instance_stats: InstanceStats::default(),
                system_api_call_counters: SystemApiCallCounters::default(),
            };
            self.schedule
                .push((self.round, canister_id, instructions_to_execute));
            return WasmExecutionResult::Finished(
                slice,
                output,
                CanisterStateChanges {
                    execution_state_changes: None,
                    system_state_modifications: SystemStateModifications::default(),
                },
            );
        }

        let message = paused.message;
        let instructions_left = message_limit - paused.instructions_executed;

        // Generate all the outgoing calls.
        let system_state_modifications = self.perform_calls(
            paused.sandbox_safe_system_state,
            message.calls,
            paused.call_context_id,
            paused.canister_current_memory_usage,
            paused.canister_current_message_memory_usage,
        );

        let execution_state_changes = ExecutionStateChanges {
            globals: execution_state.exported_globals.clone(),
            wasm_memory: execution_state.wasm_memory.clone(),
            stable_memory: execution_state.stable_memory.clone(),
        };

        let instance_stats = InstanceStats {
            wasm_accessed_pages: message.dirty_pages,
            wasm_dirty_pages: message.dirty_pages,
            wasm_read_before_write_count: message.dirty_pages,
            ..Default::default()
        };
        let slice = SliceExecutionOutput {
            executed_instructions: instructions_to_execute,
        };
        let output = WasmExecutionOutput {
            wasm_result: Ok(None),
            allocated_bytes: NumBytes::from(0),
            allocated_guaranteed_response_message_bytes: NumBytes::from(0),
            new_memory_usage: None,
            new_message_memory_usage: None,
            num_instructions_left: instructions_left,
            instance_stats,
            system_api_call_counters: SystemApiCallCounters::default(),
        };
        self.schedule
            .push((self.round, canister_id, instructions_to_execute));
        WasmExecutionResult::Finished(
            slice,
            output,
            CanisterStateChanges {
                execution_state_changes: Some(execution_state_changes),
                system_state_modifications,
            },
        )
    }

    fn create_execution_state(
        &mut self,
        canister_module: CanisterModule,
        _canister_id: CanisterId,
    ) -> HypervisorResult<(ExecutionState, NumInstructions, Option<CompilationResult>)> {
        let mut exported_functions = vec![
            WasmMethod::Update("update".into()),
            WasmMethod::System(SystemMethod::CanisterPostUpgrade),
            WasmMethod::System(SystemMethod::CanisterInit),
        ];
        if !canister_module.as_slice().is_empty()
            && let Ok(text) = std::str::from_utf8(canister_module.as_slice())
            && let Ok(system_task) = SystemMethod::try_from(text)
        {
            exported_functions.push(WasmMethod::System(system_task));
        }
        let execution_state = ExecutionState::new(
            Default::default(),
            execution_state::WasmBinary::new(canister_module),
            ExportedFunctions::new(exported_functions.into_iter().collect()),
            Memory::new_for_testing(),
            Memory::new_for_testing(),
            vec![],
            WasmMetadata::default(),
        );
        let compilation_result = CompilationResult::empty_for_testing();
        Ok((
            execution_state,
            NumInstructions::from(0),
            Some(compilation_result),
        ))
    }

    fn perform_calls(
        &mut self,
        mut system_state: SandboxSafeSystemState,
        calls: Vec<TestCall>,
        call_context_id: Option<CallContextId>,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
    ) -> SystemStateModifications {
        for call in calls.into_iter() {
            if let Err(error) = self.perform_call(
                &mut system_state,
                call,
                call_context_id.unwrap(),
                canister_current_memory_usage,
                canister_current_message_memory_usage,
            ) {
                eprintln!("Skipping a call due to an error: {error}");
            }
        }
        system_state.take_changes()
    }

    // Create the request and callback corresponding to the given test call.
    fn perform_call(
        &mut self,
        system_state: &mut SandboxSafeSystemState,
        call: TestCall,
        call_context_id: CallContextId,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
    ) -> Result<(), String> {
        let sender = system_state.canister_id();
        let receiver = call.other_side.canister.unwrap();
        let call_message_id = self.next_message_id();
        let response_message_id = self.next_message_id();
        let closure = WasmClosure::new(0, response_message_id.into());
        let prepayment_for_response_execution = self
            .cycles_account_manager
            .prepayment_for_response_execution(
                self.subnet_size,
                system_state.cost_schedule(),
                WasmExecutionMode::from_is_wasm64(system_state.is_wasm64_execution),
            );
        let prepayment_for_response_transmission = self
            .cycles_account_manager
            .prepayment_for_response_transmission(self.subnet_size, system_state.cost_schedule());
        let deadline = NO_DEADLINE;
        let callback = system_state
            .register_callback(Callback {
                call_context_id,
                originator: sender,
                respondent: receiver,
                cycles_sent: Cycles::zero(),
                prepayment_for_response_execution,
                prepayment_for_response_transmission,
                on_reply: closure.clone(),
                on_reject: closure,
                on_cleanup: None,
                deadline,
            })
            .map_err(|err| err.to_string())?;
        let request = Request {
            receiver,
            sender,
            sender_reply_callback: callback,
            payment: Cycles::zero(),
            method_name: "update".into(),
            method_payload: encode_message_id_as_payload(call_message_id),
            metadata: Default::default(),
            deadline,
        };
        if let Err(req) = system_state.push_output_request(
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            request,
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
        ) {
            system_state.unregister_callback(callback);
            return Err(format!("Failed pushing request {req:?} to output queue."));
        }
        self.messages.insert(call_message_id, call.other_side);
        self.messages.insert(response_message_id, call.on_response);
        Ok(())
    }

    // Returns the test message corresponding to the given input.
    fn take_message(
        &mut self,
        input: &WasmExecutionInput,
    ) -> (u32, TestMessage, Option<CallContextId>) {
        let canister_id = input.sandbox_safe_system_state.canister_id();
        match &input.api_type {
            ApiType::Update {
                incoming_payload,
                call_context_id,
                ..
            } => {
                let message_id = decode_message_id_from_payload(incoming_payload.clone());
                let message = self.messages.remove(&message_id).unwrap();
                (message_id, message, Some(*call_context_id))
            }
            ApiType::ReplyCallback {
                call_context_id, ..
            }
            | ApiType::RejectCallback {
                call_context_id, ..
            } => {
                let message_id = match &input.func_ref {
                    FuncRef::Method(_) => unreachable!("A callback requires a closure"),
                    FuncRef::UpdateClosure(closure) | FuncRef::QueryClosure(closure) => {
                        closure.env.try_into().unwrap()
                    }
                };
                let message = self.messages.remove(&message_id).unwrap();
                (message_id, message, Some(*call_context_id))
            }
            ApiType::SystemTask {
                call_context_id, ..
            } => {
                let message_id = self.next_message_id();
                let message = self
                    .system_tasks
                    .get_mut(&canister_id)
                    .unwrap()
                    .pop_front()
                    .unwrap();
                (message_id, message, Some(*call_context_id))
            }
            ApiType::Init {
                incoming_payload, ..
            } => {
                let message_id = decode_message_id_from_payload(incoming_payload.clone());
                let message = self.messages.remove(&message_id).unwrap();
                (message_id, message, None)
            }
            ApiType::PreUpgrade { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::Start { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. } => {
                unreachable!("The test Wasm executor does not support {}", input.api_type)
            }
        }
    }

    fn push_ingress(
        &mut self,
        canister_id: CanisterId,
        canister: &mut CanisterState,
        message: TestMessage,
        expiry_time: Time,
    ) -> MessageId {
        let ingress_id = self.next_message_id();
        self.messages.insert(ingress_id, message);
        let ingress: Ingress = (
            SignedIngressBuilder::new()
                .canister_id(canister_id)
                .method_name("update")
                .method_payload(encode_message_id_as_payload(ingress_id))
                .expiry_time(expiry_time)
                .build(),
            None,
        )
            .into();
        let message_id = ingress.message_id.clone();
        canister.push_ingress(ingress);
        message_id
    }

    fn push_install_code(&mut self, message: TestMessage) -> u32 {
        let message_id = self.next_message_id();
        self.messages.insert(message_id, message);
        message_id
    }

    fn push_system_task(&mut self, canister_id: CanisterId, system_task: TestMessage) {
        self.system_tasks
            .entry(canister_id)
            .or_default()
            .push_back(system_task);
    }

    fn next_message_id(&mut self) -> u32 {
        let result = self.next_message_id;
        self.next_message_id += 1;
        result
    }
}

/// Represent fake Wasm execution that can be paused and resumed.
struct TestPausedWasmExecution {
    message_id: u32,
    message: TestMessage,
    sandbox_safe_system_state: SandboxSafeSystemState,
    execution_parameters: ExecutionParameters,
    canister_current_memory_usage: NumBytes,
    canister_current_message_memory_usage: MessageMemoryUsage,
    call_context_id: Option<CallContextId>,
    instructions_executed: NumInstructions,
    executor: Arc<TestWasmExecutor>,
}

impl std::fmt::Debug for TestPausedWasmExecution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestPausedWasmExecution")
            .field("message", &self.message)
            .field("instructions_executed", &self.instructions_executed)
            .finish()
    }
}

impl PausedWasmExecution for TestPausedWasmExecution {
    fn resume(self: Box<Self>, execution_state: &ExecutionState) -> WasmExecutionResult {
        let executor = Arc::clone(&self.executor);
        let mut guard = executor.core.lock().unwrap();
        guard.execute_slice(self, execution_state)
    }

    fn abort(self: Box<Self>) {
        let executor = Arc::clone(&self.executor);
        let mut guard = executor.core.lock().unwrap();
        // Put back the message, so we could restart its execution later
        guard.messages.insert(self.message_id, self.message);
    }
}

fn decode_message_id_from_payload(payload: Vec<u8>) -> u32 {
    u32::from_le_bytes(payload.try_into().unwrap())
}

fn encode_message_id_as_payload(message_id: u32) -> Vec<u8> {
    message_id.to_le_bytes().into()
}
