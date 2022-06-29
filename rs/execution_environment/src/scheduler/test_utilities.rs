use std::{
    collections::{BTreeMap, HashMap},
    convert::{TryFrom, TryInto},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_btc_canister::BitcoinCanister;
use ic_config::{
    flag_status::FlagStatus,
    subnet_config::{SchedulerConfig, SubnetConfigs},
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::{
    wasm_executor::{WasmExecutionResult, WasmExecutor},
    WasmExecutionInput,
};
use ic_interfaces::execution_environment::{
    CompilationResult, ExecutionRoundType, HypervisorResult, IngressHistoryWriter, InstanceStats,
    Scheduler, WasmExecutionOutput,
};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::execution_state::{self, WasmMetadata},
    testing::CanisterQueuesTesting,
    CanisterState, ExecutionState, ExportedFunctions, ReplicatedState,
};
use ic_system_api::{
    sandbox_safe_system_state::{SandboxSafeSystemState, SystemStateChanges},
    ApiType,
};
use ic_test_utilities::{
    execution_environment::test_registry_settings,
    state::CanisterStateBuilder,
    types::{
        ids::{canister_test_id, subnet_test_id, user_test_id},
        messages::SignedIngressBuilder,
    },
};
use ic_types::{
    messages::{CallContextId, Request},
    methods::{Callback, FuncRef, WasmClosure, WasmMethod},
    ComputeAllocation, Cycles, ExecutionRound, MemoryAllocation, NumInstructions, Randomness,
    UserId,
};
use ic_wasm_types::CanisterModule;
use maplit::btreemap;

use crate::{ExecutionEnvironmentImpl, Hypervisor, IngressHistoryWriterImpl};

use super::SchedulerImpl;

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

    pub fn canister_state_mut(&mut self, canister_id: CanisterId) -> &mut CanisterState {
        self.state_mut().canister_state_mut(&canister_id).unwrap()
    }

    pub fn ingress_queue_size(&self, canister_id: CanisterId) -> usize {
        self.canister_state(canister_id)
            .system_state
            .queues()
            .ingress_queue_size()
    }

    pub fn last_round(&self) -> ExecutionRound {
        ExecutionRound::new(self.round.get().max(1) - 1)
    }

    pub fn scheduler(&self) -> &SchedulerImpl {
        &self.scheduler
    }

    pub fn xnet_canister_id(&self) -> CanisterId {
        self.xnet_canister_id
    }

    pub fn create_canister(&mut self) -> CanisterId {
        self.create_canister_with(
            self.initial_canister_cycles,
            ComputeAllocation::zero(),
            MemoryAllocation::BestEffort,
        )
    }

    pub fn create_canister_with(
        &mut self,
        cycles: Cycles,
        compute_allocation: ComputeAllocation,
        memory_allocation: MemoryAllocation,
    ) -> CanisterId {
        let canister_id = self.next_canister_id();
        let wasm_source = vec![];
        let mut canister_state = CanisterStateBuilder::new()
            .with_canister_id(canister_id)
            .with_cycles(cycles)
            .with_controller(self.user_id.get())
            .with_compute_allocation(compute_allocation)
            .with_memory_allocation(memory_allocation.bytes())
            .with_wasm(wasm_source.clone())
            .build();
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        canister_state.execution_state = Some(
            wasm_executor
                .create_execution_state(wasm_source, canister_id)
                .unwrap()
                .1,
        );
        self.state
            .as_mut()
            .unwrap()
            .put_canister_state(canister_state);
        canister_id
    }

    pub fn send_ingress(&mut self, canister_id: CanisterId, message: TestMessage) {
        let mut wasm_executor = self.wasm_executor.core.lock().unwrap();
        let mut state = self.state.take().unwrap();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        wasm_executor.push_ingress(canister_id, canister, message);
        self.state = Some(state);
    }

    pub fn execute_round(&mut self, round_type: ExecutionRoundType) {
        let state = self.state.take().unwrap();
        let state = self.scheduler.execute_round(
            state,
            Randomness::from([0; 32]),
            BTreeMap::new(),
            self.round,
            round_type,
            &test_registry_settings(),
        );
        self.state = Some(state);
        self.increment_round();
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
}

/// A builder for `SchedulerTest`.
pub(crate) struct SchedulerTestBuilder {
    own_subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    subnet_type: SubnetType,
    scheduler_config: SchedulerConfig,
    initial_canister_cycles: Cycles,
    subnet_total_memory: u64,
    subnet_message_memory: u64,
    max_canister_memory_size: u64,
    allocatable_compute_capacity_in_percent: usize,
    log: ReplicaLogger,
}

impl Default for SchedulerTestBuilder {
    fn default() -> Self {
        let subnet_type = SubnetType::Application;
        let scheduler_config = SubnetConfigs::default()
            .own_subnet_config(subnet_type)
            .scheduler_config;
        let config = ic_config::execution_environment::Config::default();
        let subnet_total_memory = config.subnet_memory_capacity.get();
        let max_canister_memory_size = config.max_canister_memory_size.get();
        Self {
            own_subnet_id: subnet_test_id(1),
            nns_subnet_id: subnet_test_id(2),
            subnet_type,
            scheduler_config,
            initial_canister_cycles: Cycles::new(1_000_000_000_000_000_000),
            subnet_total_memory,
            subnet_message_memory: subnet_total_memory,
            max_canister_memory_size,
            allocatable_compute_capacity_in_percent: 100,
            log: no_op_logger(),
        }
    }
}

impl SchedulerTestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        let scheduler_config = SubnetConfigs::default()
            .own_subnet_config(subnet_type)
            .scheduler_config;
        Self {
            subnet_type,
            scheduler_config,
            ..self
        }
    }

    pub fn with_subnet_total_memory(self, subnet_total_memory: u64) -> Self {
        Self {
            subnet_total_memory,
            ..self
        }
    }

    pub fn with_subnet_message_memory(self, subnet_message_memory: u64) -> Self {
        Self {
            subnet_message_memory,
            ..self
        }
    }

    pub fn with_max_canister_memory_size(self, max_canister_memory_size: u64) -> Self {
        Self {
            max_canister_memory_size,
            ..self
        }
    }

    pub fn with_scheduler_config(self, scheduler_config: SchedulerConfig) -> Self {
        Self {
            scheduler_config,
            ..self
        }
    }

    pub fn build(self) -> SchedulerTest {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let first_xnet_canister = u64::MAX / 2;
        let routing_table = Arc::new(
            RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0x0), end: CanisterId::from(first_xnet_canister) } => self.own_subnet_id,
            }).unwrap()
        );

        let mut state = ReplicatedState::new_rooted_at(
            self.own_subnet_id,
            self.subnet_type,
            tmpdir.path().to_path_buf(),
        );
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = self.nns_subnet_id;

        let metrics_registry = MetricsRegistry::new();

        let config = SubnetConfigs::default()
            .own_subnet_config(self.subnet_type)
            .cycles_account_manager_config;
        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            self.scheduler_config.max_instructions_per_message,
            self.subnet_type,
            self.own_subnet_id,
            config,
        ));
        let config = ic_config::execution_environment::Config {
            allocatable_compute_capacity_in_percent: self.allocatable_compute_capacity_in_percent,
            subnet_memory_capacity: NumBytes::from(self.subnet_total_memory as u64),
            subnet_message_memory_capacity: NumBytes::from(self.subnet_message_memory as u64),
            max_canister_memory_size: NumBytes::from(self.max_canister_memory_size),
            ..ic_config::execution_environment::Config::default()
        };
        let wasm_executor = Arc::new(TestWasmExecutor::new());
        let hypervisor = Hypervisor::new_for_testing(
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            self.log.clone(),
            Arc::clone(&cycles_account_manager),
            Arc::<TestWasmExecutor>::clone(&wasm_executor),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer =
            IngressHistoryWriterImpl::new(config.clone(), self.log.clone(), &metrics_registry);
        let ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>> =
            Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironmentImpl::new(
            self.log.clone(),
            hypervisor,
            Arc::clone(&ingress_history_writer),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            1,
            config,
            Arc::clone(&cycles_account_manager),
        );
        let bitcoin_canister = Arc::new(BitcoinCanister::new(&metrics_registry, self.log.clone()));
        let scheduler = SchedulerImpl::new(
            self.scheduler_config,
            self.own_subnet_id,
            ingress_history_writer,
            Arc::new(exec_env),
            cycles_account_manager,
            bitcoin_canister,
            &metrics_registry,
            self.log,
            FlagStatus::Enabled,
            FlagStatus::Enabled,
        );
        SchedulerTest {
            state: Some(state),
            next_canister_id: 0,
            round: ExecutionRound::new(0),
            initial_canister_cycles: self.initial_canister_cycles,
            user_id: user_test_id(1),
            xnet_canister_id: canister_test_id(first_xnet_canister),
            scheduler,
            wasm_executor,
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
///    modifies one page.
/// - `ingress(5).call(other_side(callee, 3), on_response(8))`: a message
///    that uses 5 instructions and calls a canister with id `callee`.
///    The called message uses 3 instructions. The response handler  uses
///    8 instructions.
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

// A wrapper around the fake Wasm executor.
// This wrapper is needs to guaranteed thread-safety.
struct TestWasmExecutor {
    core: Mutex<TestWasmExecutorCore>,
}

impl TestWasmExecutor {
    fn new() -> Self {
        Self {
            core: Mutex::new(TestWasmExecutorCore::new()),
        }
    }
}

impl WasmExecutor for TestWasmExecutor {
    fn execute(
        self: Arc<Self>,
        input: WasmExecutionInput,
    ) -> (
        Option<CompilationResult>,
        ExecutionState,
        WasmExecutionResult,
    ) {
        let mut guard = self.core.lock().unwrap();
        guard.execute(input)
    }

    fn create_execution_state(
        &self,
        wasm_source: Vec<u8>,
        _canister_root: PathBuf,
        canister_id: CanisterId,
    ) -> HypervisorResult<(CompilationResult, ExecutionState)> {
        let mut guard = self.core.lock().unwrap();
        guard.create_execution_state(wasm_source, canister_id)
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
    next_message_id: u32,
    round: ExecutionRound,
}

impl TestWasmExecutorCore {
    fn new() -> Self {
        Self {
            messages: HashMap::new(),
            next_message_id: 0,
            round: ExecutionRound::new(0),
        }
    }

    // The entry point of the Wasm executor.
    //
    // It finds the test message corresponding to the given input and "executes"
    // it by interpreting its description.
    fn execute(
        &mut self,
        input: WasmExecutionInput,
    ) -> (
        Option<CompilationResult>,
        ExecutionState,
        WasmExecutionResult,
    ) {
        let (_message_id, message, call_context_id) = self.take_message(&input);

        // Generate all the outgoing calls.
        let system_state_changes = self.perform_calls(
            input.sandbox_safe_system_state,
            message.calls,
            call_context_id,
            input.canister_current_memory_usage,
            input.execution_parameters.compute_allocation,
        );

        // TODO(RUN-124): Use `slice_instruction_limit` and support DTS here.
        let instructions_left = input.execution_parameters.total_instruction_limit;
        let instructions_left = instructions_left - message.instructions.min(instructions_left);
        let instance_stats = InstanceStats {
            accessed_pages: message.dirty_pages,
            dirty_pages: message.dirty_pages,
        };
        let output = WasmExecutionOutput {
            wasm_result: Ok(None),
            num_instructions_left: instructions_left,
            instance_stats,
        };
        (
            None,
            input.execution_state,
            WasmExecutionResult::Finished(output, system_state_changes),
        )
    }

    fn create_execution_state(
        &mut self,
        wasm_source: Vec<u8>,
        _canister_id: CanisterId,
    ) -> HypervisorResult<(CompilationResult, ExecutionState)> {
        let execution_state = ExecutionState::new(
            Default::default(),
            execution_state::WasmBinary::new(CanisterModule::new(wasm_source)),
            ExportedFunctions::new([WasmMethod::Update("update".into())].into()),
            Default::default(),
            Default::default(),
            vec![],
            WasmMetadata::default(),
        );
        let compilation_result = CompilationResult {
            largest_function_instruction_count: NumInstructions::from(0),
            compilation_cost: NumInstructions::from(0),
            compilation_time: Duration::default(),
        };
        Ok((compilation_result, execution_state))
    }

    fn perform_calls(
        &mut self,
        mut system_state: SandboxSafeSystemState,
        calls: Vec<TestCall>,
        call_context_id: Option<CallContextId>,
        canister_current_memory_usage: NumBytes,
        compute_allocation: ComputeAllocation,
    ) -> SystemStateChanges {
        for call in calls.into_iter() {
            if let Err(error) = self.perform_call(
                &mut system_state,
                call,
                call_context_id.unwrap(),
                canister_current_memory_usage,
                compute_allocation,
            ) {
                eprintln!("Skipping a call due to an error: {}", error);
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
        compute_allocation: ComputeAllocation,
    ) -> Result<(), String> {
        let sender = system_state.canister_id();
        let receiver = call.other_side.canister.unwrap();
        let call_message_id = self.next_message_id();
        let response_message_id = self.next_message_id();
        let closure = WasmClosure {
            func_idx: 0,
            env: response_message_id,
        };
        let callback = system_state
            .register_callback(Callback {
                call_context_id,
                originator: Some(sender),
                respondent: Some(receiver),
                cycles_sent: Cycles::zero(),
                on_reply: closure.clone(),
                on_reject: closure,
                on_cleanup: None,
            })
            .map_err(|err| err.to_string())?;
        let request = Request {
            receiver,
            sender,
            sender_reply_callback: callback,
            payment: Cycles::zero(),
            method_name: "update".into(),
            method_payload: encode_message_id_as_payload(call_message_id),
        };
        system_state
            .push_output_request(
                canister_current_memory_usage,
                compute_allocation,
                request,
                NumBytes::from(0),
            )
            .map_err(|err| err.0.to_string())?;
        self.messages.insert(call_message_id, call.other_side);
        self.messages.insert(response_message_id, call.on_response);
        Ok(())
    }

    // Returns the test message corresponding to the given input.
    fn take_message(
        &mut self,
        input: &WasmExecutionInput,
    ) -> (u32, TestMessage, Option<CallContextId>) {
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
                    FuncRef::UpdateClosure(closure) | FuncRef::QueryClosure(closure) => closure.env,
                };
                let message = self.messages.remove(&message_id).unwrap();
                (message_id, message, Some(*call_context_id))
            }
            ApiType::Heartbeat { .. } => {
                todo!()
            }
            ApiType::Start => todo!(),
            ApiType::Init { .. } => todo!(),
            ApiType::PreUpgrade { .. } => todo!(),
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::Cleanup { .. } => {
                unreachable!("The test Wasm executor does not support {}", input.api_type)
            }
        }
    }

    fn push_ingress(
        &mut self,
        canister_id: CanisterId,
        canister: &mut CanisterState,
        message: TestMessage,
    ) {
        let ingress_id = self.next_message_id();
        self.messages.insert(ingress_id, message);
        canister.push_ingress(
            SignedIngressBuilder::new()
                .canister_id(canister_id)
                .method_name("update")
                .method_payload(encode_message_id_as_payload(ingress_id))
                .build()
                .into(),
        );
    }

    fn next_message_id(&mut self) -> u32 {
        let result = self.next_message_id;
        self.next_message_id += 1;
        result
    }
}

fn decode_message_id_from_payload(payload: Vec<u8>) -> u32 {
    u32::from_le_bytes(payload.try_into().unwrap())
}

fn encode_message_id_as_payload(message_id: u32) -> Vec<u8> {
    message_id.to_le_bytes().into()
}
