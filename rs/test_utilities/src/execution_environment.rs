use std::collections::HashMap;
use std::sync::Arc;
use std::{collections::BTreeSet, convert::TryFrom};

use ic_base_types::{NumBytes, PrincipalId, SubnetId};
use ic_config::execution_environment::Config;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfigs;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_execution_environment::{
    util::{process_response, process_stopping_canisters},
    CanisterHeartbeatError, ExecutionEnvironment, ExecutionEnvironmentImpl, Hypervisor,
    IngressHistoryWriterImpl,
};
use ic_ic00_types::{
    CanisterIdRecord, CanisterInstallMode, EmptyBlob, InstallCodeArgs, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs, SetControllerArgs,
};
use ic_interfaces::execution_environment::{IngressHistoryWriter, RegistryExecutionSettings};
use ic_interfaces::messages::RequestOrIngress;
use ic_interfaces::{
    execution_environment::{
        AvailableMemory, ExecResult, ExecutionMode, ExecutionParameters, HypervisorError,
        SubnetAvailableMemory,
    },
    messages::CanisterInputMessage,
};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::QUEUE_INDEX_NONE,
    testing::{CanisterQueuesTesting, ReplicatedStateTesting},
    CanisterState, ExecutionState, InputQueueType, ReplicatedState,
};
use ic_types::messages::{MessageId, RequestOrResponse};
use ic_types::Time;
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    CanisterId, Cycles, NumInstructions, UserId,
};
use ic_types_test_utils::ids::{subnet_test_id, user_test_id};
use ic_universal_canister::UNIVERSAL_CANISTER_WASM;
use maplit::btreemap;

use crate::{
    crypto::mock_random_number_generator, cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time, types::messages::IngressBuilder,
};

const INITIAL_CANISTER_CYCLES: Cycles = Cycles::new(1_000_000_000_000);

pub struct ExecutionEnvironmentBuilder {
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    subnet_type: SubnetType,
    log: ReplicaLogger,
    sender_canister_id: Option<CanisterId>,
    ecdsa_signature_fee: Option<Cycles>,
}

impl Default for ExecutionEnvironmentBuilder {
    fn default() -> Self {
        Self {
            nns_subnet_id: subnet_test_id(2),
            own_subnet_id: subnet_test_id(1),
            sender_subnet_id: subnet_test_id(1),
            subnet_type: SubnetType::Application,
            log: no_op_logger(),
            sender_canister_id: None,
            ecdsa_signature_fee: None,
        }
    }
}

impl ExecutionEnvironmentBuilder {
    /// By default, this subnet id and the sender subnet id are
    /// `subnet_test_id(1)`, while the nns is `subnet_test_id(2)`.
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

    pub fn with_sender_subnet_id(self, sender_subnet_id: SubnetId) -> Self {
        Self {
            sender_subnet_id,
            ..self
        }
    }

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        Self {
            subnet_type,
            ..self
        }
    }

    pub fn with_log(self, log: ReplicaLogger) -> Self {
        Self { log, ..self }
    }

    pub fn with_sender_canister(self, sender_canister: CanisterId) -> Self {
        Self {
            sender_canister_id: Some(sender_canister),
            ..self
        }
    }

    pub fn with_ecdsa_signature_fee(self, ecdsa_signing_fee: Cycles) -> Self {
        Self {
            ecdsa_signature_fee: Some(ecdsa_signing_fee),
            ..self
        }
    }

    pub fn build(self) -> (ReplicatedState, ExecutionEnvironmentImpl) {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let own_range = CanisterIdRange {
            start: CanisterId::from(0x100),
            end: CanisterId::from(0x1ff),
        };
        let routing_table = Arc::new(match self.sender_canister_id {
            None => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => self.sender_subnet_id,
                own_range => self.own_subnet_id,
            }).unwrap(),
            Some(sender_canister) => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: sender_canister, end: sender_canister } => self.sender_subnet_id,
                own_range => self.own_subnet_id,
            }).unwrap_or_else(|_| panic!("Unable to create routing table - sender canister {} is in the range {:?}", sender_canister, own_range)),
        });

        let mut state = ReplicatedState::new_rooted_at(
            self.own_subnet_id,
            self.subnet_type,
            tmpdir.path().to_path_buf(),
        );
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = self.nns_subnet_id;

        let metrics_registry = MetricsRegistry::new();

        let mut cycles_account_manager_builder =
            CyclesAccountManagerBuilder::new().with_subnet_type(self.subnet_type);
        if let Some(ecdsa_signature_fee) = self.ecdsa_signature_fee {
            cycles_account_manager_builder =
                cycles_account_manager_builder.with_ecdsa_signature_fee(ecdsa_signature_fee);
        }
        let cycles_account_manager = Arc::new(cycles_account_manager_builder.build());

        let hypervisor = Hypervisor::new(
            Config::default(),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            self.log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer =
            IngressHistoryWriterImpl::new(Config::default(), self.log.clone(), &metrics_registry);
        let ingress_history_writer = Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironmentImpl::new(
            self.log,
            hypervisor,
            ingress_history_writer,
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            1,
            Config::default(),
            cycles_account_manager,
        );
        (state, exec_env)
    }
}

/// A helper for execution tests.
///
/// Example usage:
/// ```
/// use ic_test_utilities::execution_environment::{*};
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
    instruction_limit: NumInstructions,
    install_code_instruction_limit: NumInstructions,
    initial_canister_cycles: Cycles,
    registry_settings: RegistryExecutionSettings,
    manual_execution: bool,

    // The actual implementation.
    exec_env: ExecutionEnvironmentImpl,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics_registry: MetricsRegistry,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
}

impl ExecutionTest {
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

    pub fn lost_messages(&self) -> &Vec<RequestOrResponse> {
        &self.lost_messages
    }

    pub fn executed_instructions(&self) -> NumInstructions {
        self.executed_instructions.values().sum()
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

    pub fn idle_cycles_burned_per_second(&self, canister_id: CanisterId) -> Cycles {
        let memory_usage = self.execution_state(canister_id).memory_usage();
        let memory_allocation = self
            .canister_state(canister_id)
            .system_state
            .memory_allocation;
        let compute_allocation = self
            .canister_state(canister_id)
            .scheduler_state
            .compute_allocation;
        self.cycles_account_manager.idle_cycles_burned_rate(
            memory_allocation,
            memory_usage,
            compute_allocation,
        )
    }

    pub fn call_fee<S: ToString>(&self, method_name: S, payload: &[u8]) -> Cycles {
        self.cycles_account_manager.xnet_call_performed_fee()
            + self
                .cycles_account_manager
                .xnet_call_bytes_transmitted_fee(NumBytes::from(
                    (payload.len() + method_name.to_string().len()) as u64,
                ))
    }

    pub fn reply_fee(&self, payload: &[u8]) -> Cycles {
        self.cycles_account_manager
            .xnet_call_bytes_transmitted_fee(NumBytes::from(payload.len() as u64))
    }

    pub fn reject_fee<S: ToString>(&self, reject_message: S) -> Cycles {
        let bytes = reject_message.to_string().len() + std::mem::size_of::<RejectCode>();
        self.cycles_account_manager
            .xnet_call_bytes_transmitted_fee(NumBytes::from(bytes as u64))
    }

    pub fn subnet_available_memory(&self) -> AvailableMemory {
        self.subnet_available_memory.get()
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

    pub fn ingress_status(&self, message_id: MessageId) -> IngressStatus {
        self.state().get_ingress_status(&message_id)
    }

    /// Sends a `create_canister` message to the IC management canister.
    /// Consider using higher-level helpers like `canister_from_wat()`.
    pub fn create_canister(&mut self, cycles: Cycles) -> CanisterId {
        let args = ProvisionalCreateCanisterWithCyclesArgs::new(Some(cycles.get()));
        let result =
            self.subnet_message(Method::ProvisionalCreateCanisterWithCycles, args.encode());
        CanisterIdRecord::decode(&get_reply(result))
            .unwrap()
            .get_canister_id()
    }

    /// Sends an `install_code` message to the IC management canister.
    /// Consider using higher-level helpers like `canister_from_wat()`.
    pub fn install_code(&mut self, args: InstallCodeArgs) -> Result<WasmResult, UserError> {
        self.subnet_message(Method::InstallCode, args.encode())
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
        self.subnet_message_raw(Method::StopCanister, payload)
    }

    /// Stops stopping canisters that no longer have open call contexts.
    pub fn process_stopping_canisters(&mut self) {
        let state = self.state.take().unwrap();
        let own_subnet_id = state.metadata.own_subnet_id;
        let state =
            process_stopping_canisters(state, self.ingress_history_writer.as_ref(), own_subnet_id);
        self.state = Some(state);
    }

    /// Returns the canister status by canister id.
    pub fn canister_status(&mut self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        let payload = CanisterIdRecord::from(canister_id).encode();
        self.subnet_message(Method::CanisterStatus, payload)
    }

    /// Sets the controller of the canister to the given principal.
    pub fn set_controller(
        &mut self,
        canister_id: CanisterId,
        controller: PrincipalId,
    ) -> Result<WasmResult, UserError> {
        let payload = SetControllerArgs::new(canister_id, controller).encode();
        self.subnet_message(Method::SetController, payload)
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
            None,
        );
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob::encode()), result);
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
            None,
        );
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob::encode()), result);
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
            None,
        );
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob::encode()), result);
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
            None,
        );
        let result = self.install_code(args)?;
        assert_eq!(WasmResult::Reply(EmptyBlob::encode()), result);
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
        let mut features = wabt::Features::new();
        features.enable_bulk_memory();
        self.canister_from_cycles_and_binary(
            initial_cycles,
            wabt::wat2wasm_with_features(wat.to_string(), features).unwrap(),
        )
    }

    /// Creates a canister and installs the Wasm binary.
    pub fn canister_from_binary(&mut self, wasm_binary: Vec<u8>) -> Result<CanisterId, UserError> {
        self.canister_from_cycles_and_binary(self.initial_canister_cycles, wasm_binary)
    }

    // Creates a canister and installs the Wasm module given in the textual
    // representation.
    pub fn canister_from_wat<S: ToString>(&mut self, wat: S) -> Result<CanisterId, UserError> {
        self.canister_from_cycles_and_wat(self.initial_canister_cycles, wat)
    }

    // Creates and installs a universal canister.
    pub fn universal_canister(&mut self) -> Result<CanisterId, UserError> {
        self.canister_from_binary(UNIVERSAL_CANISTER_WASM.to_vec())
    }

    // Creates and installs a universal canister with cycles
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
        (ingress_id.clone(), self.ingress_status(ingress_id))
    }

    /// Executes the heartbeat method of the given canister.
    pub fn heartbeat(&mut self, canister_id: CanisterId) -> Result<(), CanisterHeartbeatError> {
        let mut state = self.state.take().unwrap();
        let canister = state.take_canister_state(&canister_id).unwrap();
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let (canister, num_instructions_left, result) = self.exec_env.execute_canister_heartbeat(
            canister,
            self.instruction_limit,
            network_topology,
            self.time,
            self.subnet_available_memory.clone(),
        );
        state.put_canister_state(canister);
        if let Ok(heap_delta) = result {
            state.metadata.heap_delta_estimate += heap_delta;
        }
        self.state = Some(state);
        self.update_execution_stats(canister_id, self.instruction_limit, num_instructions_left);
        result?;
        Ok(())
    }

    /// Executes an anonymous query in the given canister.
    pub fn anonymous_query<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<Option<WasmResult>, HypervisorError> {
        let mut state = self.state.take().unwrap();
        let canister = state.take_canister_state(&canister_id).unwrap();
        let execution_parameters = ExecutionParameters {
            total_instruction_limit: self.instruction_limit,
            slice_instruction_limit: self.instruction_limit,
            canister_memory_limit: canister.memory_limit(NumBytes::new(u64::MAX / 2)),
            subnet_available_memory: self.subnet_available_memory.clone(),
            compute_allocation: canister.scheduler_state.compute_allocation,
            subnet_type: state.metadata.own_subnet_type,
            execution_mode: ExecutionMode::NonReplicated,
        };
        let (canister, _, result) = self
            .exec_env
            .hypervisor_for_testing()
            .execute_anonymous_query(
                self.time,
                &method_name.to_string(),
                method_payload.as_slice(),
                canister,
                None,
                execution_parameters,
                &Default::default(),
            );
        state.put_canister_state(canister);
        self.state = Some(state);
        result
    }

    // A low-level helper to send subnet messages to the IC management canister.
    pub fn subnet_message<S: ToString>(
        &mut self,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let ingress_id = self.subnet_message_raw(method_name, method_payload);
        check_ingress_status(self.ingress_status(ingress_id))
    }

    // A low-level helper to send subnet messages to the IC management canister.
    fn subnet_message_raw<S: ToString>(
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

        self.execute_subnet_message();

        message_id
    }

    // Executes a single subnet message from the subnet input queue.
    // Return a progress flag indicating if the message was executed or not.
    fn execute_subnet_message(&mut self) -> bool {
        let mut state = self.state.take().unwrap();
        let message = match state.pop_subnet_input() {
            Some(message) => message,
            None => {
                self.state = Some(state);
                return false;
            }
        };
        let maybe_canister_id = get_canister_id_if_install_code(message.clone());
        let (new_state, instructions_left) = self.exec_env.execute_subnet_message(
            message,
            state,
            self.install_code_instruction_limit,
            &mut mock_random_number_generator(),
            &None,
            self.subnet_available_memory.clone(),
            &self.registry_settings,
        );
        self.state = Some(new_state);
        if let Some(canister_id) = maybe_canister_id {
            self.update_execution_stats(
                canister_id,
                self.install_code_instruction_limit,
                instructions_left,
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
        let mut canisters = state.take_canister_states();
        let canister_ids: Vec<CanisterId> = canisters.keys().copied().collect();
        for canister_id in canister_ids {
            let network_topology = Arc::new(state.metadata.network_topology.clone());
            let mut canister = canisters.remove(&canister_id).unwrap();
            while canister.has_input() {
                let message = canister.pop_input().unwrap();
                let result = self.exec_env.execute_canister_message(
                    canister,
                    self.instruction_limit,
                    message,
                    self.time,
                    Arc::clone(&network_topology),
                    self.subnet_available_memory.clone(),
                );
                let result = process_response(result);
                state.metadata.heap_delta_estimate += result.heap_delta;
                self.update_execution_stats(
                    canister_id,
                    self.instruction_limit,
                    result.num_instructions_left,
                );
                canister = result.canister;
                if let ExecResult::IngressResult(ir) = result.result {
                    self.ingress_history_writer
                        .set_status(&mut state, ir.0, ir.1);
                };
                executed_any = true;
            }
            canisters.insert(canister_id, canister);
        }
        state.put_canister_states(canisters);
        self.state = Some(state);
        executed_any
    }

    /// Executes a pending message of the given canister.
    pub fn execute_message(&mut self, canister_id: CanisterId) {
        let mut state = self.state.take().unwrap();
        let mut canisters = state.take_canister_states();
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let mut canister = canisters.remove(&canister_id).unwrap();
        if canister.has_input() {
            let message = canister.pop_input().unwrap();
            let result = self.exec_env.execute_canister_message(
                canister,
                self.instruction_limit,
                message,
                self.time,
                Arc::clone(&network_topology),
                self.subnet_available_memory.clone(),
            );
            let result = process_response(result);
            state.metadata.heap_delta_estimate += result.heap_delta;
            self.update_execution_stats(
                canister_id,
                self.instruction_limit,
                result.num_instructions_left,
            );
            canister = result.canister;
            if let ExecResult::IngressResult(ir) = result.result {
                self.ingress_history_writer
                    .set_status(&mut state, ir.0, ir.1);
            };
        }
        canisters.insert(canister_id, canister);
        state.put_canister_states(canisters);
        self.state = Some(state);
    }

    // Increments the executed instructions and the execution cost counters.
    fn update_execution_stats(
        &mut self,
        canister_id: CanisterId,
        limit: NumInstructions,
        left: NumInstructions,
    ) {
        let mgr = &self.cycles_account_manager;
        *self
            .executed_instructions
            .entry(canister_id)
            .or_insert(NumInstructions::new(0)) += limit - left;
        // Ideally we would simply add `execution_cost(limit - left)`
        // but that leads to small precision errors because 1 Cycle = 0.4 Instructions.
        let fixed_cost = mgr.execution_cost(NumInstructions::from(0));
        let instruction_cost = mgr.execution_cost(limit) - mgr.execution_cost(left);
        *self
            .execution_cost
            .entry(canister_id)
            .or_insert(Cycles::new(0)) += instruction_cost + fixed_cost;
    }

    /// Inducts messages between canisters and pushes all cross-net messages to
    /// `self.xnet_messages`.
    pub fn induct_messages(&mut self) {
        let mut state = self.state.take().unwrap();
        let mut subnet_available_memory = self.subnet_available_memory.get().get_total_memory();
        let max_canister_memory_size = self.exec_env.max_canister_memory_size();
        let output_messages = get_output_messages(&mut state);
        let mut canisters = state.take_canister_states();
        for (canister_id, message) in output_messages {
            match canisters.get_mut(&canister_id) {
                Some(dest_canister) => {
                    let result = dest_canister.push_input(
                        QUEUE_INDEX_NONE,
                        message.clone(),
                        max_canister_memory_size,
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
                            .push_input(QUEUE_INDEX_NONE, message, InputQueueType::LocalSubnet)
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

    /// A low-level helper to generate the next message id.
    fn next_message_id(&mut self) -> MessageId {
        let message_id = self.message_id;
        self.message_id += 1;
        MessageId::try_from(&[&[0; 24][..], &message_id.to_be_bytes()[..]].concat()[..]).unwrap()
    }
}

/// A builder for `ExecutionTest`.
pub struct ExecutionTestBuilder {
    nns_subnet_id: SubnetId,
    own_subnet_id: SubnetId,
    sender_subnet_id: SubnetId,
    subnet_type: SubnetType,
    log: ReplicaLogger,
    sender_canister_id: Option<CanisterId>,
    ecdsa_signature_fee: Option<Cycles>,
    instruction_limit: NumInstructions,
    install_code_instruction_limit: NumInstructions,
    initial_canister_cycles: Cycles,
    subnet_total_memory: i64,
    subnet_message_memory: i64,
    registry_settings: RegistryExecutionSettings,
    manual_execution: bool,
}

impl Default for ExecutionTestBuilder {
    fn default() -> Self {
        let subnet_type = SubnetType::Application;
        let config = SubnetConfigs::default()
            .own_subnet_config(subnet_type)
            .scheduler_config;
        let subnet_total_memory = ic_config::execution_environment::Config::default()
            .subnet_memory_capacity
            .get() as i64;
        Self {
            nns_subnet_id: subnet_test_id(2),
            own_subnet_id: subnet_test_id(1),
            sender_subnet_id: subnet_test_id(1),
            subnet_type,
            log: no_op_logger(),
            sender_canister_id: None,
            ecdsa_signature_fee: None,
            instruction_limit: config.max_instructions_per_message,
            install_code_instruction_limit: config.max_instructions_per_install_code,
            initial_canister_cycles: INITIAL_CANISTER_CYCLES,
            subnet_total_memory,
            subnet_message_memory: subnet_total_memory,
            registry_settings: test_registry_settings(),
            manual_execution: false,
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

    pub fn with_sender_subnet_id(self, sender_subnet_id: SubnetId) -> Self {
        Self {
            sender_subnet_id,
            ..self
        }
    }

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        Self {
            subnet_type,
            ..self
        }
    }

    pub fn with_log(self, log: ReplicaLogger) -> Self {
        Self { log, ..self }
    }

    pub fn with_sender_canister(self, sender_canister: CanisterId) -> Self {
        Self {
            sender_canister_id: Some(sender_canister),
            ..self
        }
    }

    pub fn with_ecdsa_signature_fee(self, ecdsa_signing_fee: Cycles) -> Self {
        Self {
            ecdsa_signature_fee: Some(ecdsa_signing_fee),
            ..self
        }
    }

    pub fn with_instruction_limit(self, instruction_limit: u64) -> Self {
        Self {
            instruction_limit: NumInstructions::from(instruction_limit),
            ..self
        }
    }

    pub fn with_install_code_instruction_limit(self, install_code_instruction_limit: u64) -> Self {
        Self {
            install_code_instruction_limit: NumInstructions::from(install_code_instruction_limit),
            ..self
        }
    }

    pub fn with_initial_canister_cycles(self, initial_canister_cycles: u128) -> Self {
        Self {
            initial_canister_cycles: Cycles::new(initial_canister_cycles),
            ..self
        }
    }

    pub fn with_subnet_total_memory(self, subnet_total_memory: i64) -> Self {
        Self {
            subnet_total_memory,
            ..self
        }
    }

    pub fn with_subnet_message_memory(self, subnet_message_memory: i64) -> Self {
        Self {
            subnet_message_memory,
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

    pub fn build(self) -> ExecutionTest {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();

        let own_range = CanisterIdRange {
            start: CanisterId::from(0x100),
            end: CanisterId::from(0x1ff),
        };
        let routing_table = Arc::new(match self.sender_canister_id {
            None => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => self.sender_subnet_id,
                own_range => self.own_subnet_id,
            }).unwrap(),
            Some(sender_canister) => RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: sender_canister, end: sender_canister } => self.sender_subnet_id,
                own_range => self.own_subnet_id,
            }).unwrap_or_else(|_| panic!("Unable to create routing table - sender canister {} is in the range {:?}", sender_canister, own_range)),
        });

        let mut state = ReplicatedState::new_rooted_at(
            self.own_subnet_id,
            self.subnet_type,
            tmpdir.path().to_path_buf(),
        );
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = self.nns_subnet_id;

        let metrics_registry = MetricsRegistry::new();

        let mut config = SubnetConfigs::default()
            .own_subnet_config(self.subnet_type)
            .cycles_account_manager_config;
        if let Some(ecdsa_signature_fee) = self.ecdsa_signature_fee {
            config.ecdsa_signature_fee = ecdsa_signature_fee;
        }
        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            self.instruction_limit,
            self.subnet_type,
            self.own_subnet_id,
            config,
        ));
        let config = Config {
            rate_limiting_of_instructions: FlagStatus::Disabled,
            ..Config::default()
        };
        let hypervisor = Hypervisor::new(
            config.clone(),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            self.log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer =
            IngressHistoryWriterImpl::new(config.clone(), self.log.clone(), &metrics_registry);
        let ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>> =
            Arc::new(ingress_history_writer);
        let exec_env = ExecutionEnvironmentImpl::new(
            self.log,
            hypervisor,
            Arc::clone(&ingress_history_writer),
            &metrics_registry,
            self.own_subnet_id,
            self.subnet_type,
            1,
            config,
            Arc::clone(&cycles_account_manager),
        );
        ExecutionTest {
            state: Some(state),
            message_id: 0,
            executed_instructions: HashMap::new(),
            execution_cost: HashMap::new(),
            xnet_messages: vec![],
            lost_messages: vec![],
            subnet_available_memory: SubnetAvailableMemory::from(AvailableMemory::new(
                self.subnet_total_memory,
                self.subnet_message_memory,
            )),
            time: mock_time(),
            instruction_limit: self.instruction_limit,
            install_code_instruction_limit: self.install_code_instruction_limit,
            initial_canister_cycles: self.initial_canister_cycles,
            registry_settings: self.registry_settings,
            user_id: user_test_id(1),
            exec_env,
            cycles_account_manager,
            metrics_registry,
            ingress_history_writer,
            manual_execution: self.manual_execution,
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

pub fn test_registry_settings() -> RegistryExecutionSettings {
    RegistryExecutionSettings {
        max_number_of_canisters: 1_000,
        provisional_whitelist: ProvisionalWhitelist::Set(BTreeSet::new()),
    }
}

fn get_output_messages(state: &mut ReplicatedState) -> Vec<(CanisterId, RequestOrResponse)> {
    let mut output: Vec<(CanisterId, RequestOrResponse)> = vec![];
    let output_iter = state.output_into_iter();

    for (queue_id, _, msg) in output_iter {
        let canister_id = CanisterId::try_from(queue_id.dst_canister.get()).unwrap();
        output.push((canister_id, msg));
    }
    output
}

fn get_canister_id_if_install_code(message: CanisterInputMessage) -> Option<CanisterId> {
    let message = match message {
        CanisterInputMessage::Response(_) => return None,
        CanisterInputMessage::Request(request) => RequestOrIngress::Request(request),
        CanisterInputMessage::Ingress(ingress) => RequestOrIngress::Ingress(ingress),
    };
    if message.method_name() != "install_code" {
        return None;
    }
    match InstallCodeArgs::decode(message.method_payload()) {
        Err(_) => None,
        Ok(args) => Some(CanisterId::try_from(args.canister_id).unwrap()),
    }
}
