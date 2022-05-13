use std::sync::Arc;
use std::{collections::BTreeSet, convert::TryFrom};

use ic_base_types::{NumBytes, SubnetId};
use ic_config::execution_environment::Config;
use ic_config::subnet_config::SubnetConfigs;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_execution_environment::{
    CanisterHeartbeatError, ExecutionEnvironment, ExecutionEnvironmentImpl, Hypervisor,
    IngressHistoryWriterImpl,
};
use ic_ic00_types::{
    CanisterIdRecord, CanisterInstallMode, EmptyBlob, InstallCodeArgs, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs,
};
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
use ic_replicated_state::{CanisterState, ExecutionState, ReplicatedState};
use ic_types::messages::MessageId;
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    CanisterId, Cycles, NumInstructions, UserId,
};
use ic_types_test_utils::ids::{subnet_test_id, user_test_id};
use maplit::btreemap;

use crate::{
    crypto::mock_random_number_generator, cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time, types::messages::IngressBuilder,
};

const INITIAL_CANISTER_CYCLES: Cycles = Cycles::new(1_000_000_000_000);
const MAX_NUMBER_OF_CANISTERS: u64 = 1000;

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
    // The number of instructions executed so far.
    executed_instructions: NumInstructions,
    // The number of heap delta bytes produced so far.
    produced_heap_delta: NumBytes,

    // Read-only fields.
    instruction_limit: NumInstructions,
    install_code_instruction_limit: NumInstructions,
    initial_canister_cycles: Cycles,
    max_number_of_canisters: u64,
    user_id: UserId,

    // The actual implementation.
    exec_env: ExecutionEnvironmentImpl,
    cycles_account_manager: Arc<CyclesAccountManager>,
}

impl ExecutionTest {
    pub fn state(&self) -> &ReplicatedState {
        self.state.as_ref().unwrap()
    }

    pub fn canister_state(&self, canister_id: CanisterId) -> &CanisterState {
        self.state().canister_state(&canister_id).unwrap()
    }

    pub fn execution_state(&self, canister_id: CanisterId) -> &ExecutionState {
        self.canister_state(canister_id)
            .execution_state
            .as_ref()
            .unwrap()
    }

    pub fn executed_instructions(&self) -> NumInstructions {
        self.executed_instructions
    }

    pub fn produced_heap_delta(&self) -> NumBytes {
        self.produced_heap_delta
    }

    /// Sends a `create_canister` message to the IC management canister.
    /// Consider using higher-level helpers like `canister_from_wat()`.
    pub fn create_canister(&mut self, initial_cycles: Cycles) -> CanisterId {
        let cycles = initial_cycles + self.cycles_account_manager.canister_creation_fee();
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

    /// Starts running the given canister.
    /// Consider using higher-level helpers like `canister_from_wat()`.
    pub fn start_canister(&mut self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        let payload = CanisterIdRecord::from(canister_id).encode();
        self.subnet_message(Method::StartCanister, payload)
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

    /// Sends an ingress message to the given canister to call an update or a
    /// query method. In the latter case the query runs in update context.
    pub fn ingress<S: ToString>(
        &mut self,
        canister_id: CanisterId,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let mut state = self.state.take().unwrap();
        let message_id = self.next_message_id();
        let canister = state.take_canister_state(&canister_id).unwrap();
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let exec_result = self.exec_env.execute_canister_message(
            canister,
            self.instruction_limit,
            CanisterInputMessage::Ingress(
                IngressBuilder::new()
                    .message_id(message_id)
                    .source(self.user_id)
                    .receiver(canister_id)
                    .method_name(method_name)
                    .method_payload(method_payload)
                    .build(),
            ),
            mock_time(),
            network_topology,
            self.subnet_available_memory.clone(),
        );
        state.put_canister_state(exec_result.canister);
        self.state = Some(state);
        self.executed_instructions += self.instruction_limit - exec_result.num_instructions_left;
        self.produced_heap_delta += exec_result.heap_delta;
        let ingress_status = match exec_result.result {
            ExecResult::ResponseResult(_) | ExecResult::Empty => {
                unreachable!("Unexpected execution result {:?}", exec_result.result)
            }
            ExecResult::IngressResult((_, ingress_status)) => ingress_status,
        };
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

    /// Executes the heartbeat method of the given canister.
    pub fn heartbeat(&mut self, canister_id: CanisterId) -> Result<(), CanisterHeartbeatError> {
        let mut state = self.state.take().unwrap();
        let canister = state.take_canister_state(&canister_id).unwrap();
        let network_topology = Arc::new(state.metadata.network_topology.clone());
        let (canister, num_instructions_left, result) = self.exec_env.execute_canister_heartbeat(
            canister,
            self.instruction_limit,
            network_topology,
            mock_time(),
            self.subnet_available_memory.clone(),
        );
        state.put_canister_state(canister);
        self.state = Some(state);
        self.executed_instructions += self.instruction_limit - num_instructions_left;
        match result {
            Ok(heap_delta) => {
                self.produced_heap_delta += heap_delta;
                Ok(())
            }
            Err(err) => Err(err),
        }
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
        let (canister, num_instructions_left, result) = self
            .exec_env
            .hypervisor_for_testing()
            .execute_anonymous_query(
                mock_time(),
                &method_name.to_string(),
                method_payload.as_slice(),
                canister,
                None,
                execution_parameters,
            );
        state.put_canister_state(canister);
        self.state = Some(state);
        self.executed_instructions += self.instruction_limit - num_instructions_left;
        result
    }

    // A low-level helper to send subnet messages to the IC management canister.
    fn subnet_message<S: ToString>(
        &mut self,
        method_name: S,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let state = self.state.take().unwrap();

        let message_id = self.next_message_id();

        let mut provisional_whitelist = BTreeSet::new();
        provisional_whitelist.insert(self.user_id.get());

        let (new_state, instructions_left) = self.exec_env.execute_subnet_message(
            CanisterInputMessage::Ingress(
                IngressBuilder::new()
                    .message_id(message_id.clone())
                    .source(self.user_id)
                    .receiver(CanisterId::ic_00())
                    .method_name(method_name)
                    .method_payload(method_payload)
                    .build(),
            ),
            state,
            self.install_code_instruction_limit,
            &mut mock_random_number_generator(),
            &None,
            &ProvisionalWhitelist::Set(provisional_whitelist),
            self.subnet_available_memory.clone(),
            self.max_number_of_canisters,
        );
        let ingress_status = new_state.get_ingress_status(&message_id);
        self.state = Some(new_state);
        self.executed_instructions += self.install_code_instruction_limit - instructions_left;
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
    subnet_available_memory: i64,
    max_number_of_canisters: u64,
}

impl Default for ExecutionTestBuilder {
    fn default() -> Self {
        let subnet_type = SubnetType::Application;
        let config = SubnetConfigs::default()
            .own_subnet_config(subnet_type)
            .scheduler_config;
        let subnet_available_memory = ic_config::execution_environment::Config::default()
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
            subnet_available_memory,
            max_number_of_canisters: MAX_NUMBER_OF_CANISTERS,
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

    pub fn with_subnet_available_memory(self, subnet_available_memory: i64) -> Self {
        Self {
            subnet_available_memory,
            ..self
        }
    }

    pub fn with_max_number_of_canisters(self, max_number_of_canisters: u64) -> Self {
        Self {
            max_number_of_canisters,
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
            Arc::clone(&cycles_account_manager),
        );
        ExecutionTest {
            state: Some(state),
            message_id: 0,
            executed_instructions: NumInstructions::from(0),
            produced_heap_delta: NumBytes::from(0),
            subnet_available_memory: SubnetAvailableMemory::from(AvailableMemory::new(
                self.subnet_available_memory,
                self.subnet_available_memory,
            )),
            instruction_limit: self.instruction_limit,
            install_code_instruction_limit: self.install_code_instruction_limit,
            initial_canister_cycles: self.initial_canister_cycles,
            max_number_of_canisters: self.max_number_of_canisters,
            user_id: user_test_id(1),
            exec_env,
            cycles_account_manager,
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
