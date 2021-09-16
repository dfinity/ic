mod request_in_prep;
mod system_state_accessor;
mod system_state_accessor_direct;

use ic_ic00_types::IC_00;
use ic_interfaces::execution_environment::{
    ExecutionParameters,
    HypervisorError::{self, *},
    HypervisorResult, SubnetAvailableMemory, SystemApi,
    TrapCode::CyclesAmountTooBigFor64Bit,
};
use ic_logger::{error, ReplicaLogger};
use ic_registry_routing_table::{resolve_destination, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::system_state::CanisterStatus, page_map::PAGE_SIZE, NumWasmPages64, StateError,
};
use ic_types::{
    ingress::WasmResult,
    messages::{CallContextId, RejectContext, Request, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES},
    methods::{Callback, WasmClosure},
    user_error::RejectCode,
    CanisterId, Cycles, NumBytes, NumInstructions, PrincipalId, SubnetId, Time,
};
use request_in_prep::{into_request, RequestInPrep};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    convert::{From, TryFrom},
    sync::Arc,
};
pub use system_state_accessor::SystemStateAccessor;
pub use system_state_accessor_direct::SystemStateAccessorDirect;

const MULTIPLIER_MAX_SIZE_INTRA_SUBNET: u64 = 5;
const MAX_NON_REPLICATED_QUERY_REPLY_SIZE: NumBytes = NumBytes::new(3 << 20);

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum ResponseStatus {
    // Indicates that the current call context was never replied.
    NotRepliedYet,
    // Indicates that the current call context was replied in one of other
    // executions belonging to this call context (other callbacks, e.g.).
    AlreadyReplied,
    // Contains the response assigned during the current execution.
    JustRepliedWith(Option<WasmResult>),
}

/// This enum indicates whether execution of a non-replicated query
/// should keep track of the state or not. The distinction is necessary
/// because some non-replicated queries can call other queries. In such
/// a case the caller has too keep the state until the callee returns.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum NonReplicatedQueryKind {
    Stateful,
    Pure,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
pub enum ApiType {
    // For executing the `canister_start` method
    Start,

    // For executing the `canister_init` method
    Init {
        time: Time,
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
    },

    // For executing canister methods marked as `update`
    Update {
        time: Time,
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        caller: PrincipalId,
        call_context_id: CallContextId,
        // Begins as empty and used to accumulate data for sending replies.
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
    },

    // For executing canister methods marked as `query`
    ReplicatedQuery {
        time: Time,
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        data_certificate: Option<Vec<u8>>,
        max_reply_size: NumBytes,
    },

    NonReplicatedQuery {
        time: Time,
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
        call_context_id: CallContextId,
        data_certificate: Option<Vec<u8>>,
        own_subnet_id: SubnetId,
        routing_table: Arc<RoutingTable>,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        // Begins as empty and used to accumulate data for sending replies.
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        max_reply_size: NumBytes,
        query_kind: NonReplicatedQueryKind,
    },

    // For executing closures when a `Reply` is received
    ReplyCallback {
        time: Time,
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        // Begins as empty and used to accumulate data for sending replies.
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
    },

    // For executing closures when a `Reject` is received
    RejectCallback {
        time: Time,
        reject_context: RejectContext,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        // Begins as empty and used to accumulate data for sending replies.
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
    },

    PreUpgrade {
        caller: PrincipalId,
        time: Time,
    },

    /// For executing canister_inspect_message method that allows the canister
    /// to decide pre-consensus if it actually wants to accept the message or
    /// not.
    InspectMessage {
        caller: PrincipalId,
        method_name: String,
        incoming_payload: Vec<u8>,
        time: Time,
        message_accepted: bool,
    },

    // For executing the `canister_heartbeat` method
    Heartbeat {
        time: Time,
        call_context_id: CallContextId,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
    },

    /// For executing the `call_on_cleanup` callback.
    ///
    /// The `call_on_cleanup` callback is executed iff the `reply` or the
    /// `reject` callback was executed and trapped (for any reason).
    ///
    /// See https://sdk.dfinity.org/docs/interface-spec/index.html#system-api-call
    Cleanup {
        time: Time,
    },
}

impl ApiType {
    pub fn start() -> Self {
        Self::Start {}
    }

    pub fn init(time: Time, incoming_payload: Vec<u8>, caller: PrincipalId) -> Self {
        Self::Init {
            time,
            incoming_payload,
            caller,
        }
    }

    pub fn heartbeat(
        time: Time,
        call_context_id: CallContextId,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    ) -> Self {
        Self::Heartbeat {
            time,
            call_context_id,
            own_subnet_id,
            own_subnet_type,
            routing_table,
            subnet_records,
            outgoing_request: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update(
        time: Time,
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        caller: PrincipalId,
        call_context_id: CallContextId,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    ) -> Self {
        Self::Update {
            time,
            incoming_payload,
            incoming_cycles,
            caller,
            call_context_id,
            response_data: vec![],
            response_status: ResponseStatus::NotRepliedYet,
            own_subnet_id,
            own_subnet_type,
            routing_table,
            subnet_records,
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        }
    }

    pub fn replicated_query(
        time: Time,
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
        data_certificate: Option<Vec<u8>>,
    ) -> Self {
        Self::ReplicatedQuery {
            time,
            incoming_payload,
            caller,
            response_data: vec![],
            response_status: ResponseStatus::NotRepliedYet,
            data_certificate,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn non_replicated_query(
        time: Time,
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
        call_context_id: CallContextId,
        own_subnet_id: SubnetId,
        routing_table: Arc<RoutingTable>,
        data_certificate: Option<Vec<u8>>,
        query_kind: NonReplicatedQueryKind,
    ) -> Self {
        Self::NonReplicatedQuery {
            time,
            incoming_payload,
            caller,
            call_context_id,
            own_subnet_id,
            routing_table,
            data_certificate,
            outgoing_request: None,
            response_data: vec![],
            response_status: ResponseStatus::NotRepliedYet,
            max_reply_size: MAX_NON_REPLICATED_QUERY_REPLY_SIZE,
            query_kind,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reply_callback(
        time: Time,
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        replied: bool,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    ) -> Self {
        Self::ReplyCallback {
            time,
            incoming_payload,
            incoming_cycles,
            call_context_id,
            response_data: vec![],
            response_status: if replied {
                ResponseStatus::AlreadyReplied
            } else {
                ResponseStatus::NotRepliedYet
            },
            own_subnet_id,
            own_subnet_type,
            routing_table,
            subnet_records,
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reject_callback(
        time: Time,
        reject_context: RejectContext,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        replied: bool,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    ) -> Self {
        Self::RejectCallback {
            time,
            reject_context,
            incoming_cycles,
            call_context_id,
            response_data: vec![],
            response_status: if replied {
                ResponseStatus::AlreadyReplied
            } else {
                ResponseStatus::NotRepliedYet
            },
            own_subnet_id,
            own_subnet_type,
            routing_table,
            subnet_records,
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        }
    }

    pub fn pre_upgrade(time: Time, caller: PrincipalId) -> Self {
        Self::PreUpgrade { time, caller }
    }

    pub fn inspect_message(
        caller: PrincipalId,
        method_name: String,
        incoming_payload: Vec<u8>,
        time: Time,
    ) -> Self {
        Self::InspectMessage {
            caller,
            method_name,
            incoming_payload,
            time,
            message_accepted: false,
        }
    }

    /// Returns a string slice representation of the enum variant name for use
    /// e.g. as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiType::Start { .. } => "start",
            ApiType::Init { .. } => "init",
            ApiType::Heartbeat { .. } => "heartbeat",
            ApiType::Update { .. } => "update",
            ApiType::ReplicatedQuery { .. } => "replicated query",
            ApiType::NonReplicatedQuery { .. } => "non replicated query",
            ApiType::ReplyCallback { .. } => "reply callback",
            ApiType::RejectCallback { .. } => "reject callback",
            ApiType::PreUpgrade { .. } => "pre upgrade",
            ApiType::InspectMessage { .. } => "inspect message",
            ApiType::Cleanup { .. } => "cleanup",
        }
    }
}

// This type is potentially serialized and exposed to the external world.  We
// use custom formatting to avoid exposing its internal details.
impl std::fmt::Display for ApiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A struct to gather the relevant fields that correspond to a canister's
/// memory consumption.
struct MemoryUsage {
    /// Upper limit on how much the memory the canister could use.
    limit: NumBytes,
    /// The current amount of memory that the canister is using.
    current_usage: NumBytes,
    // This is the amount of memory that the subnet has available. Any
    // expansions in the canister's memory need to be deducted from here.
    subnet_available_memory: SubnetAvailableMemory,

    stable_memory_delta: usize,
}

impl MemoryUsage {
    fn new(
        limit: NumBytes,
        current_usage: NumBytes,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> Self {
        assert!(
            limit >= current_usage,
            "Expected limit {} to be >= than current_usage {}",
            limit,
            current_usage
        );
        Self {
            limit,
            current_usage,
            subnet_available_memory,
            stable_memory_delta: 0,
        }
    }

    fn increase_usage(&mut self, pages: u64) -> HypervisorResult<()> {
        let bytes = ic_replicated_state::num_bytes_try_from64(NumWasmPages64::from(pages))
            .map_err(|_| HypervisorError::OutOfMemory)?;
        let (new_usage, overflow) = self.current_usage.get().overflowing_add(bytes.get());
        if overflow || new_usage > self.limit.get() {
            return Err(HypervisorError::OutOfMemory);
        }
        match self.subnet_available_memory.try_decrement(bytes) {
            Ok(()) => {
                self.current_usage = NumBytes::from(new_usage);
                Ok(())
            }
            Err(_err) => Err(HypervisorError::OutOfMemory),
        }
    }

    fn decrease_usage(&mut self, pages: u64) {
        // Expected to work as we have converted `pages` to bytes when `increase_usage`
        // was called and if it would have failed, we wouldn't call `decrease_usage`.
        let bytes = ic_replicated_state::num_bytes_try_from64(NumWasmPages64::from(pages))
            .expect("could not convert wasm pages to bytes");
        self.subnet_available_memory.increment(bytes);
        self.current_usage -= bytes;
    }
}

/// Struct that implements the SystemApi trait. This trait enables a canister to
/// have mediated access to its system state.
pub struct SystemApiImpl<A: SystemStateAccessor> {
    // An execution error of the current message.
    execution_error: Option<HypervisorError>,

    log: ReplicaLogger,

    // The variant of ApiType being executed.
    api_type: ApiType,

    // Mediate access to system state.
    system_state_accessor: A,

    memory_usage: MemoryUsage,

    execution_parameters: ExecutionParameters,
}

impl<A: SystemStateAccessor> SystemApiImpl<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_type: ApiType,
        system_state_accessor: A,
        canister_current_memory_usage: NumBytes,
        execution_parameters: ExecutionParameters,
        log: ReplicaLogger,
    ) -> Self {
        let memory_usage = MemoryUsage::new(
            execution_parameters.canister_memory_limit,
            canister_current_memory_usage,
            execution_parameters.subnet_available_memory.clone(),
        );

        Self {
            execution_error: None,
            api_type,
            system_state_accessor,
            memory_usage,
            execution_parameters,
            log,
        }
    }

    pub fn take_execution_result(&mut self) -> HypervisorResult<Option<WasmResult>> {
        if let Some(err) = self.execution_error.take() {
            return Err(err);
        }
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Heartbeat { .. } => Ok(None),
            ApiType::InspectMessage {
                message_accepted, ..
            } => {
                if *message_accepted {
                    Ok(None)
                } else {
                    Err(HypervisorError::MessageRejected)
                }
            }
            ApiType::Update {
                response_status, ..
            }
            | ApiType::ReplicatedQuery {
                response_status, ..
            }
            | ApiType::NonReplicatedQuery {
                response_status, ..
            }
            | ApiType::ReplyCallback {
                response_status, ..
            }
            | ApiType::RejectCallback {
                response_status, ..
            } => match response_status {
                ResponseStatus::JustRepliedWith(ref mut result) => Ok(result.take()),
                _ => Ok(None),
            },
        }
    }

    fn error_for(&self, method_name: &str) -> HypervisorError {
        HypervisorError::ContractViolation(format!(
            "\"{}\" cannot be executed in {} mode",
            method_name, self.api_type
        ))
    }

    fn get_response_info(&mut self) -> Option<(&mut Vec<u8>, &NumBytes, &mut ResponseStatus)> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::InspectMessage { .. } => None,
            ApiType::Update {
                response_data,
                response_status,
                max_reply_size,
                ..
            }
            | ApiType::ReplicatedQuery {
                response_data,
                response_status,
                max_reply_size,
                ..
            }
            | ApiType::NonReplicatedQuery {
                response_data,
                response_status,
                max_reply_size,
                ..
            }
            | ApiType::ReplyCallback {
                response_data,
                response_status,
                max_reply_size,
                ..
            }
            | ApiType::RejectCallback {
                response_data,
                response_status,
                max_reply_size,
                ..
            } => Some((response_data, max_reply_size, response_status)),
        }
    }

    fn get_reject_code(&self) -> Option<i32> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Update { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => None,
            ApiType::ReplyCallback { .. } => Some(0),
            ApiType::RejectCallback { reject_context, .. } => Some(reject_context.code as i32),
        }
    }

    fn get_reject_context(&self) -> Option<&RejectContext> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => None,
            ApiType::RejectCallback { reject_context, .. } => Some(reject_context),
        }
    }

    fn ic0_call_cycles_add_helper(
        &mut self,
        method_name: &str,
        amount: Cycles,
    ) -> HypervisorResult<()> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for(method_name)),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::Heartbeat {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            } => match outgoing_request {
                None => Err(HypervisorError::ContractViolation(format!(
                    "{} called when no call is under construction.",
                    method_name
                ))),
                Some(request) => {
                    self.system_state_accessor.canister_cycles_withdraw(
                        self.memory_usage.current_usage,
                        self.execution_parameters.compute_allocation,
                        amount,
                    )?;
                    request.add_cycles(amount);
                    Ok(())
                }
            },
        }
    }

    fn ic0_canister_cycles_balance_helper(
        &self,
        method_name: &str,
    ) -> HypervisorResult<(u64, u64)> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for(method_name)),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                let res = self
                    .system_state_accessor
                    .canister_cycles_balance()
                    .into_parts();
                Ok(res)
            }
        }
    }

    fn ic0_msg_cycles_available_helper(&self, method_name: &str) -> HypervisorResult<(u64, u64)> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for(method_name)),
            ApiType::Update {
                call_context_id, ..
            }
            | ApiType::ReplyCallback {
                call_context_id, ..
            }
            | ApiType::RejectCallback {
                call_context_id, ..
            } => self
                .system_state_accessor
                .msg_cycles_available(call_context_id)
                .map(|cycles| cycles.into_parts()),
        }
    }

    fn ic0_msg_cycles_refunded_helper(&self, method_name: &str) -> HypervisorResult<(u64, u64)> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Update { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for(method_name)),
            ApiType::ReplyCallback {
                incoming_cycles, ..
            }
            | ApiType::RejectCallback {
                incoming_cycles, ..
            } => Ok((*incoming_cycles).into_parts()),
        }
    }

    fn ic0_msg_cycles_accept_helper(
        &mut self,
        method_name: &str,
        max_amount: Cycles,
    ) -> HypervisorResult<(u64, u64)> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for(method_name)),
            ApiType::Update {
                call_context_id, ..
            }
            | ApiType::ReplyCallback {
                call_context_id, ..
            }
            | ApiType::RejectCallback {
                call_context_id, ..
            } => Ok(self
                .system_state_accessor
                .msg_cycles_accept(call_context_id, max_amount)
                .into_parts()),
        }
    }

    pub fn release_system_state_accessor(mut self) -> A {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::NonReplicatedQuery { .. } => (),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            } => {
                if let Some(outgoing_request) = outgoing_request.take() {
                    self.system_state_accessor
                        .canister_cycles_refund(outgoing_request.take_cycles());
                }
            }
        }
        self.system_state_accessor
    }
}

impl<A: SystemStateAccessor> SystemApi for SystemApiImpl<A> {
    fn set_execution_error(&mut self, error: HypervisorError) {
        self.execution_error = Some(error)
    }

    fn get_execution_error(&self) -> Option<&HypervisorError> {
        self.execution_error.as_ref()
    }

    fn get_stable_memory_delta_pages(&self) -> usize {
        self.memory_usage.stable_memory_delta
    }

    fn get_num_instructions_from_bytes(&self, num_bytes: NumBytes) -> NumInstructions {
        self.system_state_accessor
            .get_num_instructions_from_bytes(num_bytes)
    }

    fn ic0_msg_caller_size(&self) -> HypervisorResult<u32> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => Err(self.error_for("ic0_msg_caller_size")),
            ApiType::Init { caller, .. }
            | ApiType::Update { caller, .. }
            | ApiType::ReplicatedQuery { caller, .. }
            | ApiType::NonReplicatedQuery { caller, .. }
            | ApiType::PreUpgrade { caller, .. }
            | ApiType::InspectMessage { caller, .. } => Ok(caller.as_slice().len() as u32),
        }
    }

    fn ic0_msg_caller_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => Err(self.error_for("ic0_msg_caller_copy")),
            ApiType::Init { caller, .. }
            | ApiType::Update { caller, .. }
            | ApiType::ReplicatedQuery { caller, .. }
            | ApiType::PreUpgrade { caller, .. }
            | ApiType::InspectMessage { caller, .. }
            | ApiType::NonReplicatedQuery { caller, .. } => {
                let id_bytes = caller.as_slice();
                valid_subslice("ic0.msg_caller_copy heap", dst, size, heap)?;
                let slice = valid_subslice("ic0.msg_caller_copy id", offset, size, id_bytes)?;
                let (dst, size) = (dst as usize, size as usize);
                heap[dst..dst + size].copy_from_slice(slice);
                Ok(())
            }
        }
    }

    fn ic0_msg_arg_data_size(&self) -> HypervisorResult<u32> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. } => Err(self.error_for("ic0_msg_arg_data_size")),
            ApiType::Init {
                incoming_payload, ..
            }
            | ApiType::Update {
                incoming_payload, ..
            }
            | ApiType::ReplyCallback {
                incoming_payload, ..
            }
            | ApiType::ReplicatedQuery {
                incoming_payload, ..
            }
            | ApiType::InspectMessage {
                incoming_payload, ..
            }
            | ApiType::NonReplicatedQuery {
                incoming_payload, ..
            } => Ok(incoming_payload.len() as u32),
        }
    }

    fn ic0_msg_arg_data_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. } => Err(self.error_for("ic0_msg_arg_data_copy")),
            ApiType::Init {
                incoming_payload, ..
            }
            | ApiType::Update {
                incoming_payload, ..
            }
            | ApiType::ReplyCallback {
                incoming_payload, ..
            }
            | ApiType::ReplicatedQuery {
                incoming_payload, ..
            }
            | ApiType::InspectMessage {
                incoming_payload, ..
            }
            | ApiType::NonReplicatedQuery {
                incoming_payload, ..
            } => {
                valid_subslice("ic0.msg_arg_data_copy heap", dst, size, heap)?;
                let payload_subslice = valid_subslice(
                    "ic0.msg_arg_data_copy payload",
                    offset,
                    size,
                    incoming_payload,
                )?;
                let (dst, size) = (dst as usize, size as usize);
                heap[dst..dst + size].copy_from_slice(payload_subslice);
                Ok(())
            }
        }
    }

    fn ic0_msg_method_name_size(&self) -> HypervisorResult<u32> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Init { .. } => Err(self.error_for("ic0_msg_method_name_size")),
            ApiType::InspectMessage { method_name, .. } => Ok(method_name.len() as u32),
        }
    }

    fn ic0_msg_method_name_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Init { .. } => Err(self.error_for("ic0_msg_method_name_copy")),
            ApiType::InspectMessage { method_name, .. } => {
                valid_subslice("ic0.msg_method_name_copy heap", dst, size, heap)?;
                let payload_subslice = valid_subslice(
                    "ic0.msg_method_name_copy payload",
                    offset,
                    size,
                    method_name.as_bytes(),
                )?;
                let (dst, size) = (dst as usize, size as usize);
                heap[dst..dst + size].copy_from_slice(payload_subslice);
                Ok(())
            }
        }
    }

    fn ic0_accept_message(&mut self) -> HypervisorResult<()> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Init { .. } => Err(self.error_for("ic0_accept_message")),
            ApiType::InspectMessage {
                message_accepted, ..
            } => {
                if *message_accepted {
                    Err(ContractViolation(
                        "ic0.accept_message: the function was already called.".to_string(),
                    ))
                } else {
                    *message_accepted = true;
                    Ok(())
                }
            }
        }
    }

    fn ic0_msg_reply(&mut self) -> HypervisorResult<()> {
        match self.get_response_info() {
            None => Err(self.error_for("ic0_msg_reply")),
            Some((data, _, status)) => match status {
                ResponseStatus::NotRepliedYet => {
                    *status = ResponseStatus::JustRepliedWith(Some(WasmResult::Reply(
                        std::mem::replace(data, Vec::new()),
                    )));
                    Ok(())
                }
                ResponseStatus::AlreadyReplied | ResponseStatus::JustRepliedWith(_) => Err(
                    ContractViolation("ic0.msg_reply: the call is already replied".to_string()),
                ),
            },
        }
    }

    fn ic0_msg_reply_data_append(
        &mut self,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        match self.get_response_info() {
            None => Err(self.error_for("ic0_msg_reply_data_append")),
            Some((data, max_reply_size, response_status)) => match response_status {
                ResponseStatus::NotRepliedYet => {
                    let payload_size = (data.len() + size as usize) as u64;
                    if payload_size > max_reply_size.get() {
                        let string = format!(
                            "ic0.msg_reply_data_append: application payload size ({}) cannot be larger than {}",
                            payload_size,
                            max_reply_size,
                        );
                        return Err(ContractViolation(string));
                    }
                    data.extend_from_slice(valid_subslice("msg.reply", src, size, heap)?);
                    Ok(())
                }
                ResponseStatus::AlreadyReplied | ResponseStatus::JustRepliedWith(_) => {
                    Err(ContractViolation(
                        "ic0.msg_reply_data_append: the call is already replied".to_string(),
                    ))
                }
            },
        }
    }

    fn ic0_msg_reject(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()> {
        match self.get_response_info() {
            None => Err(self.error_for("ic0_msg_reject")),
            Some((_, max_reply_size, response_status)) => match response_status {
                ResponseStatus::NotRepliedYet => {
                    if size as u64 > max_reply_size.get() {
                        let string = format!(
                        "ic0.msg_reject: application payload size ({}) cannot be larger than {}",
                        size, max_reply_size
                    );
                        return Err(ContractViolation(string));
                    }
                    let msg_bytes = valid_subslice("ic0.msg_reject", src, size, heap)?;
                    let msg = String::from_utf8(msg_bytes.to_vec()).map_err(|_| {
                        ContractViolation(
                            "ic0.msg_reject: invalid UTF-8 string provided".to_string(),
                        )
                    })?;
                    *response_status =
                        ResponseStatus::JustRepliedWith(Some(WasmResult::Reject(msg)));
                    Ok(())
                }
                ResponseStatus::AlreadyReplied | ResponseStatus::JustRepliedWith(_) => Err(
                    ContractViolation("ic0.msg_reject: the call is already replied".to_string()),
                ),
            },
        }
    }

    fn ic0_msg_reject_code(&self) -> HypervisorResult<i32> {
        self.get_reject_code()
            .ok_or_else(|| self.error_for("ic0_msg_reject_code"))
    }

    fn ic0_msg_reject_msg_size(&self) -> HypervisorResult<u32> {
        let reject_context = self
            .get_reject_context()
            .ok_or_else(|| self.error_for("ic0_msg_reject_msg_size"))?;
        Ok(reject_context.message().len() as u32)
    }

    fn ic0_msg_reject_msg_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let reject_context = self
            .get_reject_context()
            .ok_or_else(|| self.error_for("ic0_msg_reject_msg_copy"))?;
        valid_subslice("ic0.msg_reject_msg_copy heap", dst, size, heap)?;
        let msg = reject_context.message();
        let dst = dst as usize;
        let msg_bytes =
            valid_subslice("ic0.msg_reject_msg_copy msg", offset, size, msg.as_bytes())?;
        let size = size as usize;
        heap[dst..dst + size].copy_from_slice(msg_bytes);
        Ok(())
    }

    fn ic0_canister_self_size(&self) -> HypervisorResult<usize> {
        match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_canister_self_size")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Ok(self
                .system_state_accessor
                .canister_id()
                .get_ref()
                .as_slice()
                .len()),
        }
    }

    fn ic0_canister_self_copy(
        &mut self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_canister_self_copy")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                valid_subslice("ic0.canister_self_copy heap", dst, size, heap)?;
                let canister_id = self.system_state_accessor.canister_id();
                let id_bytes = canister_id.get_ref().as_slice();
                let slice = valid_subslice("ic0.canister_self_copy id", offset, size, id_bytes)?;
                let (dst, size) = (dst as usize, size as usize);
                heap[dst..dst + size].copy_from_slice(slice);
                Ok(())
            }
        }
    }

    fn ic0_controller_size(&self) -> HypervisorResult<usize> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_controller_size")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                Ok(self.system_state_accessor.controller().as_slice().len())
            }
        }
    }

    fn ic0_controller_copy(
        &mut self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_controller_copy")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                valid_subslice("ic0.controller_copy heap", dst, size, heap)?;
                let controller = self.system_state_accessor.controller();
                let id_bytes = controller.as_slice();
                let slice = valid_subslice("ic0.controller_copy id", offset, size, id_bytes)?;
                let (dst, size) = (dst as usize, size as usize);
                heap[dst..dst + size].copy_from_slice(slice);
                Ok(())
            }
        }
    }

    fn ic0_call_simple(
        &mut self,
        callee_src: u32,
        callee_size: u32,
        method_name_src: u32,
        method_name_len: u32,
        reply_fun: u32,
        reply_env: u32,
        reject_fun: u32,
        reject_env: u32,
        data_src: u32,
        data_len: u32,
        heap: &[u8],
    ) -> HypervisorResult<i32> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery {
                query_kind: NonReplicatedQueryKind::Pure,
                ..
            }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_simple")),
            ApiType::Update {
                call_context_id,
                own_subnet_id,
                routing_table,
                ..
            }
            | ApiType::NonReplicatedQuery {
                call_context_id,
                own_subnet_id,
                routing_table,
                query_kind: NonReplicatedQueryKind::Stateful,
                ..
            }
            | ApiType::Heartbeat {
                call_context_id,
                own_subnet_id,
                routing_table,
                ..
            }
            | ApiType::ReplyCallback {
                call_context_id,
                own_subnet_id,
                routing_table,
                ..
            }
            | ApiType::RejectCallback {
                call_context_id,
                own_subnet_id,
                routing_table,
                ..
            } => {
                if data_len as u64 > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get() {
                    return Ok(RejectCode::SysFatal as i32);
                }

                let method_name = valid_subslice(
                    "ic0.call_simple method_name",
                    method_name_src,
                    method_name_len,
                    heap,
                )?;
                let method_name = String::from_utf8_lossy(method_name).to_string();
                let payload = Vec::from(valid_subslice(
                    "ic0.call_simple payload",
                    data_src,
                    data_len,
                    heap,
                )?);
                let id_bytes =
                    valid_subslice("ic0.call_simple callee_src", callee_src, callee_size, heap)?;

                let callee =
                    PrincipalId::try_from(id_bytes).map_err(HypervisorError::InvalidPrincipalId)?;

                let callee = if callee == IC_00.get() {
                    // This is a request to ic:00. Update `callee` to be the appropriate subnet.
                    let callee = resolve_destination(
                        routing_table.clone(),
                        method_name.as_str(),
                        payload.as_slice(),
                        *own_subnet_id,
                    )
                    .unwrap_or_else(|_| {
                        // Couldn't find the right subnet. Send it to the current subnet,
                        // which will handle rejecting the request gracefully.
                        *own_subnet_id
                    });
                    CanisterId::new(callee.get()).unwrap()
                } else {
                    CanisterId::new(callee).map_err(HypervisorError::InvalidCanisterId)?
                };

                let on_reply = WasmClosure::new(reply_fun, reply_env);
                let on_reject = WasmClosure::new(reject_fun, reject_env);
                let callback_id = self.system_state_accessor.register_callback(Callback::new(
                    *call_context_id,
                    Cycles::from(0),
                    on_reply,
                    on_reject,
                    None,
                ));

                let msg = Request {
                    sender: self.system_state_accessor.canister_id(),
                    receiver: callee,
                    method_name,
                    method_payload: payload,
                    sender_reply_callback: callback_id,
                    payment: Cycles::zero(),
                };
                match self.system_state_accessor.push_output_request(
                    self.memory_usage.current_usage,
                    self.execution_parameters.compute_allocation,
                    msg,
                ) {
                    Ok(()) => Ok(0),
                    Err((StateError::QueueFull { .. }, request))
                    | Err((StateError::CanisterOutOfCycles { .. }, request)) => {
                        self.system_state_accessor
                            .canister_cycles_refund(request.payment);
                        self.system_state_accessor
                            .unregister_callback(request.sender_reply_callback);
                        Ok(RejectCode::SysTransient as i32)
                    }
                    Err((err, _)) => {
                        unreachable!("Unexpected error while pushing to output queue: {}", err)
                    }
                }
            }
        }
    }

    fn ic0_call_new(
        &mut self,
        callee_src: u32,
        callee_size: u32,
        name_src: u32,
        name_len: u32,
        reply_fun: u32,
        reply_env: u32,
        reject_fun: u32,
        reject_env: u32,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery {
                query_kind: NonReplicatedQueryKind::Pure,
                ..
            }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_new")),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::NonReplicatedQuery {
                outgoing_request,
                query_kind: NonReplicatedQueryKind::Stateful,
                ..
            }
            | ApiType::Heartbeat {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            } => {
                if let Some(outgoing_request) = outgoing_request.take() {
                    self.system_state_accessor
                        .canister_cycles_refund(outgoing_request.take_cycles());
                }

                let req = RequestInPrep::new(
                    self.system_state_accessor.canister_id(),
                    callee_src,
                    callee_size,
                    name_src,
                    name_len,
                    heap,
                    WasmClosure::new(reply_fun, reply_env),
                    WasmClosure::new(reject_fun, reject_env),
                    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
                    MULTIPLIER_MAX_SIZE_INTRA_SUBNET,
                )?;
                *outgoing_request = Some(req);
                Ok(())
            }
        }
    }

    fn ic0_call_data_append(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery {
                query_kind: NonReplicatedQueryKind::Pure,
                ..
            }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_data_append")),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::NonReplicatedQuery {
                outgoing_request,
                query_kind: NonReplicatedQueryKind::Stateful,
                ..
            }
            | ApiType::Heartbeat {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            } => match outgoing_request {
                None => Err(HypervisorError::ContractViolation(
                    "ic0.call_data_append called when no call is under construction.".to_string(),
                )),
                Some(request) => request.extend_method_payload(src, size, heap),
            },
        }
    }

    fn ic0_call_on_cleanup(&mut self, fun: u32, env: u32) -> HypervisorResult<()> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery {
                query_kind: NonReplicatedQueryKind::Pure,
                ..
            }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_on_cleanup")),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::NonReplicatedQuery {
                outgoing_request,
                query_kind: NonReplicatedQueryKind::Stateful,
                ..
            }
            | ApiType::Heartbeat {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            } => match outgoing_request {
                None => Err(HypervisorError::ContractViolation(
                    "ic0.call_on_cleanup called when no call is under construction.".to_string(),
                )),
                Some(request) => request.set_on_cleanup(WasmClosure::new(fun, env)),
            },
        }
    }

    fn ic0_call_cycles_add(&mut self, amount: u64) -> HypervisorResult<()> {
        self.ic0_call_cycles_add_helper("ic0_call_cycles_add", Cycles::from(amount))
    }

    fn ic0_call_cycles_add128(&mut self, amount: Cycles) -> HypervisorResult<()> {
        self.ic0_call_cycles_add_helper("ic0_call_cycles_add128", amount)
    }

    // Note that if this function returns an error, then the canister will be
    // trapped and the state will be rolled back. Hence, we do not have to worry
    // about rolling back any modifications that previous calls like
    // ic0_call_cycles_add128() made.
    //
    // However, this call can still "fail" without returning an error. Examples
    // are if the canister does not have sufficient cycles to send the request
    // or the output queues are full. In this case, we need to perform the
    // necessary cleanups.
    fn ic0_call_perform(&mut self) -> HypervisorResult<i32> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery {
                query_kind: NonReplicatedQueryKind::Pure,
                ..
            }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_perform")),
            ApiType::Update {
                call_context_id,
                own_subnet_id,
                own_subnet_type,
                outgoing_request,
                routing_table,
                subnet_records,
                ..
            }
            | ApiType::Heartbeat {
                call_context_id,
                own_subnet_id,
                own_subnet_type,
                outgoing_request,
                routing_table,
                subnet_records,
                ..
            }
            | ApiType::ReplyCallback {
                call_context_id,
                own_subnet_id,
                own_subnet_type,
                outgoing_request,
                routing_table,
                subnet_records,
                ..
            }
            | ApiType::RejectCallback {
                call_context_id,
                own_subnet_id,
                own_subnet_type,
                outgoing_request,
                routing_table,
                subnet_records,
                ..
            } => {
                let req_in_prep = outgoing_request.take().ok_or_else(|| {
                    ContractViolation(
                        "ic0.call_perform called when no call is under construction.".to_string(),
                    )
                })?;

                let req = into_request(
                    routing_table.clone(),
                    subnet_records,
                    req_in_prep,
                    *call_context_id,
                    *own_subnet_id,
                    *own_subnet_type,
                    &self.system_state_accessor,
                )?;
                match self.system_state_accessor.push_output_request(
                    self.memory_usage.current_usage,
                    self.execution_parameters.compute_allocation,
                    req,
                ) {
                    Ok(()) => Ok(0),
                    Err((StateError::QueueFull { .. }, request))
                    | Err((StateError::CanisterOutOfCycles { .. }, request)) => {
                        self.system_state_accessor
                            .canister_cycles_refund(request.payment);
                        self.system_state_accessor
                            .unregister_callback(request.sender_reply_callback);
                        Ok(RejectCode::SysTransient as i32)
                    }
                    Err((err, _)) => {
                        unreachable!("Unexpected error while pushing to output queue: {}", err)
                    }
                }
            }
            ApiType::NonReplicatedQuery {
                call_context_id,
                own_subnet_id,
                outgoing_request,
                routing_table,
                query_kind: NonReplicatedQueryKind::Stateful,
                ..
            } => {
                let req_in_prep = outgoing_request.take().ok_or_else(|| {
                    ContractViolation(
                        "ic0.call_perform called when no call is under construction.".to_string(),
                    )
                })?;

                // We do not support inter canister queries between subnets so
                // we can use nominal values for these fields to satisfy the
                // constraints.
                let own_subnet_type = SubnetType::Application;
                let mut subnet_records = BTreeMap::new();
                subnet_records.insert(*own_subnet_id, own_subnet_type);

                let req = into_request(
                    routing_table.clone(),
                    &subnet_records,
                    req_in_prep,
                    *call_context_id,
                    *own_subnet_id,
                    own_subnet_type,
                    &self.system_state_accessor,
                )?;
                match self.system_state_accessor.push_output_request(
                    self.memory_usage.current_usage,
                    self.execution_parameters.compute_allocation,
                    req,
                ) {
                    Ok(()) => Ok(0),
                    Err((StateError::QueueFull { .. }, request))
                    | Err((StateError::CanisterOutOfCycles { .. }, request)) => {
                        self.system_state_accessor
                            .unregister_callback(request.sender_reply_callback);
                        Ok(RejectCode::SysTransient as i32)
                    }
                    Err((err, _)) => {
                        unreachable!("Unexpected error while pushing to output queue: {}", err)
                    }
                }
            }
        }
    }

    fn ic0_stable_size(&self) -> HypervisorResult<u32> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable_size")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => self.system_state_accessor.stable_size(),
        }
    }

    fn ic0_stable_grow(&mut self, additional_pages: u32) -> HypervisorResult<i32> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable_grow")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                match self.memory_usage.increase_usage(additional_pages as u64) {
                    Ok(()) => {
                        let native_memory_grow_res =
                            self.system_state_accessor.stable_grow(additional_pages)?;
                        if native_memory_grow_res == -1 {
                            self.memory_usage.decrease_usage(additional_pages as u64);
                            return Ok(-1);
                        }
                        Ok(native_memory_grow_res)
                    }
                    Err(_err) => Ok(-1),
                }
            }
        }
    }

    fn ic0_stable_read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable_read")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => self
                .system_state_accessor
                .stable_read(dst, offset, size, heap),
        }
    }

    fn ic0_stable_write(
        &mut self,
        offset: u32,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable_write")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => self
                .system_state_accessor
                .stable_write(offset, src, size, heap)
                .map(|_| {
                    self.memory_usage.stable_memory_delta +=
                        (size as usize / *PAGE_SIZE) + std::cmp::min(1, size as usize % *PAGE_SIZE);
                }),
        }
    }

    fn ic0_stable64_size(&self) -> HypervisorResult<u64> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable64_size")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => self.system_state_accessor.stable64_size(),
        }
    }

    fn ic0_stable64_grow(&mut self, additional_pages: u64) -> HypervisorResult<i64> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable64_grow")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                match self.memory_usage.increase_usage(additional_pages) {
                    Ok(()) => {
                        let native_memory_grow_res =
                            self.system_state_accessor.stable64_grow(additional_pages)?;
                        if native_memory_grow_res == -1 {
                            self.memory_usage.decrease_usage(additional_pages);
                            return Ok(-1);
                        }
                        Ok(native_memory_grow_res)
                    }
                    Err(_err) => Ok(-1),
                }
            }
        }
    }

    fn ic0_stable64_read(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable64_read")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => self
                .system_state_accessor
                .stable64_read(dst, offset, size, heap),
        }
    }

    fn ic0_stable64_write(
        &mut self,
        offset: u64,
        src: u64,
        size: u64,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start {} => Err(self.error_for("ic0_stable64_write")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => self
                .system_state_accessor
                .stable64_write(offset, src, size, heap)
                .map(|_| {
                    self.memory_usage.stable_memory_delta +=
                        (size as usize / *PAGE_SIZE) + std::cmp::min(1, size as usize % *PAGE_SIZE);
                }),
        }
    }

    fn ic0_time(&self) -> HypervisorResult<Time> {
        match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_time")),
            ApiType::Init { time, .. }
            | ApiType::Heartbeat { time, .. }
            | ApiType::Update { time, .. }
            | ApiType::Cleanup { time, .. }
            | ApiType::NonReplicatedQuery { time, .. }
            | ApiType::ReplicatedQuery { time, .. }
            | ApiType::PreUpgrade { time, .. }
            | ApiType::ReplyCallback { time, .. }
            | ApiType::RejectCallback { time, .. }
            | ApiType::InspectMessage { time, .. } => Ok(*time),
        }
    }

    fn out_of_instructions(&self) -> HypervisorError {
        HypervisorError::OutOfInstructions
    }

    fn update_available_memory(
        &mut self,
        native_memory_grow_res: i32,
        additional_pages: u32,
    ) -> HypervisorResult<i32> {
        if native_memory_grow_res == -1 {
            return Ok(-1);
        }
        match self.memory_usage.increase_usage(additional_pages as u64) {
            Ok(()) => Ok(native_memory_grow_res),
            Err(_err) => Err(HypervisorError::OutOfMemory),
        }
    }

    fn ic0_canister_cycle_balance(&self) -> HypervisorResult<u64> {
        let (high_amount, low_amount) =
            self.ic0_canister_cycles_balance_helper("ic0_canister_cycles_balance")?;
        if high_amount != 0 {
            return Err(HypervisorError::Trapped(CyclesAmountTooBigFor64Bit));
        }
        Ok(low_amount)
    }

    fn ic0_canister_cycles_balance128(&self) -> HypervisorResult<(u64, u64)> {
        self.ic0_canister_cycles_balance_helper("ic0_canister_cycles_balance128")
    }

    fn ic0_msg_cycles_available(&self) -> HypervisorResult<u64> {
        let (high_amount, low_amount) =
            self.ic0_msg_cycles_available_helper("ic0_msg_cycles_available")?;
        if high_amount != 0 {
            return Err(HypervisorError::Trapped(CyclesAmountTooBigFor64Bit));
        }
        Ok(low_amount)
    }

    fn ic0_msg_cycles_available128(&self) -> HypervisorResult<(u64, u64)> {
        self.ic0_msg_cycles_available_helper("ic0_msg_cycles_available128")
    }

    fn ic0_msg_cycles_refunded(&self) -> HypervisorResult<u64> {
        let (high_amount, low_amount) =
            self.ic0_msg_cycles_refunded_helper("ic0_msg_cycles_refunded")?;
        if high_amount != 0 {
            return Err(HypervisorError::Trapped(CyclesAmountTooBigFor64Bit));
        }
        Ok(low_amount)
    }

    fn ic0_msg_cycles_refunded128(&self) -> HypervisorResult<(u64, u64)> {
        self.ic0_msg_cycles_refunded_helper("ic0_msg_cycles_refunded128")
    }

    fn ic0_msg_cycles_accept(&mut self, max_amount: u64) -> HypervisorResult<u64> {
        // Cannot accept more than max_amount.
        let (high_amount, low_amount) =
            self.ic0_msg_cycles_accept_helper("ic0_msg_cycles_accept", Cycles::from(max_amount))?;
        if high_amount != 0 {
            error!(
                self.log,
                "ic0_msg_cycles_accept cannot accept more than max_amount {}; accepted amount {}",
                max_amount,
                Cycles::from_parts(high_amount, low_amount).get()
            )
        }
        Ok(low_amount)
    }

    fn ic0_msg_cycles_accept128(&mut self, max_amount: Cycles) -> HypervisorResult<(u64, u64)> {
        self.ic0_msg_cycles_accept_helper("ic0_msg_cycles_accept128", max_amount)
    }

    fn ic0_data_certificate_present(&self) -> HypervisorResult<i32> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::Update { .. }
            | ApiType::Heartbeat { .. } => Ok(0),
            ApiType::ReplicatedQuery {
                data_certificate, ..
            }
            | ApiType::NonReplicatedQuery {
                data_certificate, ..
            } => match data_certificate {
                Some(_) => Ok(1),
                None => Ok(0),
            },
        }
    }

    fn ic0_data_certificate_size(&self) -> HypervisorResult<i32> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_data_certificate_size")),
            ApiType::ReplicatedQuery {
                data_certificate, ..
            }
            | ApiType::NonReplicatedQuery {
                data_certificate, ..
            } => match data_certificate {
                Some(data_certificate) => Ok(data_certificate.len() as i32),
                None => Err(self.error_for("ic0_data_certificate_size")),
            },
        }
    }

    fn ic0_data_certificate_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_data_certificate_copy")),
            ApiType::ReplicatedQuery {
                data_certificate, ..
            }
            | ApiType::NonReplicatedQuery {
                data_certificate, ..
            } => match data_certificate {
                Some(data_certificate) => {
                    let (dst, offset, size) = (dst as usize, offset as usize, size as usize);

                    let (upper_bound, overflow) = offset.overflowing_add(size);
                    if overflow || upper_bound > data_certificate.len() {
                        return Err(ContractViolation(format!(
                            "ic0_data_certificate_copy failed because offset + size is out \
                                 of bounds. Found offset = {} and size = {} while offset + size \
                                 must be <= {}",
                            offset,
                            size,
                            data_certificate.len(),
                        )));
                    }

                    let (upper_bound, overflow) = dst.overflowing_add(size);
                    if overflow || upper_bound > heap.len() {
                        return Err(ContractViolation(format!(
                            "ic0_data_certificate_copy failed because dst + size is out \
                                 of bounds. Found dst = {} and size = {} while dst + size \
                                 must be <= {}",
                            dst,
                            size,
                            heap.len(),
                        )));
                    }

                    // Copy the certificate into the canister.
                    heap[dst..dst + size].copy_from_slice(&data_certificate[offset..offset + size]);
                    Ok(())
                }
                None => Err(self.error_for("ic0_data_certificate_size")),
            },
        }
    }

    fn ic0_certified_data_set(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::Cleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_certified_data_set")),
            ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. } => {
                if size > 32 {
                    return Err(ContractViolation(format!(
                        "ic0_certified_data_set failed because the passed data must be \
                        no larger than 32 bytes. Found {} bytes",
                        size
                    )));
                }

                let (src, size) = (src as usize, size as usize);
                let (upper_bound, overflow) = src.overflowing_add(size);
                if overflow || upper_bound > heap.len() {
                    return Err(ContractViolation(format!(
                        "ic0_certified_data_set failed because src + size is out \
                                 of bounds. Found src = {} and size = {} while src + size \
                                 must be <= {}",
                        src,
                        size,
                        heap.len(),
                    )));
                }

                // Update the certified data.
                self.system_state_accessor
                    .set_certified_data(heap[src..src + size].to_vec());
                Ok(())
            }
        }
    }

    fn ic0_canister_status(&self) -> HypervisorResult<u32> {
        match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_canister_status")),
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Init { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => {
                match self.system_state_accessor.canister_status() {
                    CanisterStatus::Running { .. } => Ok(1),
                    CanisterStatus::Stopping { .. } => Ok(2),
                    CanisterStatus::Stopped { .. } => Ok(3),
                }
            }
        }
    }

    fn ic0_mint_cycles(&mut self, amount: u64) -> HypervisorResult<u64> {
        match self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_mint_cycles")),
            ApiType::Update { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => {
                self.system_state_accessor
                    .mint_cycles(Cycles::from(amount))?;
                Ok(amount)
            }
        }
    }

    fn ic0_debug_print(&self, src: u32, size: u32, heap: &[u8]) {
        let msg = match valid_subslice("ic0.debug_print", src, size, heap) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Err(_) => {
                // Do not trap here!
                // debug.print should never fail, so if the specified memory range
                // is invalid, we ignore it and print the error message
                "(debug message out of memory bounds)".to_string()
            }
        };
        eprintln!(
            "[Canister {}] {}",
            self.system_state_accessor.canister_id(),
            msg
        );
    }

    fn ic0_trap(&self, src: u32, size: u32, heap: &[u8]) -> HypervisorError {
        let msg = valid_subslice("trap", src, size, heap)
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .unwrap_or_else(|_| "(trap message out of memory bounds)".to_string());
        CalledTrap(msg)
    }
}

pub(crate) fn valid_subslice<'a>(
    ctx: &str,
    src: u32,
    len: u32,
    slice: &'a [u8],
) -> HypervisorResult<&'a [u8]> {
    let len = len as usize;
    let src = src as usize;
    if slice.len() < src + len {
        return Err(ContractViolation(format!(
            "{}: src={} + length={} exceeds the slice size={}",
            ctx,
            src,
            len,
            slice.len()
        )));
    }
    Ok(&slice[src..src + len])
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_base_types::NumSeconds;
    use ic_cycles_account_manager::CyclesAccountManager;
    use ic_logger::replica_logger::no_op_logger;
    use ic_registry_routing_table::CanisterIdRange;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{CallOrigin, SystemState};
    use ic_test_utilities::{
        cycles_account_manager::CyclesAccountManagerBuilder,
        mock_time,
        state::SystemStateBuilder,
        types::ids::{call_context_test_id, canister_test_id, subnet_test_id, user_test_id},
    };
    use ic_types::{messages::CallbackId, ComputeAllocation, NumInstructions};
    use maplit::btreemap;
    use std::convert::TryInto;

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 40);
    const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
    const CANISTER_CURRENT_MEMORY_USAGE: NumBytes = NumBytes::new(0);

    fn execution_parameters() -> ExecutionParameters {
        ExecutionParameters {
            instruction_limit: NumInstructions::new(5_000_000_000),
            canister_memory_limit: NumBytes::new(4 << 30),
            subnet_available_memory: SubnetAvailableMemory::new(NumBytes::new(std::u64::MAX)),
            compute_allocation: ComputeAllocation::default(),
        }
    }

    fn setup() -> (
        SubnetId,
        SubnetType,
        Arc<RoutingTable>,
        Arc<BTreeMap<SubnetId, SubnetType>>,
    ) {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let routing_table = Arc::new(RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
        }));
        let subnet_records = Arc::new(btreemap! {
            subnet_id => subnet_type,
        });

        (subnet_id, subnet_type, routing_table, subnet_records)
    }

    fn get_system_state_for_reject() -> SystemState {
        let mut system_state = SystemStateBuilder::new().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(50),
            );

        system_state
    }

    fn get_test_api_for_reject(
        reject_context: RejectContext,
        system_state_accessor: SystemStateAccessorDirect,
    ) -> SystemApiImpl<SystemStateAccessorDirect> {
        let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
        SystemApiImpl::new(
            ApiType::reject_callback(
                mock_time(),
                reject_context,
                Cycles::from(0),
                call_context_test_id(1),
                false,
                subnet_id,
                subnet_type,
                routing_table,
                subnet_records,
            ),
            system_state_accessor,
            CANISTER_CURRENT_MEMORY_USAGE,
            execution_parameters(),
            no_op_logger(),
        )
    }

    fn assert_api_supported<T>(res: HypervisorResult<T>) {
        if let Err(HypervisorError::ContractViolation(err)) = res {
            assert!(!err.contains("cannot be executed"), "{}", err)
        }
    }

    fn assert_api_not_supported<T>(res: HypervisorResult<T>) {
        match res {
            Err(HypervisorError::ContractViolation(err)) => {
                assert!(err.contains("cannot be executed"), "{}", err)
            }
            _ => unreachable!("Expected api to be unsupported."),
        }
    }

    fn get_new_running_system_state(
        cycles_amount: Cycles,
        _own_subnet_type: SubnetType,
    ) -> SystemState {
        SystemState::new_running(
            canister_test_id(42),
            user_test_id(24).get(),
            cycles_amount,
            NumSeconds::from(100_000),
        )
    }

    fn get_update_api_type() -> ApiType {
        let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
        ApiType::update(
            mock_time(),
            vec![],
            Cycles::from(0),
            user_test_id(1).get(),
            CallContextId::from(1),
            subnet_id,
            subnet_type,
            routing_table,
            subnet_records,
        )
    }

    fn get_reply_api_type(incoming_cycles: Cycles) -> ApiType {
        let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
        ApiType::reply_callback(
            mock_time(),
            vec![],
            incoming_cycles,
            CallContextId::new(1),
            false,
            subnet_id,
            subnet_type,
            routing_table,
            subnet_records,
        )
    }

    fn get_heartbeat_api_type() -> ApiType {
        let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
        ApiType::heartbeat(
            mock_time(),
            CallContextId::from(1),
            subnet_id,
            subnet_type,
            routing_table,
            subnet_records,
        )
    }

    fn get_system_api_with_max_cycles_per_canister(
        api_type: ApiType,
        system_state: SystemState,
        cycles_account_manager: CyclesAccountManager,
    ) -> SystemApiImpl<SystemStateAccessorDirect> {
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, Arc::new(cycles_account_manager));
        SystemApiImpl::new(
            api_type,
            system_state_accessor,
            CANISTER_CURRENT_MEMORY_USAGE,
            execution_parameters(),
            no_op_logger(),
        )
    }

    fn get_system_api(
        api_type: ApiType,
        system_state: SystemState,
        cycles_account_manager: CyclesAccountManager,
    ) -> SystemApiImpl<SystemStateAccessorDirect> {
        get_system_api_with_max_cycles_per_canister(api_type, system_state, cycles_account_manager)
    }

    #[test]
    fn test_canister_init_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let mut api = get_system_api(
            ApiType::init(mock_time(), vec![], user_test_id(1).get()),
            system_state,
            cycles_account_manager,
        );

        assert_api_supported(api.ic0_msg_caller_size());
        assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_not_supported(api.ic0_msg_reply());
        assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_not_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_canister_update_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(SubnetType::System)
            .build();
        let mut system_state = SystemStateBuilder::new().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(50),
            );

        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        assert_api_supported(api.ic0_msg_caller_size());
        assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_supported(api.ic0_msg_cycles_available());
        assert_api_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_supported(api.ic0_msg_cycles_accept(0));
        assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_canister_replicated_query_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let mut api = get_system_api(
            ApiType::replicated_query(mock_time(), vec![], user_test_id(1).get(), None),
            system_state,
            cycles_account_manager,
        );

        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_caller_size());
        assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_not_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_canister_pure_query_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let mut api = get_system_api(
            ApiType::replicated_query(mock_time(), vec![], user_test_id(1).get(), None),
            system_state,
            cycles_account_manager,
        );

        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_caller_size());
        assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_not_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_canister_stateful_query_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let (subnet_id, _, routing_table, _) = setup();
        let mut api = get_system_api(
            ApiType::non_replicated_query(
                mock_time(),
                vec![],
                user_test_id(1).get(),
                CallContextId::from(1),
                subnet_id,
                routing_table,
                Some(vec![1]),
                NonReplicatedQueryKind::Stateful,
            ),
            system_state,
            cycles_account_manager,
        );

        assert_api_supported(api.ic0_msg_caller_size());
        assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_supported(api.ic0_data_certificate_size());
        assert_api_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    fn get_test_api_for_reply(
        own_subnet_type: SubnetType,
    ) -> SystemApiImpl<SystemStateAccessorDirect> {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(own_subnet_type)
            .build();
        let mut system_state = SystemStateBuilder::new().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(50),
            );
        get_system_api(
            get_reply_api_type(Cycles::from(0)),
            system_state,
            cycles_account_manager,
        )
    }

    #[test]
    fn test_reply_api_support_on_nns() {
        let mut api = get_test_api_for_reply(SubnetType::System);

        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_supported(api.ic0_msg_cycles_available());
        assert_api_supported(api.ic0_msg_cycles_available128());
        assert_api_supported(api.ic0_msg_cycles_refunded());
        assert_api_supported(api.ic0_msg_cycles_refunded128());
        assert_api_supported(api.ic0_msg_cycles_accept(0));
        assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_reply_api_support_non_nns() {
        let mut api = get_test_api_for_reply(SubnetType::Application);

        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_supported(api.ic0_msg_cycles_available());
        assert_api_supported(api.ic0_msg_cycles_available128());
        assert_api_supported(api.ic0_msg_cycles_refunded());
        assert_api_supported(api.ic0_msg_cycles_refunded128());
        assert_api_supported(api.ic0_msg_cycles_accept(0));
        assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_reject_api_support_on_nns() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(SubnetType::System)
            .build();
        let system_state = get_system_state_for_reject();
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, Arc::new(cycles_account_manager));
        let mut api = get_test_api_for_reject(
            RejectContext {
                code: RejectCode::CanisterReject,
                message: "error".to_string(),
            },
            system_state_accessor,
        );

        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_arg_data_size());
        assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject_code());
        assert_api_supported(api.ic0_msg_reject_msg_size());
        assert_api_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_supported(api.ic0_msg_cycles_available());
        assert_api_supported(api.ic0_msg_cycles_available128());
        assert_api_supported(api.ic0_msg_cycles_refunded());
        assert_api_supported(api.ic0_msg_cycles_refunded128());
        assert_api_supported(api.ic0_msg_cycles_accept(0));
        assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_reject_api_support_non_nns() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = get_system_state_for_reject();
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, Arc::new(cycles_account_manager));
        let mut api = get_test_api_for_reject(
            RejectContext {
                code: RejectCode::CanisterReject,
                message: "error".to_string(),
            },
            system_state_accessor,
        );

        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_arg_data_size());
        assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_supported(api.ic0_msg_reply());
        assert_api_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_supported(api.ic0_msg_reject_code());
        assert_api_supported(api.ic0_msg_reject_msg_size());
        assert_api_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_supported(api.ic0_msg_cycles_available());
        assert_api_supported(api.ic0_msg_cycles_available128());
        assert_api_supported(api.ic0_msg_cycles_refunded());
        assert_api_supported(api.ic0_msg_cycles_refunded128());
        assert_api_supported(api.ic0_msg_cycles_accept(0));
        assert_api_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_pre_upgrade_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let mut api = get_system_api(
            ApiType::pre_upgrade(mock_time(), user_test_id(1).get()),
            system_state,
            cycles_account_manager,
        );

        assert_api_not_supported(api.ic0_msg_arg_data_size());
        assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_caller_size());
        assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_not_supported(api.ic0_msg_reply());
        assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_not_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_start_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemState::new_for_start(canister_test_id(91));
        let mut api = get_system_api(ApiType::start(), system_state, cycles_account_manager);

        assert_api_not_supported(api.ic0_msg_arg_data_size());
        assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_not_supported(api.ic0_msg_reply());
        assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_canister_self_size());
        assert_api_not_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_controller_size());
        assert_api_not_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_not_supported(api.ic0_call_perform());
        assert_api_not_supported(api.ic0_stable_size());
        assert_api_not_supported(api.ic0_stable_grow(1));
        assert_api_not_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_stable64_size());
        assert_api_not_supported(api.ic0_stable64_grow(1));
        assert_api_not_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_time());
        assert_api_not_supported(api.ic0_canister_cycle_balance());
        assert_api_not_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_not_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_cleanup_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let mut api = get_system_api(
            ApiType::Cleanup { time: mock_time() },
            system_state,
            cycles_account_manager,
        );

        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_arg_data_size());
        assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_reply());
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_not_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_inspect_message_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let mut api = get_system_api(
            ApiType::inspect_message(
                user_test_id(1).get(),
                "hello".to_string(),
                vec![],
                mock_time(),
            ),
            system_state,
            cycles_account_manager,
        );

        assert_api_supported(api.ic0_msg_caller_size());
        assert_api_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_arg_data_size());
        assert_api_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_msg_method_name_size());
        assert_api_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_accept_message());
        assert_api_not_supported(api.ic0_msg_reply());
        assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_not_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_not_supported(api.ic0_call_cycles_add(0));
        assert_api_not_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_canister_heartbeat_support() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemStateBuilder::default().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(50),
            );

        let mut api = get_system_api(
            get_heartbeat_api_type(),
            system_state,
            cycles_account_manager,
        );

        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_arg_data_size());
        assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_not_supported(api.ic0_msg_reply());
        assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        assert_api_not_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_canister_heartbeat_support_nns() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(SubnetType::System)
            .build();
        let mut system_state = SystemStateBuilder::new().build();

        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(50),
            );

        let mut api = get_system_api(
            get_heartbeat_api_type(),
            system_state,
            cycles_account_manager,
        );

        assert_api_not_supported(api.ic0_msg_caller_size());
        assert_api_not_supported(api.ic0_msg_caller_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_arg_data_size());
        assert_api_not_supported(api.ic0_msg_arg_data_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_msg_method_name_size());
        assert_api_not_supported(api.ic0_msg_method_name_copy(0, 0, 0, &mut []));
        assert_api_not_supported(api.ic0_accept_message());
        assert_api_not_supported(api.ic0_msg_reply());
        assert_api_not_supported(api.ic0_msg_reply_data_append(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject(0, 0, &[]));
        assert_api_not_supported(api.ic0_msg_reject_code());
        assert_api_not_supported(api.ic0_msg_reject_msg_size());
        assert_api_not_supported(api.ic0_msg_reject_msg_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_canister_self_size());
        assert_api_supported(api.ic0_canister_self_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_controller_size());
        assert_api_supported(api.ic0_controller_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
        assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
        assert_api_supported(api.ic0_call_on_cleanup(0, 0));
        assert_api_supported(api.ic0_call_cycles_add(0));
        assert_api_supported(api.ic0_call_perform());
        assert_api_supported(api.ic0_stable_size());
        assert_api_supported(api.ic0_stable_grow(1));
        assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_stable64_size());
        assert_api_supported(api.ic0_stable64_grow(1));
        assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        assert_api_supported(api.ic0_time());
        assert_api_supported(api.ic0_canister_cycle_balance());
        assert_api_supported(api.ic0_canister_cycles_balance128());
        assert_api_not_supported(api.ic0_msg_cycles_available());
        assert_api_not_supported(api.ic0_msg_cycles_available128());
        assert_api_not_supported(api.ic0_msg_cycles_refunded());
        assert_api_not_supported(api.ic0_msg_cycles_refunded128());
        assert_api_not_supported(api.ic0_msg_cycles_accept(0));
        assert_api_not_supported(api.ic0_msg_cycles_accept128(Cycles::zero()));
        assert_api_supported(api.ic0_data_certificate_present());
        assert_api_not_supported(api.ic0_data_certificate_size());
        assert_api_not_supported(api.ic0_data_certificate_copy(0, 0, 0, &mut []));
        assert_api_supported(api.ic0_certified_data_set(0, 0, &[]));
        assert_api_supported(api.ic0_canister_status());
        // Only supported on NNS.
        assert_api_supported(api.ic0_mint_cycles(0));
    }

    #[test]
    fn test_valid_subslice() {
        // empty slice
        assert!(valid_subslice("", 0, 0, &[]).is_ok());
        // the only possible non-empty slice
        assert!(valid_subslice("", 0, 1, &[1]).is_ok());
        // valid empty slice
        assert!(valid_subslice("", 1, 0, &[1]).is_ok());

        // just some valid cases
        assert!(valid_subslice("", 0, 4, &[1, 2, 3, 4]).is_ok());
        assert!(valid_subslice("", 1, 3, &[1, 2, 3, 4]).is_ok());
        assert!(valid_subslice("", 2, 2, &[1, 2, 3, 4]).is_ok());

        // invalid longer-than-the-heap subslices
        assert!(valid_subslice("", 3, 2, &[1, 2, 3, 4]).is_err());
        assert!(valid_subslice("", 0, 5, &[1, 2, 3, 4]).is_err());
        assert!(valid_subslice("", 4, 1, &[1, 2, 3, 4]).is_err());
    }

    #[test]
    fn test_discard_cycles_charge_by_new_call() {
        let cycles_amount = Cycles::from(1_000_000_000_000u128);
        let max_num_instructions = NumInstructions::from(1 << 30);
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_max_num_instructions(max_num_instructions)
            .build();
        let system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        // Check ic0_canister_cycle_balance after first ic0_call_new.
        assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
        // Check cycles balance.
        assert_eq!(
            Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
            cycles_amount
        );

        // Add cycles to call.
        let amount = Cycles::from(49);
        assert_eq!(api.ic0_call_cycles_add128(amount), Ok(()));
        // Check cycles balance after call_add_cycles.
        assert_eq!(
            Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
            cycles_amount - amount
        );

        // Discard the previous call
        assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
        // Check cycles balance -> should be the same as the original as the call was
        // discarded.
        assert_eq!(
            Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
            cycles_amount
        );
    }

    #[test]
    fn test_fail_add_cycles_when_not_enough_balance() {
        let cycles_amount = Cycles::from(1_000_000_000_000u128);
        let max_num_instructions = NumInstructions::from(1 << 30);
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_max_num_instructions(max_num_instructions)
            .build();
        let system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        // Check ic0_canister_cycle_balance after first ic0_call_new.
        assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
        // Check cycles balance.
        assert_eq!(
            Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
            cycles_amount
        );

        // Add cycles to call.
        let amount = cycles_amount + Cycles::from(1);
        assert_eq!(
            api.ic0_call_cycles_add128(amount).unwrap_err(),
            HypervisorError::InsufficientCyclesBalance {
                available: cycles_amount,
                requested: amount,
            }
        );
        //Check cycles balance after call_add_cycles.
        assert_eq!(
            Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
            cycles_amount
        );
    }

    #[test]
    fn test_fail_adding_more_cycles_when_not_enough_balance() {
        let cycles_amount = 1_000_000_000_000;
        let max_num_instructions = NumInstructions::from(1 << 30);
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_max_num_instructions(max_num_instructions)
            .build();
        let system_state =
            get_new_running_system_state(Cycles::from(cycles_amount), SubnetType::Application);
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        // Check ic0_canister_cycle_balance after first ic0_call_new.
        assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
        // Check cycles balance.
        assert_eq!(
            api.ic0_canister_cycle_balance().unwrap() as u128,
            cycles_amount
        );

        // Add cycles to call.
        let amount = cycles_amount / 2 + 1;
        assert_eq!(
            api.ic0_call_cycles_add128(amount.try_into().unwrap()),
            Ok(())
        );
        // Check cycles balance after call_add_cycles.
        assert_eq!(
            api.ic0_canister_cycle_balance().unwrap() as u128,
            cycles_amount - amount
        );

        // Adding more cycles fails because not enough balance left.
        assert_eq!(
            api.ic0_call_cycles_add128(amount.try_into().unwrap())
                .unwrap_err(),
            HypervisorError::InsufficientCyclesBalance {
                available: Cycles::from(cycles_amount - amount),
                requested: Cycles::from(amount),
            }
        );
        // Balance unchanged after the second call_add_cycles.
        assert_eq!(
            api.ic0_canister_cycle_balance().unwrap() as u128,
            cycles_amount - amount
        );
    }

    #[test]
    fn test_canister_balance() {
        let cycles_amount = 100;
        let max_num_instructions = NumInstructions::from(1 << 30);
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_max_num_instructions(max_num_instructions)
            .build();
        let mut system_state =
            get_new_running_system_state(Cycles::from(cycles_amount), SubnetType::Application);

        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(50),
            );

        let api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        // Check cycles balance.
        assert_eq!(api.ic0_canister_cycle_balance().unwrap(), cycles_amount);
    }

    #[test]
    fn test_canister_cycle_balance() {
        let cycles_amount = Cycles::from(123456789012345678901234567890u128);
        let max_num_instructions = NumInstructions::from(1 << 30);
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_max_num_instructions(max_num_instructions)
            .build();
        let mut system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);

        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(50),
            );

        let api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        // Check ic0_canister_cycle_balance.
        assert_eq!(
            api.ic0_canister_cycle_balance(),
            Err(HypervisorError::Trapped(CyclesAmountTooBigFor64Bit))
        );
        let (high, low) = api.ic0_canister_cycles_balance128().unwrap();
        assert_eq!(Cycles::from_parts(high, low), cycles_amount);
    }

    #[test]
    fn test_msg_cycles_available_traps() {
        let cycles_amount = Cycles::from(123456789012345678901234567890u128);
        let available_cycles = Cycles::from(789012345678901234567890u128);
        let mut system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                available_cycles,
            );

        let api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        assert_eq!(
            api.ic0_msg_cycles_available(),
            Err(HypervisorError::Trapped(CyclesAmountTooBigFor64Bit))
        );
        let (high, low) = api.ic0_msg_cycles_available128().unwrap();
        assert_eq!(Cycles::from_parts(high, low), available_cycles);
    }

    #[test]
    fn test_msg_cycles_refunded_traps() {
        let incoming_cycles = Cycles::from(789012345678901234567890u128);
        let cycles_amount = Cycles::from(123456789012345678901234567890u128);
        let system_state = get_new_running_system_state(cycles_amount, SubnetType::Application);
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let api = get_system_api(
            get_reply_api_type(incoming_cycles),
            system_state,
            cycles_account_manager,
        );

        assert_eq!(
            api.ic0_msg_cycles_refunded(),
            Err(HypervisorError::Trapped(CyclesAmountTooBigFor64Bit))
        );
        let (high, low) = api.ic0_msg_cycles_refunded128().unwrap();
        assert_eq!(Cycles::from_parts(high, low), incoming_cycles);
    }

    #[test]
    fn certified_data_set() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);
        let heap = vec![10; 33];

        // Setting more than 32 bytes fails.
        assert!(api.ic0_certified_data_set(0, 33, &heap).is_err());

        // Setting out of bounds size fails.
        assert!(api.ic0_certified_data_set(30, 10, &heap).is_err());

        // Copy the certified data into the system state.
        api.ic0_certified_data_set(0, 32, &heap).unwrap();

        let system_state_accessor = api.release_system_state_accessor();
        assert_eq!(
            system_state_accessor.release_system_state().certified_data,
            vec![10; 32]
        )
    }

    #[test]
    fn data_certificate_copy() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state = SystemStateBuilder::default().build();
        let api = get_system_api(
            ApiType::replicated_query(
                mock_time(),
                vec![],
                user_test_id(1).get(),
                Some(vec![1, 2, 3, 4, 5, 6]),
            ),
            system_state,
            cycles_account_manager,
        );
        let mut heap = vec![0; 10];

        // Copying with out of bounds offset + size fails.
        assert!(api.ic0_data_certificate_copy(0, 0, 10, &mut heap).is_err());
        assert!(api.ic0_data_certificate_copy(0, 10, 1, &mut heap).is_err());

        // Copying with out of bounds dst + size fails.
        assert!(api.ic0_data_certificate_copy(10, 1, 1, &mut heap).is_err());
        assert!(api.ic0_data_certificate_copy(0, 1, 11, &mut heap).is_err());

        // Copying all the data certificate.
        api.ic0_data_certificate_copy(0, 0, 6, &mut heap).unwrap();
        assert_eq!(heap, vec![1, 2, 3, 4, 5, 6, 0, 0, 0, 0]);

        // Copying part of the data certificate.
        api.ic0_data_certificate_copy(6, 2, 4, &mut heap).unwrap();
        assert_eq!(heap, vec![1, 2, 3, 4, 5, 6, 3, 4, 5, 6]);
    }

    #[test]
    fn canister_status() {
        let own_subnet_type = SubnetType::Application;
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let running_system_state = get_new_running_system_state(INITIAL_CYCLES, own_subnet_type);

        let api = get_system_api(
            get_update_api_type(),
            running_system_state,
            cycles_account_manager,
        );
        assert_eq!(api.ic0_canister_status(), Ok(1));

        let stopping_system_state = SystemState::new_stopping(
            canister_test_id(42),
            user_test_id(24).get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let api = get_system_api(
            get_update_api_type(),
            stopping_system_state,
            cycles_account_manager,
        );
        assert_eq!(api.ic0_canister_status(), Ok(2));

        let stopped_system_state = SystemState::new_stopped(
            canister_test_id(42),
            user_test_id(24).get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let api = get_system_api(
            get_update_api_type(),
            stopped_system_state,
            cycles_account_manager,
        );
        assert_eq!(api.ic0_canister_status(), Ok(3));
    }

    /// msg_cycles_accept() can accept all cycles in call context
    #[test]
    fn msg_cycles_accept_all_cycles_in_call_context() {
        let amount = 50;
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemStateBuilder::default().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(amount),
            );
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        assert_eq!(api.ic0_msg_cycles_accept(amount), Ok(amount));
    }

    /// msg_cycles_accept() can accept all cycles in call context when more
    /// asked for
    #[test]
    fn msg_cycles_accept_all_cycles_in_call_context_when_more_asked() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut system_state = SystemStateBuilder::default().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(40),
            );
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        assert_eq!(api.ic0_msg_cycles_accept(50), Ok(40));
    }

    /// msg_cycles_accept() can accept till max it can store
    #[test]
    fn msg_cycles_accept_accept_till_max_on_application_subnet() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_cycles_limit_per_canister(Some(CYCLES_LIMIT_PER_CANISTER))
            .build();
        let mut system_state = SystemStateBuilder::default().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(40),
            );

        // Set cycles balance to max - 10.
        cycles_account_manager.add_cycles(&mut system_state, CYCLES_LIMIT_PER_CANISTER);
        cycles_account_manager
            .withdraw_cycles_for_transfer(
                &mut system_state,
                NumBytes::from(0),
                ComputeAllocation::default(),
                Cycles::from(10),
            )
            .unwrap();

        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        assert_eq!(api.ic0_msg_cycles_accept(50), Ok(10));
    }

    #[test]
    fn msg_cycles_accept_max_cycles_per_canister_none_on_application_subnet() {
        let cycles = 10_000_000_000;
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_cycles_limit_per_canister(None)
            .build();
        let mut system_state = SystemStateBuilder::new().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(cycles),
            );

        cycles_account_manager.add_cycles(&mut system_state, CYCLES_LIMIT_PER_CANISTER);

        let mut api = get_system_api_with_max_cycles_per_canister(
            get_update_api_type(),
            system_state,
            cycles_account_manager,
        );

        assert_eq!(api.ic0_msg_cycles_accept(cycles), Ok(cycles));
        let balance = api.ic0_canister_cycle_balance().unwrap();
        assert!(Cycles::from(balance) > CYCLES_LIMIT_PER_CANISTER);
    }

    /// msg_cycles_accept() can accept above max
    #[test]
    fn msg_cycles_accept_above_max_on_nns() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(SubnetType::System)
            .build();
        let mut system_state = SystemStateBuilder::new().build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(40),
            );

        // Set cycles balance to max - 10.
        cycles_account_manager.add_cycles(&mut system_state, CYCLES_LIMIT_PER_CANISTER);
        cycles_account_manager
            .withdraw_cycles_for_transfer(
                &mut system_state,
                NumBytes::from(0),
                ComputeAllocation::default(),
                Cycles::from(10),
            )
            .unwrap();

        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        assert_eq!(api.ic0_msg_cycles_accept(50), Ok(40));
        let balance = api.ic0_canister_cycle_balance().unwrap();
        assert!(Cycles::from(balance) > CYCLES_LIMIT_PER_CANISTER);
    }

    /// If call call_perform() fails because canister does not have enough
    /// cycles to send the message, then the state is reset.
    #[test]
    fn call_perform_not_enough_cycles_resets_state() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(SubnetType::Application)
            .build();
        // Set initial cycles small enough so that it does not have enough
        // cycles to send xnet messages.
        let initial_cycles = cycles_account_manager.xnet_call_performed_fee() - Cycles::from(10);
        let mut system_state = SystemStateBuilder::new()
            .initial_cycles(initial_cycles)
            .build();
        system_state
            .call_context_manager_mut()
            .unwrap()
            .new_call_context(
                CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
                Cycles::from(40),
            );
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);
        api.ic0_call_new(0, 10, 0, 10, 0, 0, 0, 0, &[0; 1024])
            .unwrap();
        api.ic0_call_cycles_add128(Cycles::from(100)).unwrap();
        assert_eq!(api.ic0_call_perform().unwrap(), 2);
        let system_state = api.release_system_state_accessor().release_system_state();
        let call_context_manager = system_state.call_context_manager().unwrap();
        assert_eq!(call_context_manager.call_contexts().len(), 1);
        assert_eq!(call_context_manager.callbacks().len(), 0);
        assert_eq!(system_state.cycles_balance, initial_cycles);
    }

    #[test]
    fn mint_all_cycles() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(SubnetType::System)
            .build();
        let system_state = SystemStateBuilder::new().build();
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);
        let balance_before = api.system_state_accessor.canister_cycles_balance();

        let amount = 50;
        assert_eq!(api.ic0_mint_cycles(amount), Ok(amount));
        assert_eq!(
            api.system_state_accessor.canister_cycles_balance() - balance_before,
            Cycles::from(amount)
        );
    }

    #[test]
    fn mint_cycles_above_max() {
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(SubnetType::System)
            .build();
        let mut system_state = SystemStateBuilder::new().build();

        // Set cycles balance to max - 10.
        cycles_account_manager.add_cycles(&mut system_state, CYCLES_LIMIT_PER_CANISTER);
        cycles_account_manager
            .withdraw_cycles_for_transfer(
                &mut system_state,
                NumBytes::from(0),
                ComputeAllocation::default(),
                Cycles::from(10),
            )
            .unwrap();

        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);
        let balance_before = api.system_state_accessor.canister_cycles_balance();

        let amount = 50;
        // Canisters on the System subnet can hold any amount of cycles
        assert_eq!(api.ic0_mint_cycles(amount), Ok(amount));
        assert_eq!(
            api.system_state_accessor.canister_cycles_balance() - balance_before,
            Cycles::from(amount)
        );
    }

    #[test]
    fn mint_cycles_fails_caller_not_on_nns() {
        let system_state = SystemStateBuilder::default().build();
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let mut api = get_system_api(get_update_api_type(), system_state, cycles_account_manager);

        let balance_before = api.system_state_accessor.canister_cycles_balance();

        assert!(api.ic0_mint_cycles(50).is_err());
        assert_eq!(
            api.system_state_accessor.canister_cycles_balance() - balance_before,
            Cycles::from(0)
        );
    }

    #[test]
    fn stable_grow_updates_subnet_available_memory() {
        let wasm_page_size = 64 << 10;
        let wasm_page_size_bytes = NumBytes::from(wasm_page_size);
        let subnet_available_memory_bytes = NumBytes::from(2 * wasm_page_size);
        let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes);
        let system_state = SystemStateBuilder::default().build();
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, Arc::new(cycles_account_manager));
        let mut api = SystemApiImpl::new(
            get_update_api_type(),
            system_state_accessor,
            CANISTER_CURRENT_MEMORY_USAGE,
            ExecutionParameters {
                subnet_available_memory: subnet_available_memory.clone(),
                ..execution_parameters()
            },
            no_op_logger(),
        );

        assert_eq!(api.ic0_stable_grow(1).unwrap(), 0);
        assert_eq!(subnet_available_memory.clone().get(), wasm_page_size_bytes);

        assert_eq!(api.ic0_stable_grow(10).unwrap(), -1);
        assert_eq!(subnet_available_memory.get(), wasm_page_size_bytes);
    }

    #[test]
    fn update_available_memory_updates_subnet_available_memory() {
        let wasm_page_size = 64 << 10;
        let wasm_page_size_bytes = NumBytes::from(wasm_page_size);
        let subnet_available_memory_bytes = NumBytes::from(2 * wasm_page_size);
        let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes);
        let system_state = SystemStateBuilder::default().build();
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, Arc::new(cycles_account_manager));
        let mut api = SystemApiImpl::new(
            get_update_api_type(),
            system_state_accessor,
            CANISTER_CURRENT_MEMORY_USAGE,
            ExecutionParameters {
                subnet_available_memory: subnet_available_memory.clone(),
                ..execution_parameters()
            },
            no_op_logger(),
        );

        api.update_available_memory(0, 1).unwrap();
        assert_eq!(subnet_available_memory.clone().get(), wasm_page_size_bytes);

        api.update_available_memory(0, 10).unwrap_err();
        assert_eq!(subnet_available_memory.get(), wasm_page_size_bytes);
    }
}
