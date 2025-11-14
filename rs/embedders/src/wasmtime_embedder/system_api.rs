use candid::{CandidType, DecoderConfig, decode_one_with_config};
use ic_base_types::{InternalAddress, PrincipalIdBlobParseError};
use ic_config::embedders::{Config as EmbeddersConfig, StableMemoryPageLimit};
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::ResourceSaturation;
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::{
    ExecutionMode,
    HypervisorError::{self, *},
    HypervisorResult, MessageMemoryUsage, OutOfInstructionsHandler, PerformanceCounterType,
    StableGrowOutcome, StableMemoryApi, SubnetAvailableMemory, SystemApi, SystemApiCallCounters,
    TrapCode::{self, CyclesAmountTooBigFor64Bit},
};
use ic_logger::{ReplicaLogger, error};
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, IC_00, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
    VetKdKeyId,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::execution_state::WasmExecutionMode;
use ic_replicated_state::{
    Memory, NumWasmPages, canister_state::WASM_PAGE_SIZE_IN_BYTES, memory_usage_of_request,
};
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::{
    CanisterId, CanisterLog, CanisterTimer, ComputeAllocation, Cycles, MemoryAllocation, NumBytes,
    NumInstructions, NumOsPages, PrincipalId, SubnetId, Time,
    ingress::WasmResult,
    messages::{CallContextId, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, RejectContext, Request},
    methods::{SystemMethod, WasmClosure},
};
use ic_utils::deterministic_operations::deterministic_copy_from_slice;
use ic_wasm_types::doc_ref;
use request_in_prep::{RequestInPrep, into_request};
use sandbox_safe_system_state::{SandboxSafeSystemState, SystemStateModifications};
use serde::{Deserialize, Serialize};
use stable_memory::StableMemory;
use std::time::Duration;
use std::{
    collections::BTreeMap,
    convert::{From, TryFrom},
    rc::Rc,
    str,
};

pub mod cycles_balance_change;
use cycles_balance_change::CyclesBalanceChange;
mod request_in_prep;
mod routing;
pub mod sandbox_safe_system_state;
mod stable_memory;

pub const MULTIPLIER_MAX_SIZE_LOCAL_SUBNET: u64 = 5;
const MAX_NON_REPLICATED_QUERY_REPLY_SIZE: NumBytes = NumBytes::new(3 << 20);
const CERTIFIED_DATA_MAX_LENGTH: usize = 32;

// Enables tracing of system calls for local debugging.
const TRACE_SYSCALLS: bool = false;

const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: u64 = 64 * 1024; // 4GiB

/// Upper bound on `timeout` when using calls with
/// best-effort responses represented in seconds.
pub const MAX_CALL_TIMEOUT_SECONDS: u32 = 300;

/// The maximum size of an environment variable name.
pub const MAX_ENV_VAR_NAME_SIZE: usize = 100;

// This macro is used in system calls for tracing.
macro_rules! trace_syscall {
    ($self:ident, $name:ident, $result:expr_2021 $( , $args:expr_2021 )*) => {{
        if TRACE_SYSCALLS {
            // Output to both logger and stderr to simplify debugging.
            error!(
                $self.log,
                "[system-api][{}] {}: {:?} => {:?}",
                $self.sandbox_safe_system_state.canister_id,
                stringify!($name),
                ($(&$args, )*),
                &$result
            );
            eprintln!(
                "[system-api][{}] {}: {:?} => {:?}",
                $self.sandbox_safe_system_state.canister_id,
                stringify!($name),
                ($(&$args, )*),
                &$result
            );
        }
    }}
}

// This helper is used in system calls for displaying a summary hash of a heap region.
#[inline]
fn summarize(heap: &[u8], start: usize, size: usize) -> u64 {
    if TRACE_SYSCALLS {
        let start = start.min(heap.len());
        let end = (start + size).min(heap.len());
        // The actual hash function doesn't matter much as long as it is
        // cheap to compute and maps the input to u64 reasonably well.
        let mut sum = 0;
        for (i, byte) in heap[start..end].iter().enumerate() {
            sum += (i + 1) as u64 * *byte as u64
        }
        sum
    } else {
        0
    }
}

/// Keeps the message instruction limit and the maximum slice instruction limit.
/// Supports operations to reduce the message limit while keeping the maximum
/// slice limit the same, which is useful for messages that have multiple
/// execution steps such as install, upgrade, and response.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct InstructionLimits {
    /// The total instruction limit for message execution. With deterministic
    /// time slicing this limit may exceed the per-round instruction limit.  The
    /// message fails with an `InstructionLimitExceeded` error if it executes
    /// more instructions than this limit.
    message: NumInstructions,

    /// The instruction limit to report in case of an error.
    limit_to_report: NumInstructions,

    /// The number of instructions in the largest possible slice. It may
    /// exceed `self.message()` if the latter was reduced or updated by the
    /// previous executions.
    max_slice: NumInstructions,
}

impl InstructionLimits {
    /// Returns the message and slice instruction limits.
    pub fn new(message: NumInstructions, max_slice: NumInstructions) -> Self {
        Self {
            message,
            limit_to_report: message,
            max_slice,
        }
    }

    /// See the comments of the corresponding field.
    pub fn message(&self) -> NumInstructions {
        self.message
    }

    /// See the comments of the corresponding field.
    pub fn limit_to_report(&self) -> NumInstructions {
        self.limit_to_report
    }

    /// Returns the effective slice size, which is the smallest of
    /// `self.max_slice` and `self.message`.
    pub fn slice(&self) -> NumInstructions {
        self.max_slice.min(self.message)
    }

    /// Reduces the message instruction limit by the given number.
    /// Note that with DTS, the slice size is constant for a fixed message type.
    pub fn reduce_by(&mut self, used: NumInstructions) {
        self.message = NumInstructions::from(self.message.get().saturating_sub(used.get()));
    }

    /// Sets the message instruction limit to the given number.
    /// Note that with DTS, the slice size is constant for a fixed message type.
    pub fn update(&mut self, left: NumInstructions) {
        self.message = left;
    }

    /// Checks if DTS is enabled.
    pub fn slicing_enabled(self) -> bool {
        self.max_slice < self.message
    }
}

// Canister and subnet configuration parameters required for execution.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExecutionParameters {
    pub instruction_limits: InstructionLimits,
    // The limit on the Wasm memory set by the developer in canister settings.
    pub wasm_memory_limit: Option<NumBytes>,
    pub memory_allocation: MemoryAllocation,
    pub canister_guaranteed_callback_quota: u64,
    pub compute_allocation: ComputeAllocation,
    pub subnet_type: SubnetType,
    pub execution_mode: ExecutionMode,
    pub subnet_memory_saturation: ResourceSaturation,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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

/// This enum indicates whether state modifications are important for
/// an API type or not.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ModificationTracking {
    Ignore,
    Track,
}

/// Describes the context within which a canister message is executed.
///
/// The `Arc` values in this type are safe to serialize because the contain
/// read-only data that is only shared for cheap cloning. Serializing and
/// deserializing will result in duplication of the data, but no issues in
/// correctness.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum ApiType {
    /// For executing the `canister_start` method.
    Start {
        time: Time,
    },

    /// For executing the `canister_init` or `canister_post_upgrade` method.
    Init {
        time: Time,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
    },

    /// For executing canister methods marked as `update`.
    Update {
        time: Time,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        caller: PrincipalId,
        call_context_id: CallContextId,
        /// Begins as empty and used to accumulate data for sending replies.
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
    },

    // For executing canister methods marked as `query` in replicated mode.
    ReplicatedQuery {
        time: Time,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
        call_context_id: CallContextId,
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        max_reply_size: NumBytes,
    },

    // For executing canister methods marked as `query` in non-replicated mode.
    NonReplicatedQuery {
        time: Time,
        caller: PrincipalId,
        own_subnet_id: SubnetId,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        data_certificate: Option<Vec<u8>>,
        // Begins as empty and used to accumulate data for sending replies.
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        max_reply_size: NumBytes,
    },

    // For executing canister methods marked as `composite_query`.
    CompositeQuery {
        time: Time,
        caller: PrincipalId,
        own_subnet_id: SubnetId,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        data_certificate: Option<Vec<u8>>,
        // Begins as empty and used to accumulate data for sending replies.
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        max_reply_size: NumBytes,
        call_context_id: CallContextId,
        outgoing_request: Option<RequestInPrep>,
    },

    // For executing closures when a `Reply` is received in replicated mode.
    ReplyCallback {
        time: Time,
        caller: PrincipalId,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        // Begins as empty and used to accumulate data for sending replies.
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
        /// The total number of instructions executed in the call context
        call_context_instructions_executed: NumInstructions,
    },

    // For executing closures when a `Reply` is received in a composite query context.
    CompositeReplyCallback {
        time: Time,
        caller: PrincipalId,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        // Begins as empty and used to accumulate data for sending replies.
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
        /// The total number of instructions executed in the call context
        call_context_instructions_executed: NumInstructions,
    },

    // For executing closures when a `Reject` is received in replicated mode.
    RejectCallback {
        time: Time,
        caller: PrincipalId,
        reject_context: RejectContext,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        // Begins as empty and used to accumulate data for sending replies.
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
        /// The total number of instructions executed in the call context
        call_context_instructions_executed: NumInstructions,
    },

    // For executing closures when a `Reject` is received in a composite query context.
    CompositeRejectCallback {
        time: Time,
        caller: PrincipalId,
        reject_context: RejectContext,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        // Begins as empty and used to accumulate data for sending replies.
        #[serde(with = "serde_bytes")]
        response_data: Vec<u8>,
        response_status: ResponseStatus,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
        max_reply_size: NumBytes,
        /// The total number of instructions executed in the call context
        call_context_instructions_executed: NumInstructions,
    },

    // For executing the `canister_pre_upgrade` method.
    PreUpgrade {
        caller: PrincipalId,
        time: Time,
    },

    /// For executing `canister_inspect_message` method that allows the canister
    /// to decide pre-consensus if it actually wants to accept the message or
    /// not.
    InspectMessage {
        caller: PrincipalId,
        method_name: String,
        #[serde(with = "serde_bytes")]
        incoming_payload: Vec<u8>,
        time: Time,
        message_accepted: bool,
    },

    // For executing the `canister_heartbeat` or `canister_global_timer` or `canister_on_low_wasm_memory` methods
    SystemTask {
        caller: PrincipalId,
        /// System task to execute.
        /// Only `canister_heartbeat`, `canister_global_timer`, and `canister_on_low_wasm_memory` are allowed.
        system_task: SystemMethod,
        time: Time,
        call_context_id: CallContextId,
        /// Optional outgoing request under construction. If `None` no outgoing
        /// request is currently under construction.
        outgoing_request: Option<RequestInPrep>,
    },

    /// For executing the `call_on_cleanup` callback.
    ///
    /// The `call_on_cleanup` callback is executed iff the `reply` or the
    /// `reject` callback was executed and trapped (for any reason).
    ///
    /// See https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-call
    Cleanup {
        caller: PrincipalId,
        time: Time,
        /// The total number of instructions executed in the call context
        call_context_instructions_executed: NumInstructions,
    },

    /// Like `Cleanup`, but used in a composite query context.
    CompositeCleanup {
        caller: PrincipalId,
        time: Time,
        /// The total number of instructions executed in the call context
        call_context_instructions_executed: NumInstructions,
    },
}

impl ApiType {
    pub fn start(time: Time) -> Self {
        Self::Start { time }
    }

    pub fn init(time: Time, incoming_payload: Vec<u8>, caller: PrincipalId) -> Self {
        Self::Init {
            time,
            incoming_payload,
            caller,
        }
    }

    pub fn system_task(
        system_task: SystemMethod,
        time: Time,
        call_context_id: CallContextId,
    ) -> Self {
        Self::SystemTask {
            caller: IC_00.get(),
            time,
            call_context_id,
            outgoing_request: None,
            system_task,
        }
    }

    pub fn update(
        time: Time,
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        caller: PrincipalId,
        call_context_id: CallContextId,
    ) -> Self {
        Self::Update {
            time,
            incoming_payload,
            incoming_cycles,
            caller,
            call_context_id,
            response_data: vec![],
            response_status: ResponseStatus::NotRepliedYet,
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        }
    }

    pub fn replicated_query(
        time: Time,
        incoming_payload: Vec<u8>,
        caller: PrincipalId,
        call_context_id: CallContextId,
    ) -> Self {
        Self::ReplicatedQuery {
            time,
            incoming_payload,
            caller,
            call_context_id,
            response_data: vec![],
            response_status: ResponseStatus::NotRepliedYet,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        }
    }

    pub fn non_replicated_query(
        time: Time,
        caller: PrincipalId,
        own_subnet_id: SubnetId,
        incoming_payload: Vec<u8>,
        data_certificate: Option<Vec<u8>>,
    ) -> Self {
        Self::NonReplicatedQuery {
            time,
            caller,
            own_subnet_id,
            incoming_payload,
            data_certificate,
            response_data: vec![],
            response_status: ResponseStatus::NotRepliedYet,
            max_reply_size: MAX_NON_REPLICATED_QUERY_REPLY_SIZE,
        }
    }

    pub fn composite_query(
        time: Time,
        caller: PrincipalId,
        own_subnet_id: SubnetId,
        incoming_payload: Vec<u8>,
        data_certificate: Option<Vec<u8>>,
        call_context_id: CallContextId,
    ) -> Self {
        Self::CompositeQuery {
            time,
            caller,
            own_subnet_id,
            incoming_payload,
            data_certificate,
            response_data: vec![],
            response_status: ResponseStatus::NotRepliedYet,
            max_reply_size: MAX_NON_REPLICATED_QUERY_REPLY_SIZE,
            call_context_id,
            outgoing_request: None,
        }
    }

    pub fn reply_callback(
        time: Time,
        caller: PrincipalId,
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        replied: bool,
        call_context_instructions_executed: NumInstructions,
    ) -> Self {
        Self::ReplyCallback {
            time,
            caller,
            incoming_payload,
            incoming_cycles,
            call_context_id,
            response_data: vec![],
            response_status: if replied {
                ResponseStatus::AlreadyReplied
            } else {
                ResponseStatus::NotRepliedYet
            },
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            call_context_instructions_executed,
        }
    }

    pub fn composite_reply_callback(
        time: Time,
        caller: PrincipalId,
        incoming_payload: Vec<u8>,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        replied: bool,
        call_context_instructions_executed: NumInstructions,
    ) -> Self {
        Self::CompositeReplyCallback {
            time,
            caller,
            incoming_payload,
            incoming_cycles,
            call_context_id,
            response_data: vec![],
            response_status: if replied {
                ResponseStatus::AlreadyReplied
            } else {
                ResponseStatus::NotRepliedYet
            },
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            call_context_instructions_executed,
        }
    }

    pub fn reject_callback(
        time: Time,
        caller: PrincipalId,
        reject_context: RejectContext,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        replied: bool,
        call_context_instructions_executed: NumInstructions,
    ) -> Self {
        Self::RejectCallback {
            time,
            caller,
            reject_context,
            incoming_cycles,
            call_context_id,
            response_data: vec![],
            response_status: if replied {
                ResponseStatus::AlreadyReplied
            } else {
                ResponseStatus::NotRepliedYet
            },
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            call_context_instructions_executed,
        }
    }

    pub fn composite_reject_callback(
        time: Time,
        caller: PrincipalId,
        reject_context: RejectContext,
        incoming_cycles: Cycles,
        call_context_id: CallContextId,
        replied: bool,
        call_context_instructions_executed: NumInstructions,
    ) -> Self {
        Self::CompositeRejectCallback {
            time,
            caller,
            reject_context,
            incoming_cycles,
            call_context_id,
            response_data: vec![],
            response_status: if replied {
                ResponseStatus::AlreadyReplied
            } else {
                ResponseStatus::NotRepliedYet
            },
            outgoing_request: None,
            max_reply_size: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            call_context_instructions_executed,
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

    /// Indicates whether state modifications are important for this API type or
    /// not.
    pub fn modification_tracking(&self) -> ModificationTracking {
        match self {
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => ModificationTracking::Ignore,
            ApiType::CompositeQuery { .. }
            | ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. } => ModificationTracking::Track,
        }
    }

    pub fn execution_mode(&self) -> ExecutionMode {
        match self {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. } => ExecutionMode::Replicated,
            ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::InspectMessage { .. } => ExecutionMode::NonReplicated,
        }
    }

    pub fn call_context_id(&self) -> Option<CallContextId> {
        match *self {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::NonReplicatedQuery { .. } => None,
            ApiType::Update {
                call_context_id, ..
            }
            | ApiType::ReplicatedQuery {
                call_context_id, ..
            }
            | ApiType::CompositeQuery {
                call_context_id, ..
            }
            | ApiType::ReplyCallback {
                call_context_id, ..
            }
            | ApiType::CompositeReplyCallback {
                call_context_id, ..
            }
            | ApiType::RejectCallback {
                call_context_id, ..
            }
            | ApiType::CompositeRejectCallback {
                call_context_id, ..
            }
            | ApiType::SystemTask {
                call_context_id, ..
            } => Some(call_context_id),
        }
    }

    /// Returns a string slice representation of the enum variant name for use
    /// e.g. as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiType::Start { .. } => "start",
            ApiType::Init { .. } => "init",
            ApiType::SystemTask { system_task, .. } => match system_task {
                SystemMethod::CanisterHeartbeat => "heartbeat",
                SystemMethod::CanisterGlobalTimer => "global timer",
                SystemMethod::CanisterOnLowWasmMemory => "on low Wasm memory",
                SystemMethod::CanisterStart
                | SystemMethod::CanisterInit
                | SystemMethod::CanisterPreUpgrade
                | SystemMethod::CanisterPostUpgrade
                | SystemMethod::CanisterInspectMessage => {
                    panic!(
                        "Only `canister_heartbeat`, `canister_global_timer`, and `canister_on_low_wasm_memory` are allowed."
                    )
                }
            },
            ApiType::Update { .. } => "update",
            ApiType::ReplicatedQuery { .. } => "replicated query",
            ApiType::NonReplicatedQuery { .. } => "non replicated query",
            ApiType::CompositeQuery { .. } => "composite query",
            ApiType::ReplyCallback { .. } => "reply callback",
            ApiType::CompositeReplyCallback { .. } => "composite reply callback",
            ApiType::RejectCallback { .. } => "reject callback",
            ApiType::CompositeRejectCallback { .. } => "composite reject callback",
            ApiType::PreUpgrade { .. } => "pre upgrade",
            ApiType::InspectMessage { .. } => "inspect message",
            ApiType::Cleanup { .. } => "cleanup",
            ApiType::CompositeCleanup { .. } => "composite cleanup",
        }
    }

    pub fn caller(&self) -> Option<PrincipalId> {
        match self {
            ApiType::Start { .. } => None,
            ApiType::Init { caller, .. }
            | ApiType::SystemTask { caller, .. }
            | ApiType::Update { caller, .. }
            | ApiType::ReplicatedQuery { caller, .. }
            | ApiType::NonReplicatedQuery { caller, .. }
            | ApiType::CompositeQuery { caller, .. }
            | ApiType::ReplyCallback { caller, .. }
            | ApiType::CompositeReplyCallback { caller, .. }
            | ApiType::RejectCallback { caller, .. }
            | ApiType::CompositeRejectCallback { caller, .. }
            | ApiType::PreUpgrade { caller, .. }
            | ApiType::InspectMessage { caller, .. }
            | ApiType::Cleanup { caller, .. }
            | ApiType::CompositeCleanup { caller, .. } => Some(*caller),
        }
    }

    pub fn time(&self) -> &Time {
        match self {
            ApiType::Start { time }
            | ApiType::Init { time, .. }
            | ApiType::SystemTask { time, .. }
            | ApiType::Update { time, .. }
            | ApiType::Cleanup { time, .. }
            | ApiType::CompositeCleanup { time, .. }
            | ApiType::NonReplicatedQuery { time, .. }
            | ApiType::ReplicatedQuery { time, .. }
            | ApiType::CompositeQuery { time, .. }
            | ApiType::PreUpgrade { time, .. }
            | ApiType::ReplyCallback { time, .. }
            | ApiType::CompositeReplyCallback { time, .. }
            | ApiType::RejectCallback { time, .. }
            | ApiType::CompositeRejectCallback { time, .. }
            | ApiType::InspectMessage { time, .. } => time,
        }
    }

    // Returns `true` if subnet available memory should be updated
    // and storage cycles should be reserved for the given
    // API type when growing memory.
    fn should_update_available_memory_and_reserved_cycles(&self) -> bool {
        match self {
            ApiType::Update { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. } => true,

            ApiType::Start { .. } | ApiType::Init { .. } | ApiType::PreUpgrade { .. } => {
                // Individual endpoints of install_code do not update subnet available memory
                // and do not reserve storage cycles.
                // Instead, subnet available memory is updated
                // and storage cycles are reserved at the end of install_code.
                false
            }

            ApiType::InspectMessage { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. } => {
                // Queries do not update subnet available memory
                // and do not reserve storage cycles because the state
                // changes are discarded anyways.
                false
            }
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

#[derive(Debug, PartialEq, Eq)]
enum ExecutionMemoryType {
    WasmMemory,
    StableMemory,
}

#[derive(Debug, Clone, Copy)]
/// Some cost API endpoints can fail in various ways. A return value of this
/// type must be used by the caller to determine success or failure.
pub enum CostReturnCode {
    Success = 0,
    UnknownCurveOrAlgorithm = 1,
    UnknownKey = 2,
}
/// A struct to gather the relevant fields that correspond to a canister's
/// memory consumption.
struct MemoryUsage {
    /// The Wasm memory limit set by the developer in canister settings.
    wasm_memory_limit: Option<NumBytes>,

    /// The current amount of execution memory that the canister is using.
    current_usage: NumBytes,

    /// The current amount of stable memory that the canister is using.
    stable_memory_usage: NumBytes,

    /// The current amount of Wasm memory that the canister is using.
    wasm_memory_usage: NumBytes,

    /// The current amount of message memory that the canister is using.
    current_message_usage: MessageMemoryUsage,

    /// This is the amount of memory that the subnet has available.
    /// New memory allocations (memory usage growth beyond
    /// the memory allocation of the canister) need to be deducted from here.
    subnet_available_memory: SubnetAvailableMemory,

    /// Execution memory allocated during this message execution, i.e.,
    /// wasm/stable memory usage growth beyond
    /// the memory allocation of the canister.
    allocated_execution_memory: NumBytes,

    /// Message memory allocated during this message execution.
    allocated_message_memory: MessageMemoryUsage,

    /// The memory allocation of the canister.
    memory_allocation: MemoryAllocation,
}

impl MemoryUsage {
    fn new(
        wasm_memory_limit: Option<NumBytes>,
        current_usage: NumBytes,
        stable_memory_usage: NumBytes,
        wasm_memory_usage: NumBytes,
        current_message_usage: MessageMemoryUsage,
        subnet_available_memory: SubnetAvailableMemory,
        memory_allocation: MemoryAllocation,
    ) -> Self {
        Self {
            wasm_memory_limit,
            current_usage,
            stable_memory_usage,
            wasm_memory_usage,
            current_message_usage,
            subnet_available_memory,
            allocated_execution_memory: NumBytes::new(0),
            allocated_message_memory: MessageMemoryUsage::ZERO,
            memory_allocation,
        }
    }

    /// Returns the effective Wasm memory limit depending on the message type.
    /// If the result is `None`, then this means that the limit is not enforced
    /// for this message type even if the corresponding field in canister
    /// settings is not empty.
    fn effective_wasm_memory_limit(&self, api_type: &ApiType) -> Option<NumBytes> {
        match api_type {
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. } => {
                // The Wasm memory limit is not enforced on query in order to
                // allow developers to download data from the canister via the
                // query endpoints.
                None
            }
            ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => {
                // The Wasm memory limit is not enforced in response execution.
                // The canister has already made a call to another canister, so
                // introducing a new failure mode here might break canister
                // invariants for existing canisters that were implemented before
                // the Wasm memory limit was introduced.
                None
            }
            ApiType::SystemTask { .. } => {
                // The Wasm memory limit is not enforced in system tasks (timers
                // and heartbeats) until canister logging is implemented.
                // Without canister logging developers do not get error messages
                // from system tasks.
                // TODO(RUN-957): Enforce the limit after canister logging ships.
                None
            }
            ApiType::PreUpgrade { .. } => {
                // The Wasm memory limit is not enforced in pre-upgrade
                // execution in order to allow the developer to upgrade a
                // canister to a new version that uses less memory.
                None
            }
            ApiType::Init { .. } | ApiType::Start { .. } | ApiType::Update { .. } => {
                self.wasm_memory_limit
            }
        }
    }

    /// Tries to allocate the requested amount of the Wasm or stable memory.
    ///
    /// If the canister has memory allocation, then this function only allocates
    /// bytes for memory usage growth beyond the memory allocation.
    /// Nevertheless, this function always increases `current_usage`
    /// by the full amount of memory usage growth.
    ///
    /// Returns `Err(HypervisorError::OutOfMemory)` and leaves `self` unchanged
    /// if the subnet memory limit would be exceeded.
    ///
    /// Returns `Err(HypervisorError::InsufficientCyclesInMemoryGrow)` and
    /// leaves `self` unchanged if freezing threshold check is needed for the
    /// given API type and canister would be frozen after the allocation.
    fn allocate_execution_memory(
        &mut self,
        usage_growth_bytes: NumBytes,
        api_type: &ApiType,
        sandbox_safe_system_state: &mut SandboxSafeSystemState,
        subnet_memory_saturation: &ResourceSaturation,
        execution_memory_type: ExecutionMemoryType,
    ) -> HypervisorResult<()> {
        let (new_usage, overflow) = self
            .current_usage
            .get()
            .overflowing_add(usage_growth_bytes.get());
        if overflow {
            return Err(HypervisorError::OutOfMemory);
        }

        let old_allocated_bytes = self.memory_allocation.allocated_bytes(self.current_usage);
        let new_allocated_bytes = self
            .memory_allocation
            .allocated_bytes(NumBytes::new(new_usage));
        debug_assert!(old_allocated_bytes <= new_allocated_bytes);
        let allocated_bytes = new_allocated_bytes - old_allocated_bytes; // subtraction on `NumBytes` is already saturating

        sandbox_safe_system_state.check_freezing_threshold_for_memory_grow(
            api_type,
            self.current_message_usage,
            old_allocated_bytes,
            new_allocated_bytes,
        )?;

        if api_type.should_update_available_memory_and_reserved_cycles() {
            self.subnet_available_memory
                .try_decrement(allocated_bytes, NumBytes::new(0), NumBytes::new(0))
                .map_err(|_err| HypervisorError::OutOfMemory)?;

            sandbox_safe_system_state.reserve_storage_cycles(
                allocated_bytes,
                &subnet_memory_saturation.add(self.allocated_execution_memory.get()),
            )?;
        }

        self.current_usage = NumBytes::new(new_usage);
        self.allocated_execution_memory += allocated_bytes;

        self.add_execution_memory(usage_growth_bytes, execution_memory_type)?;

        sandbox_safe_system_state.update_status_of_low_wasm_memory_hook_condition(
            self.wasm_memory_limit,
            self.wasm_memory_usage,
        );

        Ok(())
    }

    fn add_execution_memory(
        &mut self,
        execution_bytes: NumBytes,
        execution_memory_type: ExecutionMemoryType,
    ) -> Result<(), HypervisorError> {
        match execution_memory_type {
            ExecutionMemoryType::WasmMemory => {
                add_memory(&mut self.wasm_memory_usage, execution_bytes)
            }
            ExecutionMemoryType::StableMemory => {
                add_memory(&mut self.stable_memory_usage, execution_bytes)
            }
        }
    }

    /// Tries to allocate the requested amount of message memory.
    ///
    /// Returns `Err(HypervisorError::OutOfMemory)` and leaves `self` unchanged
    /// if the guaranteed response message memory limit would be exceeded.
    ///
    /// Returns `Err(HypervisorError::InsufficientCyclesInMessageMemoryGrow)`
    /// and leaves `self` unchanged if freezing threshold check is needed
    /// for the given API type and canister would be frozen after the
    /// allocation.
    fn allocate_message_memory(
        &mut self,
        message_memory_usage: MessageMemoryUsage,
        api_type: &ApiType,
        sandbox_safe_system_state: &SandboxSafeSystemState,
    ) -> HypervisorResult<()> {
        let (new_message_usage, overflow) = self
            .current_message_usage
            .overflowing_add(&message_memory_usage);
        if overflow {
            return Err(HypervisorError::OutOfMemory);
        }

        sandbox_safe_system_state.check_freezing_threshold_for_message_memory_grow(
            api_type,
            self.current_usage,
            self.current_message_usage,
            new_message_usage,
        )?;

        if message_memory_usage.guaranteed_response.get() != 0
            && let Err(_err) = self.subnet_available_memory.try_decrement(
                NumBytes::new(0),
                message_memory_usage.guaranteed_response,
                NumBytes::new(0),
            )
        {
            return Err(HypervisorError::OutOfMemory);
        }

        self.allocated_message_memory += message_memory_usage;
        self.current_message_usage = new_message_usage;
        Ok(())
    }

    /// Deallocates the given amount of message memory.
    ///
    /// Should only be called immediately after `allocate_message_memory()`, with the
    /// same number of bytes, in case allocation failed.
    fn deallocate_message_memory(&mut self, message_memory_usage: MessageMemoryUsage) {
        assert!(
            self.allocated_message_memory.ge(message_memory_usage),
            "Precondition of self.allocated_message_memory in deallocate_message_memory failed: {:?} >= {:?}",
            self.allocated_message_memory,
            message_memory_usage
        );
        assert!(
            self.current_message_usage.ge(message_memory_usage),
            "Precondition of self.current_message_usage in deallocate_message_memory failed: {:?} >= {:?}",
            self.current_message_usage,
            message_memory_usage
        );
        self.subnet_available_memory.increment(
            NumBytes::new(0),
            message_memory_usage.guaranteed_response,
            NumBytes::new(0),
        );
        self.allocated_message_memory -= message_memory_usage;
        self.current_message_usage -= message_memory_usage;
    }
}

fn add_memory(
    memory_size: &mut NumBytes,
    additional_memory: NumBytes,
) -> Result<(), HypervisorError> {
    let (new_usage, overflow) = memory_size.get().overflowing_add(additional_memory.get());

    if overflow {
        return Err(HypervisorError::OutOfMemory);
    }

    *memory_size = NumBytes::new(new_usage);
    Ok(())
}

/// Struct that implements the SystemApi trait. This trait enables a canister to
/// have mediated access to its system state.
pub struct SystemApiImpl {
    /// An execution error of the current message.
    execution_error: Option<HypervisorError>,

    log: ReplicaLogger,

    /// The variant of ApiType being executed.
    api_type: ApiType,

    memory_usage: MemoryUsage,

    execution_parameters: ExecutionParameters,

    /// Canister backtraces are enabled. This means we should attempt to collect
    /// a backtrace if the canister calls the trap API.
    #[allow(unused)]
    canister_backtrace: FlagStatus,

    /// The maximum sum of `<name>` lengths in exported functions called `canister_update <name>`,
    /// `canister_query <name>`, or `canister_composite_query <name>`.
    max_sum_exported_function_name_lengths: usize,

    /// Should not be accessed directly from public APIs. Instead read through
    /// [`Self::stable_memory`] or [`Self::stable_memory_mut`].
    stable_memory: StableMemory,

    /// System state information that is cached so that we don't need to go
    /// through the `SystemStateAccessor` to read it. This saves on IPC
    /// communication between the sandboxed canister process and the main
    /// replica process.
    sandbox_safe_system_state: SandboxSafeSystemState,

    /// A handler that is invoked when the instruction counter becomes negative
    /// (exceeds the current slice instruction limit).
    out_of_instructions_handler: Rc<dyn OutOfInstructionsHandler>,

    /// The instruction limit of the currently executing slice. It is
    /// initialized to `execution_parameters.instruction_limits.slice()` and
    /// updated after each out-of-instructions call that starts a new slice.
    current_slice_instruction_limit: i64,

    /// The total number of instructions executed before the current slice. It
    /// is initialized to 0 and updated after each out-of-instructions call that
    /// starts a new slice.
    instructions_executed_before_current_slice: i64,

    /// How many times each tracked System API call was invoked.
    call_counters: SystemApiCallCounters,
}

impl SystemApiImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_type: ApiType,
        sandbox_safe_system_state: SandboxSafeSystemState,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        execution_parameters: ExecutionParameters,
        subnet_available_memory: SubnetAvailableMemory,
        embedders_config: &EmbeddersConfig,
        stable_memory: Memory,
        wasm_memory_size: NumWasmPages,
        out_of_instructions_handler: Rc<dyn OutOfInstructionsHandler>,
        log: ReplicaLogger,
    ) -> Self {
        let stable_memory_usage = stable_memory
            .size
            .get()
            .checked_mul(WASM_PAGE_SIZE_IN_BYTES)
            .map(|v| NumBytes::new(v as u64))
            .expect("Stable memory size is larger than maximal allowed.");

        let wasm_memory_usage = wasm_memory_size
            .get()
            .checked_mul(WASM_PAGE_SIZE_IN_BYTES)
            .map(|v| NumBytes::new(v as u64))
            .expect("Wasm memory size is larger than maximal allowed.");

        let memory_usage = MemoryUsage::new(
            execution_parameters.wasm_memory_limit,
            canister_current_memory_usage,
            stable_memory_usage,
            wasm_memory_usage,
            canister_current_message_memory_usage,
            subnet_available_memory,
            execution_parameters.memory_allocation,
        );
        let stable_memory = StableMemory::new(stable_memory);
        let slice_limit = execution_parameters.instruction_limits.slice().get();
        Self {
            execution_error: None,
            api_type,
            memory_usage,
            execution_parameters,
            canister_backtrace: embedders_config.feature_flags.canister_backtrace,
            max_sum_exported_function_name_lengths: embedders_config
                .max_sum_exported_function_name_lengths,
            stable_memory,
            sandbox_safe_system_state,
            out_of_instructions_handler,
            log,
            current_slice_instruction_limit: i64::try_from(slice_limit).unwrap_or(i64::MAX),
            instructions_executed_before_current_slice: 0,
            call_counters: SystemApiCallCounters::default(),
        }
    }

    pub fn get_cost_schedule(&self) -> CanisterCyclesCostSchedule {
        self.sandbox_safe_system_state.cost_schedule
    }

    /// Refunds any cycles used for an outgoing request that doesn't get sent
    /// and returns the result of execution.
    pub fn take_execution_result(
        &mut self,
        wasm_run_error: Option<&HypervisorError>,
    ) -> HypervisorResult<Option<WasmResult>> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. } => (),
            ApiType::SystemTask {
                outgoing_request, ..
            }
            | ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeRejectCallback {
                outgoing_request, ..
            } => {
                if let Some(outgoing_request) = outgoing_request.take() {
                    self.sandbox_safe_system_state
                        .refund_cycles(outgoing_request.take_cycles());
                }
            }
        }
        if let Some(err) = wasm_run_error
            .cloned()
            .or_else(|| self.execution_error.take())
        {
            // There is no need to deallocate memory because all state changes
            // are discarded for failed executions anyway.
            return Err(err);
        }
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::SystemTask { .. } => Ok(None),
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
            | ApiType::CompositeQuery {
                response_status, ..
            }
            | ApiType::ReplyCallback {
                response_status, ..
            }
            | ApiType::CompositeReplyCallback {
                response_status, ..
            }
            | ApiType::RejectCallback {
                response_status, ..
            }
            | ApiType::CompositeRejectCallback {
                response_status, ..
            } => match response_status {
                ResponseStatus::JustRepliedWith(result) => Ok(result.take()),
                _ => Ok(None),
            },
        }
    }

    pub fn get_current_memory_usage(&self) -> NumBytes {
        self.memory_usage.current_usage
    }

    pub fn get_current_message_memory_usage(&self) -> MessageMemoryUsage {
        self.memory_usage.current_message_usage
    }

    /// Execution memory allocated during this message execution, i.e.,
    /// wasm/stable memory usage growth beyond
    /// the memory allocation of the canister.
    pub fn get_allocated_bytes(&self) -> NumBytes {
        self.memory_usage.allocated_execution_memory
    }

    /// Bytes used by or reserved for for guaranteed response messages.
    pub fn get_allocated_guaranteed_response_message_bytes(&self) -> NumBytes {
        self.memory_usage
            .allocated_message_memory
            .guaranteed_response
    }

    fn error_for(&self, method_name: &str) -> HypervisorError {
        HypervisorError::UserContractViolation {
            error: format!(
                "\"{}\" cannot be executed in {} mode",
                method_name, self.api_type
            ),
            suggestion: "Check the ICP documentation to make sure APIs are \
            being called in the correct message types."
                .to_string(),
            doc_link: doc_ref("calling-a-system-api-from-the-wrong-mode"),
        }
    }

    fn get_response_info(&mut self) -> Option<(&mut Vec<u8>, &NumBytes, &mut ResponseStatus)> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
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
            | ApiType::CompositeQuery {
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
            | ApiType::CompositeReplyCallback {
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
            }
            | ApiType::CompositeRejectCallback {
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
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::Update { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => None,
            ApiType::ReplyCallback { .. } | ApiType::CompositeReplyCallback { .. } => Some(0),
            ApiType::RejectCallback { reject_context, .. }
            | ApiType::CompositeRejectCallback { reject_context, .. } => {
                Some(reject_context.code() as i32)
            }
        }
    }

    fn get_reject_context(&self) -> Option<&RejectContext> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => None,
            ApiType::RejectCallback { reject_context, .. }
            | ApiType::CompositeRejectCallback { reject_context, .. } => Some(reject_context),
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
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => Err(self.error_for(method_name)),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::SystemTask {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            } => {
                match outgoing_request {
                    None => Err(HypervisorError::ToolchainContractViolation {
                        error: format!("{method_name} called when no call is under construction."),
                    }),
                    Some(request) => {
                        self.sandbox_safe_system_state
                            .withdraw_cycles_for_transfer(
                                self.memory_usage.current_usage,
                                self.memory_usage.current_message_usage,
                                amount,
                                false, // synchronous error => no need to reveal top up balance
                            )?;
                        request.add_cycles(amount);
                        Ok(())
                    }
                }
            }
        }
    }

    fn ic0_canister_cycle_balance_helper(&self, method_name: &str) -> HypervisorResult<Cycles> {
        match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for(method_name)),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                let res = self.sandbox_safe_system_state.cycles_balance();
                Ok(res)
            }
        }
    }

    fn ic0_msg_cycles_available_helper(&self, method_name: &str) -> HypervisorResult<Cycles> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => Err(self.error_for(method_name)),
            ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => {
                Ok(self.sandbox_safe_system_state.msg_cycles_available())
            }
        }
    }

    fn ic0_msg_cycles_refunded_helper(&self, method_name: &str) -> HypervisorResult<Cycles> {
        match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Update { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => Err(self.error_for(method_name)),
            ApiType::ReplyCallback {
                incoming_cycles, ..
            }
            | ApiType::RejectCallback {
                incoming_cycles, ..
            } => Ok(*incoming_cycles),
        }
    }

    fn ic0_msg_cycles_accept_helper(
        &mut self,
        method_name: &str,
        max_amount: Cycles,
    ) -> HypervisorResult<Cycles> {
        match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => Err(self.error_for(method_name)),
            ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => {
                Ok(self.sandbox_safe_system_state.msg_cycles_accept(max_amount))
            }
        }
    }

    fn add_canister_log_for_trap(
        &self,
        err: &HypervisorError,
        time: Time,
        system_state_modifications: &mut SystemStateModifications,
    ) {
        if let Some(log_message) = match err {
            HypervisorError::Trapped {
                trap_code,
                backtrace,
            } => match backtrace {
                Some(bt) => Some(format!("[TRAP]: {trap_code}\n{bt}")),
                None => Some(format!("[TRAP]: {trap_code}")),
            },
            HypervisorError::CalledTrap { message, backtrace } => {
                let message = if message.is_empty() {
                    "(no message)"
                } else {
                    message
                };
                match backtrace {
                    Some(bt) => Some(format!("[TRAP]: {message}\n{bt}")),
                    None => Some(format!("[TRAP]: {message}")),
                }
            }
            _ => None,
        } {
            system_state_modifications
                .canister_log
                .add_record(time.as_nanos_since_unix_epoch(), log_message.into_bytes());
        }
    }

    pub fn take_system_state_modifications(&mut self) -> SystemStateModifications {
        let mut system_state_modifications = self.sandbox_safe_system_state.take_changes();
        // In the below, we explicitly list all fields of `SystemStateModifications`
        // so that an explicit decision needs to be made for each context and
        // and execution result combination when a new field is added to the struct.
        match self.api_type {
            // Inspect message runs in non-replicated mode, not persisting any changes.
            // Same for non-replicated queries.
            ApiType::InspectMessage { .. } | ApiType::NonReplicatedQuery { .. } => {
                SystemStateModifications {
                    new_certified_data: None,
                    callback_updates: vec![],
                    cycles_balance_change: CyclesBalanceChange::zero(),
                    reserved_cycles: Cycles::zero(),
                    consumed_cycles_by_use_case: BTreeMap::new(),
                    call_context_balance_taken: None,
                    request_slots_used: BTreeMap::new(),
                    requests: vec![],
                    new_global_timer: None,
                    canister_log: Default::default(),
                    on_low_wasm_memory_hook_condition_check_result: None,
                    should_bump_canister_version: false,
                }
            }
            // Composite queries, as well as composite reply, reject and cleanup
            // callbacks should persist any changes related to inter-canister
            // calls, like output queue requests and callbacks.
            // In case of a trap, no changes are returned.
            ApiType::CompositeQuery { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. } => match &self.execution_error {
                Some(_) => SystemStateModifications {
                    new_certified_data: None,
                    callback_updates: vec![],
                    cycles_balance_change: CyclesBalanceChange::zero(),
                    reserved_cycles: Cycles::zero(),
                    consumed_cycles_by_use_case: BTreeMap::new(),
                    call_context_balance_taken: None,
                    request_slots_used: BTreeMap::new(),
                    requests: vec![],
                    new_global_timer: None,
                    canister_log: Default::default(),
                    on_low_wasm_memory_hook_condition_check_result: None,
                    should_bump_canister_version: false,
                },
                None => SystemStateModifications {
                    new_certified_data: None,
                    callback_updates: system_state_modifications.callback_updates,
                    cycles_balance_change: CyclesBalanceChange::zero(),
                    reserved_cycles: Cycles::zero(),
                    consumed_cycles_by_use_case: BTreeMap::new(),
                    call_context_balance_taken: None,
                    request_slots_used: system_state_modifications.request_slots_used,
                    requests: system_state_modifications.requests,
                    new_global_timer: None,
                    canister_log: Default::default(),
                    on_low_wasm_memory_hook_condition_check_result: None,
                    should_bump_canister_version: false,
                },
            },
            // Replicated queries return changes to the logs and cycles balance,
            // as well as bumping the canister's version in case there was no trap.
            // In case of a trap, only changes to logs should be returned.
            ApiType::ReplicatedQuery { time, .. } => match &self.execution_error {
                Some(err) => {
                    self.add_canister_log_for_trap(err, time, &mut system_state_modifications);
                    SystemStateModifications {
                        new_certified_data: None,
                        callback_updates: vec![],
                        cycles_balance_change: CyclesBalanceChange::zero(),
                        reserved_cycles: Cycles::zero(),
                        consumed_cycles_by_use_case: BTreeMap::new(),
                        call_context_balance_taken: None,
                        request_slots_used: BTreeMap::new(),
                        requests: vec![],
                        new_global_timer: None,
                        canister_log: system_state_modifications.canister_log,
                        on_low_wasm_memory_hook_condition_check_result: None,
                        should_bump_canister_version: false,
                    }
                }
                None => SystemStateModifications {
                    new_certified_data: None,
                    callback_updates: vec![],
                    cycles_balance_change: system_state_modifications.cycles_balance_change,
                    reserved_cycles: Cycles::zero(),
                    consumed_cycles_by_use_case: system_state_modifications
                        .consumed_cycles_by_use_case,
                    call_context_balance_taken: system_state_modifications
                        .call_context_balance_taken,
                    request_slots_used: BTreeMap::new(),
                    requests: vec![],
                    new_global_timer: None,
                    canister_log: system_state_modifications.canister_log,
                    on_low_wasm_memory_hook_condition_check_result: None,
                    should_bump_canister_version: true,
                },
            },
            // Replicated executions (except queries), should return all changes and bump
            // the canister version in case there was no trap. Otherwise, only changes
            // to logs are returned.
            ApiType::SystemTask { time, .. }
            | ApiType::Update { time, .. }
            | ApiType::Cleanup { time, .. }
            | ApiType::ReplyCallback { time, .. }
            | ApiType::RejectCallback { time, .. } => match &self.execution_error {
                Some(err) => {
                    self.add_canister_log_for_trap(err, time, &mut system_state_modifications);
                    SystemStateModifications {
                        new_certified_data: None,
                        callback_updates: vec![],
                        cycles_balance_change: CyclesBalanceChange::zero(),
                        reserved_cycles: Cycles::zero(),
                        consumed_cycles_by_use_case: BTreeMap::new(),
                        call_context_balance_taken: None,
                        request_slots_used: BTreeMap::new(),
                        requests: vec![],
                        new_global_timer: None,
                        canister_log: system_state_modifications.canister_log,
                        on_low_wasm_memory_hook_condition_check_result: None,
                        should_bump_canister_version: false,
                    }
                }
                None => {
                    system_state_modifications.should_bump_canister_version = true;
                    system_state_modifications
                }
            },
            // Start, init and pre-upgrade are very similar to replicated executions
            // except that they don't bump the canister's version when the execution
            // was successful. This is because these are part of canister `install_code`
            // which bumps the version once for the whole `install_code` request as
            // opposed to per message execution involved during the `install_code`
            // request.
            ApiType::Start { time, .. }
            | ApiType::Init { time, .. }
            | ApiType::PreUpgrade { time, .. } => match &self.execution_error {
                Some(err) => {
                    self.add_canister_log_for_trap(err, time, &mut system_state_modifications);
                    SystemStateModifications {
                        new_certified_data: None,
                        callback_updates: vec![],
                        cycles_balance_change: CyclesBalanceChange::zero(),
                        reserved_cycles: Cycles::zero(),
                        consumed_cycles_by_use_case: BTreeMap::new(),
                        call_context_balance_taken: None,
                        request_slots_used: BTreeMap::new(),
                        requests: vec![],
                        new_global_timer: None,
                        canister_log: system_state_modifications.canister_log,
                        on_low_wasm_memory_hook_condition_check_result: None,
                        should_bump_canister_version: false,
                    }
                }
                None => system_state_modifications,
            },
        }
    }

    /// Wrapper around `self.sandbox_safe_system_state.push_output_request()` that
    /// tries to allocate memory for the `Request` before pushing it.
    ///
    /// On failure to allocate memory or withdraw cycles; or on queue full;
    /// returns `Ok(RejectCode::SysTransient as i32)`.
    ///
    /// Note that this function is made public only for the tests
    #[doc(hidden)]
    pub fn push_output_request(
        &mut self,
        req: Request,
        prepayment_for_response_execution: Cycles,
        prepayment_for_response_transmission: Cycles,
    ) -> HypervisorResult<i32> {
        let abort = |request: Request, sandbox_safe_system_state: &mut SandboxSafeSystemState| {
            sandbox_safe_system_state.refund_cycles(request.payment);
            sandbox_safe_system_state.unregister_callback(request.sender_reply_callback);
        };

        let memory_usage_of_request = if self.execution_parameters.subnet_type == SubnetType::System
        {
            // Effectively disable the memory limit checks on system subnets.
            MessageMemoryUsage::ZERO
        } else {
            memory_usage_of_request(&req)
        };
        if let Err(_err) = self.memory_usage.allocate_message_memory(
            memory_usage_of_request,
            &self.api_type,
            &self.sandbox_safe_system_state,
        ) {
            abort(req, &mut self.sandbox_safe_system_state);
            // Return an error code instead of trapping here in order to allow
            // the user code to handle the error gracefully.
            return Ok(RejectCode::SysTransient as i32);
        }

        match self.sandbox_safe_system_state.push_output_request(
            self.memory_usage.current_usage,
            self.memory_usage.current_message_usage,
            req,
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
        ) {
            Ok(()) => Ok(0),
            Err(request) => {
                self.memory_usage
                    .deallocate_message_memory(memory_usage_of_request);
                abort(request, &mut self.sandbox_safe_system_state);
                Ok(RejectCode::SysTransient as i32)
            }
        }
    }

    /// Return tracked System API call counters.
    pub fn call_counters(&self) -> SystemApiCallCounters {
        self.call_counters.clone()
    }

    /// Appends the specified bytes on the heap as a string to the canister's logs.
    pub fn save_log_message(&mut self, src: usize, size: usize, heap: &[u8]) {
        self.sandbox_safe_system_state.append_canister_log(
            self.api_type.time(),
            valid_subslice(
                "save_log_message",
                InternalAddress::new(src),
                InternalAddress::new(size),
                heap,
            )
            .unwrap_or(
                // Do not trap here!
                // If the specified memory range is invalid, ignore it and log the error message.
                b"(debug_print message out of memory bounds)",
            )
            .to_vec(),
        );
    }

    /// Takes collected canister log records.
    pub fn take_canister_log(&mut self) -> CanisterLog {
        self.sandbox_safe_system_state.take_canister_log()
    }

    /// Returns collected canister log records.
    pub fn canister_log(&self) -> &CanisterLog {
        self.sandbox_safe_system_state.canister_log()
    }

    /// Checks if the current API type is an install or upgrade message.
    /// This is relevant when enforcing the stable memory dirty page limit.
    pub fn is_install_or_upgrade_message(&self) -> bool {
        matches!(
            self.api_type,
            ApiType::Init { .. } | ApiType::PreUpgrade { .. }
        )
    }

    /// Based on the page limit object, returns the page limit for the current
    /// system API type. Can be called with the limit for dirty pages or accessed pages.
    pub fn get_page_limit(&self, page_limit: &StableMemoryPageLimit) -> NumOsPages {
        match &self.api_type {
            // Longer-running messages make use of a different, possibly higher limit.
            ApiType::Init { .. } | ApiType::PreUpgrade { .. } => page_limit.upgrade,
            // Queries (including composite queries) have a separate limit.
            ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. } => page_limit.query,
            // All other API types get the replicated message limit.
            ApiType::Update { .. }
            | ApiType::Start { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. } => page_limit.message,
        }
    }
}

impl SystemApi for SystemApiImpl {
    fn set_execution_error(&mut self, error: HypervisorError) {
        self.execution_error = Some(error)
    }

    fn get_execution_error(&self) -> Option<&HypervisorError> {
        self.execution_error.as_ref()
    }

    fn get_num_instructions_from_bytes(&self, num_bytes: NumBytes) -> NumInstructions {
        NumInstructions::from(num_bytes.get())
    }

    fn subnet_type(&self) -> SubnetType {
        self.execution_parameters.subnet_type
    }

    fn message_instruction_limit(&self) -> NumInstructions {
        self.execution_parameters.instruction_limits.message()
    }

    fn message_instructions_executed(&self, instruction_counter: i64) -> NumInstructions {
        let result = (self.instructions_executed_before_current_slice as u64)
            .saturating_add(self.slice_instructions_executed(instruction_counter).get());
        NumInstructions::from(result)
    }

    fn call_context_instructions_executed(&self) -> NumInstructions {
        match &self.api_type {
            ApiType::ReplyCallback {
                call_context_instructions_executed,
                ..
            }
            | ApiType::RejectCallback {
                call_context_instructions_executed,
                ..
            }
            | ApiType::Cleanup {
                call_context_instructions_executed,
                ..
            }
            | ApiType::CompositeReplyCallback {
                call_context_instructions_executed,
                ..
            }
            | ApiType::CompositeRejectCallback {
                call_context_instructions_executed,
                ..
            }
            | ApiType::CompositeCleanup {
                call_context_instructions_executed,
                ..
            } => *call_context_instructions_executed,
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::Update { .. } => 0.into(),
        }
    }

    fn slice_instruction_limit(&self) -> NumInstructions {
        // Note that `self.execution_parameters.instruction_limits.slice()` is
        // the instruction limit of the first slice, not the current one.
        NumInstructions::from(u64::try_from(self.current_slice_instruction_limit).unwrap_or(0))
    }

    fn slice_instructions_executed(&self, instruction_counter: i64) -> NumInstructions {
        let result = self
            .current_slice_instruction_limit
            .saturating_sub(instruction_counter)
            .max(0) as u64;
        NumInstructions::from(result)
    }

    fn canister_id(&self) -> CanisterId {
        self.sandbox_safe_system_state.canister_id
    }

    fn ic0_env_var_count(&self) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_env_var_count")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                Ok(self.sandbox_safe_system_state.environment_variables().len())
            }
        };

        trace_syscall!(self, EnvVarCount, result);
        result
    }

    fn ic0_env_var_name_size(&self, index: usize) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_env_var_name_size")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                let keys = self
                    .sandbox_safe_system_state
                    .environment_variables()
                    .keys()
                    .collect::<Vec<_>>();
                match keys.get(index) {
                    Some(name) => Ok(name.len()),
                    None => Err(EnvironmentVariableIndexOutOfBounds {
                        index,
                        length: keys.len(),
                    }),
                }
            }
        };

        trace_syscall!(self, EnvVarNameSize, result);
        result
    }

    fn ic0_env_var_name_copy(
        &self,
        index: usize,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_env_var_name_copy")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                let keys = self
                    .sandbox_safe_system_state
                    .environment_variables()
                    .keys()
                    .collect::<Vec<_>>();
                match keys.get(index) {
                    Some(name) => {
                        // Validate destination buffer
                        valid_subslice(
                            "ic0.env_var_name_copy heap",
                            InternalAddress::new(dst),
                            InternalAddress::new(size),
                            heap,
                        )?;
                        let slice = valid_subslice(
                            "ic0.env_var_name_copy name",
                            InternalAddress::new(offset),
                            InternalAddress::new(size),
                            name.as_bytes(),
                        )?;
                        deterministic_copy_from_slice(&mut heap[dst..dst + size], slice);
                        Ok(())
                    }
                    None => Err(EnvironmentVariableIndexOutOfBounds {
                        index,
                        length: keys.len(),
                    }),
                }
            }
        };

        trace_syscall!(
            self,
            EnvVarNameCopy,
            result,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_env_var_name_exists(
        &self,
        name_src: usize,
        name_size: usize,
        heap: &[u8],
    ) -> HypervisorResult<i32> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_env_var_name_exists")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                if name_size > MAX_ENV_VAR_NAME_SIZE {
                    return Err(HypervisorError::UserContractViolation {
                        error: "ic0.env_var_name_exists: Variable name is too large.".to_string(),
                        suggestion: "".to_string(),
                        doc_link: "".to_string(),
                    });
                }

                let name_bytes = valid_subslice(
                    "ic0.env_var_name_exists heap",
                    InternalAddress::new(name_src),
                    InternalAddress::new(name_size),
                    heap,
                )?;

                let name = std::str::from_utf8(name_bytes).map_err(|_| {
                    HypervisorError::UserContractViolation {
                        error:
                            "ic0.env_var_name_exists: Variable name is not a valid UTF-8 string."
                                .to_string(),
                        suggestion:
                            "Provide a valid UTF-8 string for the environment variable name."
                                .to_string(),
                        doc_link: "".to_string(),
                    }
                })?;
                Ok(self
                    .sandbox_safe_system_state
                    .environment_variables()
                    .contains_key(name) as i32)
            }
        };

        trace_syscall!(self, EnvVarNameExists, result);
        result
    }

    fn ic0_env_var_value_size(
        &self,
        name_src: usize,
        name_size: usize,
        heap: &[u8],
    ) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_env_var_value_size")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                if name_size > MAX_ENV_VAR_NAME_SIZE {
                    return Err(HypervisorError::UserContractViolation {
                        error: "ic0.env_var_value_size: Variable name is too large.".to_string(),
                        suggestion: "".to_string(),
                        doc_link: "".to_string(),
                    });
                }

                let name_bytes = valid_subslice(
                    "ic0.env_var_value_size heap",
                    InternalAddress::new(name_src),
                    InternalAddress::new(name_size),
                    heap,
                )?;

                let name = std::str::from_utf8(name_bytes).map_err(|_| {
                    HypervisorError::UserContractViolation {
                        error: "ic0.env_var_value_size: Variable name is not a valid UTF-8 string."
                            .to_string(),
                        suggestion:
                            "Provide a valid UTF-8 string for the environment variable name."
                                .to_string(),
                        doc_link: "".to_string(),
                    }
                })?;
                match &self
                    .sandbox_safe_system_state
                    .environment_variables()
                    .get(name)
                {
                    Some(value) => Ok(value.len()),
                    None => Err(EnvironmentVariableNotFound {
                        name: name.to_string(),
                    }),
                }
            }
        };

        trace_syscall!(self, EnvVarValueSize, result);
        result
    }

    fn ic0_env_var_value_copy(
        &self,
        name_src: usize,
        name_size: usize,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_env_var_value_copy")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                if name_size > MAX_ENV_VAR_NAME_SIZE {
                    return Err(HypervisorError::UserContractViolation {
                        error: "ic0.env_var_value_copy: Variable name is too large.".to_string(),
                        suggestion: "".to_string(),
                        doc_link: "".to_string(),
                    });
                }

                let name_bytes = valid_subslice(
                    "ic0.env_var_value_copy name",
                    InternalAddress::new(name_src),
                    InternalAddress::new(name_size),
                    heap,
                )?;

                let name = std::str::from_utf8(name_bytes).map_err(|_| {
                    HypervisorError::UserContractViolation {
                        error: "ic0.env_var_value_copy: Variable name is not a valid UTF-8 string."
                            .to_string(),
                        suggestion:
                            "Provide a valid UTF-8 string for the environment variable name."
                                .to_string(),
                        doc_link: "".to_string(),
                    }
                })?;

                match &self
                    .sandbox_safe_system_state
                    .environment_variables()
                    .get(name)
                {
                    Some(value) => {
                        // Validate destination buffer
                        valid_subslice(
                            "ic0.env_var_value_copy heap",
                            InternalAddress::new(dst),
                            InternalAddress::new(size),
                            heap,
                        )?;
                        let slice = valid_subslice(
                            "ic0.env_var_value_copy value",
                            InternalAddress::new(offset),
                            InternalAddress::new(size),
                            value.as_bytes(),
                        )?;
                        deterministic_copy_from_slice(&mut heap[dst..dst + size], slice);
                        Ok(())
                    }
                    None => Err(EnvironmentVariableNotFound {
                        name: name.to_string(),
                    }),
                }
            }
        };

        trace_syscall!(
            self,
            EnvVarValueCopy,
            result,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_msg_caller_size(&self) -> HypervisorResult<usize> {
        let result = self
            .api_type
            .caller()
            .map(|caller_id| caller_id.as_slice().len())
            .ok_or_else(|| self.error_for("ic0_msg_caller_size"));
        trace_syscall!(self, MsgCallerSize, result);
        result
    }

    fn ic0_msg_caller_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match self.api_type.caller() {
            Some(caller_id) => {
                let id_bytes = caller_id.as_slice();
                valid_subslice(
                    "ic0.msg_caller_copy heap",
                    InternalAddress::new(dst),
                    InternalAddress::new(size),
                    heap,
                )?;
                let slice = valid_subslice(
                    "ic0.msg_caller_copy id",
                    InternalAddress::new(offset),
                    InternalAddress::new(size),
                    id_bytes,
                )?;
                deterministic_copy_from_slice(&mut heap[dst..dst + size], slice);
                Ok(())
            }
            None => Err(self.error_for("ic0_msg_caller_copy")),
        };
        trace_syscall!(
            self,
            MsgCallerCopy,
            result,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_msg_arg_data_size(&self) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::SystemTask { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
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
            | ApiType::CompositeReplyCallback {
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
            }
            | ApiType::CompositeQuery {
                incoming_payload, ..
            } => Ok(incoming_payload.len()),
        };
        trace_syscall!(self, MsgArgDataSize, result);
        result
    }

    fn ic0_msg_arg_data_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
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
            | ApiType::CompositeReplyCallback {
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
            }
            | ApiType::CompositeQuery {
                incoming_payload, ..
            } => {
                valid_subslice(
                    "ic0.msg_arg_data_copy heap",
                    InternalAddress::new(dst),
                    InternalAddress::new(size),
                    heap,
                )?;
                let payload_subslice = valid_subslice(
                    "ic0.msg_arg_data_copy payload",
                    InternalAddress::new(offset),
                    InternalAddress::new(size),
                    incoming_payload,
                )?;
                deterministic_copy_from_slice(&mut heap[dst..dst + size], payload_subslice);
                Ok(())
            }
        };
        trace_syscall!(
            self,
            MsgArgDataCopy,
            result,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_msg_method_name_size(&self) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::Init { .. } => Err(self.error_for("ic0_msg_method_name_size")),
            ApiType::InspectMessage { method_name, .. } => Ok(method_name.len()),
        };
        trace_syscall!(self, MsgMethodNameSize, result);
        result
    }

    fn ic0_msg_method_name_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::Init { .. } => Err(self.error_for("ic0_msg_method_name_copy")),
            ApiType::InspectMessage { method_name, .. } => {
                valid_subslice(
                    "ic0.msg_method_name_copy heap",
                    InternalAddress::new(dst),
                    InternalAddress::new(size),
                    heap,
                )?;
                let payload_subslice = valid_subslice(
                    "ic0.msg_method_name_copy payload",
                    InternalAddress::new(offset),
                    InternalAddress::new(size),
                    method_name.as_bytes(),
                )?;
                deterministic_copy_from_slice(&mut heap[dst..dst + size], payload_subslice);
                Ok(())
            }
        };
        trace_syscall!(
            self,
            MsgMethodNameCopy,
            result,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_accept_message(&mut self) -> HypervisorResult<()> {
        let result = match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::Init { .. } => Err(self.error_for("ic0_accept_message")),
            ApiType::InspectMessage {
                message_accepted, ..
            } => {
                if *message_accepted {
                    Err(ToolchainContractViolation {
                        error: "ic0.accept_message: the function was already called.".to_string(),
                    })
                } else {
                    *message_accepted = true;
                    Ok(())
                }
            }
        };
        trace_syscall!(self, AcceptMessage, result);
        result
    }

    fn ic0_msg_reply(&mut self) -> HypervisorResult<()> {
        let result = match self.get_response_info() {
            None => Err(self.error_for("ic0_msg_reply")),
            Some((data, _, status)) => match status {
                ResponseStatus::NotRepliedYet => {
                    *status = ResponseStatus::JustRepliedWith(Some(WasmResult::Reply(
                        std::mem::take(data),
                    )));
                    Ok(())
                }
                ResponseStatus::AlreadyReplied | ResponseStatus::JustRepliedWith(_) => {
                    Err(ToolchainContractViolation {
                        error: "ic0.msg_reply: the call is already replied".to_string(),
                    })
                }
            },
        };
        trace_syscall!(self, MsgReply, result);
        result
    }

    fn ic0_msg_reply_data_append(
        &mut self,
        src: usize,
        size: usize,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let result = match self.get_response_info() {
            None => Err(self.error_for("ic0_msg_reply_data_append")),
            Some((data, max_reply_size, response_status)) => match response_status {
                ResponseStatus::NotRepliedYet => {
                    let payload_size = data.len().saturating_add(size) as u64;
                    if payload_size > max_reply_size.get() {
                        let string = format!(
                            "ic0.msg_reply_data_append: application payload size ({payload_size}) cannot be larger than {max_reply_size}.",
                        );
                        return Err(UserContractViolation {
                            error: string,
                            suggestion:
                                "Consider checking the response size and returning an error if \
                                it is too long."
                                    .to_string(),
                            doc_link: doc_ref("msg_reply_data_append-payload-too-large"),
                        });
                    }
                    data.extend_from_slice(valid_subslice(
                        "msg.reply",
                        InternalAddress::new(src),
                        InternalAddress::new(size),
                        heap,
                    )?);
                    Ok(())
                }
                ResponseStatus::AlreadyReplied | ResponseStatus::JustRepliedWith(_) => {
                    Err(ToolchainContractViolation {
                        error: "ic0.msg_reply_data_append: the call is already replied."
                            .to_string(),
                    })
                }
            },
        };
        trace_syscall!(
            self,
            MsgReplyDataAppend,
            result,
            src,
            size,
            summarize(heap, src, size)
        );
        result
    }

    fn ic0_msg_reject(&mut self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<()> {
        let result = match self.get_response_info() {
            None => Err(self.error_for("ic0_msg_reject")),
            Some((_, max_reply_size, response_status)) => match response_status {
                ResponseStatus::NotRepliedYet => {
                    if size as u64 > max_reply_size.get() {
                        let string = format!(
                            "ic0.msg_reject: application payload size ({size}) cannot be larger than {max_reply_size}."
                        );
                        return Err(UserContractViolation {
                            error: string,
                            suggestion: "Try truncating the error messages that are too long."
                                .to_string(),
                            doc_link: doc_ref("msg_reject-payload-too-large"),
                        });
                    }
                    let msg_bytes = valid_subslice(
                        "ic0.msg_reject",
                        InternalAddress::new(src),
                        InternalAddress::new(size),
                        heap,
                    )?;
                    let msg = String::from_utf8(msg_bytes.to_vec()).map_err(|_| {
                        ToolchainContractViolation {
                            error: "ic0.msg_reject: invalid UTF-8 string provided".to_string(),
                        }
                    })?;
                    *response_status =
                        ResponseStatus::JustRepliedWith(Some(WasmResult::Reject(msg)));
                    Ok(())
                }
                ResponseStatus::AlreadyReplied | ResponseStatus::JustRepliedWith(_) => {
                    Err(ToolchainContractViolation {
                        error: "ic0.msg_reject: the call is already replied".to_string(),
                    })
                }
            },
        };
        trace_syscall!(
            self,
            MsgReject,
            result,
            src,
            size,
            summarize(heap, src, size)
        );
        result
    }

    fn ic0_msg_reject_code(&self) -> HypervisorResult<i32> {
        let result = self
            .get_reject_code()
            .ok_or_else(|| self.error_for("ic0_msg_reject_code"));
        trace_syscall!(self, MsgRejectCode, result);
        result
    }

    fn ic0_msg_reject_msg_size(&self) -> HypervisorResult<usize> {
        let reject_context = self
            .get_reject_context()
            .ok_or_else(|| self.error_for("ic0_msg_reject_msg_size"))?;
        let result = Ok(reject_context.message().len());
        trace_syscall!(self, MsgRejectMsgSize, result);
        result
    }

    fn ic0_msg_reject_msg_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = {
            let reject_context = self
                .get_reject_context()
                .ok_or_else(|| self.error_for("ic0_msg_reject_msg_copy"))?;
            valid_subslice(
                "ic0.msg_reject_msg_copy heap",
                InternalAddress::new(dst),
                InternalAddress::new(size),
                heap,
            )?;

            let msg = reject_context.message();
            let msg_bytes = valid_subslice(
                "ic0.msg_reject_msg_copy msg",
                InternalAddress::new(offset),
                InternalAddress::new(size),
                msg.as_bytes(),
            )?;
            deterministic_copy_from_slice(&mut heap[dst..dst + size], msg_bytes);
            Ok(())
        };
        trace_syscall!(
            self,
            MsgRejectMsgCopy,
            result,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_canister_self_size(&self) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_canister_self_size")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Ok(self
                .sandbox_safe_system_state
                .canister_id
                .get_ref()
                .as_slice()
                .len()),
        };
        trace_syscall!(self, CanisterSelfSize, result);
        result
    }

    fn ic0_canister_self_copy(
        &mut self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_canister_self_copy")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                valid_subslice(
                    "ic0.canister_self_copy heap",
                    InternalAddress::new(dst),
                    InternalAddress::new(size),
                    heap,
                )?;
                let canister_id = self.sandbox_safe_system_state.canister_id;
                let id_bytes = canister_id.get_ref().as_slice();
                let slice = valid_subslice(
                    "ic0.canister_self_copy id",
                    InternalAddress::new(offset),
                    InternalAddress::new(size),
                    id_bytes,
                )?;
                deterministic_copy_from_slice(&mut heap[dst..dst + size], slice);
                Ok(())
            }
        };
        trace_syscall!(
            self,
            CanisterSelfCopy,
            result,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_call_new(
        &mut self,
        callee_src: usize,
        callee_size: usize,
        name_src: usize,
        name_len: usize,
        reply_fun: u32,
        reply_env: u64,
        reject_fun: u32,
        reject_env: u64,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let result = match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_new")),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::CompositeQuery {
                outgoing_request, ..
            }
            | ApiType::SystemTask {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeRejectCallback {
                outgoing_request, ..
            } => {
                if let Some(outgoing_request) = outgoing_request.take() {
                    self.sandbox_safe_system_state
                        .refund_cycles(outgoing_request.take_cycles());
                }

                let req = RequestInPrep::new(
                    self.sandbox_safe_system_state.canister_id,
                    callee_src,
                    callee_size,
                    name_src,
                    name_len,
                    heap,
                    WasmClosure::new(reply_fun, reply_env),
                    WasmClosure::new(reject_fun, reject_env),
                    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
                    MULTIPLIER_MAX_SIZE_LOCAL_SUBNET,
                    self.max_sum_exported_function_name_lengths,
                )?;
                *outgoing_request = Some(req);
                Ok(())
            }
        };
        trace_syscall!(
            self,
            CallNew,
            result,
            callee_src,
            callee_size,
            name_src,
            name_len,
            reply_fun,
            reply_env,
            reject_fun,
            reject_env,
            summarize(heap, callee_src, callee_size)
        );
        result
    }

    fn ic0_call_data_append(
        &mut self,
        src: usize,
        size: usize,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let result = match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_data_append")),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::CompositeQuery {
                outgoing_request, ..
            }
            | ApiType::SystemTask {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeRejectCallback {
                outgoing_request, ..
            } => match outgoing_request {
                None => Err(HypervisorError::ToolchainContractViolation {
                    error: "ic0.call_data_append called when no call is under construction."
                        .to_string(),
                }),
                Some(request) => request.extend_method_payload(src, size, heap),
            },
        };
        trace_syscall!(self, CallDataAppend, src, size, summarize(heap, src, size));
        result
    }

    fn ic0_call_on_cleanup(&mut self, fun: u32, env: u64) -> HypervisorResult<()> {
        let result = match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_on_cleanup")),
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::CompositeQuery {
                outgoing_request, ..
            }
            | ApiType::SystemTask {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeRejectCallback {
                outgoing_request, ..
            } => match outgoing_request {
                None => Err(HypervisorError::ToolchainContractViolation {
                    error: "ic0.call_on_cleanup called when no call is under construction."
                        .to_string(),
                }),
                Some(request) => request.set_on_cleanup(WasmClosure::new(fun, env)),
            },
        };
        trace_syscall!(self, CallOnCleanup, fun, env);
        result
    }

    fn ic0_call_cycles_add(&mut self, amount: u64) -> HypervisorResult<()> {
        let result = self.ic0_call_cycles_add_helper("ic0_call_cycles_add", Cycles::from(amount));
        trace_syscall!(self, CallCyclesAdd, result, amount);
        result
    }

    fn ic0_call_cycles_add128(&mut self, amount: Cycles) -> HypervisorResult<()> {
        let result = self.ic0_call_cycles_add_helper("ic0_call_cycles_add128", amount);
        trace_syscall!(self, CallCyclesAdd128, result, amount);
        result
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
        let result = match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_call_perform")),
            ApiType::Update {
                time,
                call_context_id,
                outgoing_request,
                ..
            }
            | ApiType::SystemTask {
                time,
                call_context_id,
                outgoing_request,
                ..
            }
            | ApiType::ReplyCallback {
                time,
                call_context_id,
                outgoing_request,
                ..
            }
            | ApiType::CompositeReplyCallback {
                time,
                call_context_id,
                outgoing_request,
                ..
            }
            | ApiType::RejectCallback {
                time,
                call_context_id,
                outgoing_request,
                ..
            }
            | ApiType::CompositeRejectCallback {
                time,
                call_context_id,
                outgoing_request,
                ..
            }
            | ApiType::CompositeQuery {
                time,
                call_context_id,
                outgoing_request,
                ..
            } => {
                let req_in_prep =
                    outgoing_request
                        .take()
                        .ok_or_else(|| ToolchainContractViolation {
                            error: "ic0.call_perform called when no call is under construction."
                                .to_string(),
                        })?;

                let req = into_request(
                    req_in_prep,
                    *call_context_id,
                    &mut self.sandbox_safe_system_state,
                    &self.log,
                    *time,
                )?;

                self.push_output_request(
                    req.request,
                    req.prepayment_for_response_execution,
                    req.prepayment_for_response_transmission,
                )
            }
        };
        trace_syscall!(self, CallPerform, result);
        result
    }

    fn stable_read_without_bounds_checks(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        self.stable_memory
            .stable_read_without_bounds_checks(dst, offset, size, heap)
    }

    fn ic0_time(&mut self) -> HypervisorResult<Time> {
        self.call_counters.time += 1;
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_time")),
            ApiType::Init { time, .. }
            | ApiType::SystemTask { time, .. }
            | ApiType::Update { time, .. }
            | ApiType::Cleanup { time, .. }
            | ApiType::CompositeCleanup { time, .. }
            | ApiType::NonReplicatedQuery { time, .. }
            | ApiType::CompositeQuery { time, .. }
            | ApiType::ReplicatedQuery { time, .. }
            | ApiType::PreUpgrade { time, .. }
            | ApiType::ReplyCallback { time, .. }
            | ApiType::CompositeReplyCallback { time, .. }
            | ApiType::RejectCallback { time, .. }
            | ApiType::CompositeRejectCallback { time, .. }
            | ApiType::InspectMessage { time, .. } => Ok(*time),
        };
        trace_syscall!(self, Time, result);
        result
    }

    fn ic0_global_timer_set(&mut self, time: Time) -> HypervisorResult<Time> {
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_global_timer_set")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => {
                // Reply and reject callbacks can be executed in non-replicated mode
                // iff from within a composite query call. Disallow in that case.
                if self.execution_parameters.execution_mode == ExecutionMode::NonReplicated {
                    return Err(self.error_for("ic0_global_timer_set"));
                }

                let prev_time = self.sandbox_safe_system_state.global_timer().to_time();
                self.sandbox_safe_system_state
                    .set_global_timer(CanisterTimer::from_time(time));
                Ok(prev_time)
            }
        };
        trace_syscall!(self, GlobalTimerSet, result);
        result
    }

    fn ic0_performance_counter(
        &self,
        performance_counter_type: PerformanceCounterType,
    ) -> HypervisorResult<u64> {
        let result = match performance_counter_type {
            PerformanceCounterType::Instructions(instruction_counter) => Ok(self
                .message_instructions_executed(instruction_counter)
                .get()),
            PerformanceCounterType::CallContextInstructions(instruction_counter) => Ok(self
                .call_context_instructions_executed()
                .get()
                .saturating_add(
                    self.message_instructions_executed(instruction_counter)
                        .get(),
                )),
        };
        trace_syscall!(self, PerformanceCounter, result);
        result
    }

    fn ic0_canister_version(&self) -> HypervisorResult<u64> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_canister_version")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                Ok(self.sandbox_safe_system_state.canister_version())
            }
        };
        trace_syscall!(self, CanisterVersion, result);
        result
    }

    fn out_of_instructions(&mut self, instruction_counter: i64) -> HypervisorResult<i64> {
        let result = self
            .out_of_instructions_handler
            .out_of_instructions(instruction_counter);
        if let Ok(new_slice_instruction_limit) = result {
            // A new slice has started, update the instruction sum and limit.
            let slice_instructions = self
                .current_slice_instruction_limit
                .saturating_sub(instruction_counter)
                .max(0);
            self.instructions_executed_before_current_slice += slice_instructions;
            self.current_slice_instruction_limit = new_slice_instruction_limit;
        }
        trace_syscall!(self, OutOfInstructions, result, instruction_counter);
        result
    }

    /// Performance improvement:
    /// This function is called after a message execution succeeded but the number of
    /// dirty pages is large enough to warrant an extra round of execution.
    /// Therefore, we yield control back to the replica and we wait for the
    /// next round to start copying dirty pages.
    fn yield_for_dirty_memory_copy(&mut self) -> HypervisorResult<i64> {
        let result = self
            .out_of_instructions_handler
            .yield_for_dirty_memory_copy();
        if let Ok(new_slice_instruction_limit) = result {
            // A new slice has started, update the instruction sum and limit.
            self.instructions_executed_before_current_slice += self.current_slice_instruction_limit;
            self.current_slice_instruction_limit = new_slice_instruction_limit;
        }
        trace_syscall!(self, yield_for_dirty_memory_copy, result);
        result
    }

    fn try_grow_wasm_memory(
        &mut self,
        native_memory_grow_res: i64,
        additional_wasm_pages: u64,
    ) -> HypervisorResult<()> {
        let result = {
            if native_memory_grow_res == -1 {
                return Ok(());
            }
            let new_bytes = additional_wasm_pages
                .checked_mul(WASM_PAGE_SIZE_IN_BYTES as u64)
                .map(NumBytes::new)
                .ok_or(HypervisorError::OutOfMemory)?;

            // The `memory.grow` instruction returns the previous size of the
            // Wasm memory in pages.
            let old_bytes = (native_memory_grow_res as u64)
                .checked_mul(WASM_PAGE_SIZE_IN_BYTES as u64)
                .map(NumBytes::new)
                .ok_or(HypervisorError::OutOfMemory)?;

            if let Some(wasm_memory_limit) = self
                .memory_usage
                .effective_wasm_memory_limit(&self.api_type)
            {
                let wasm_memory_usage =
                    NumBytes::new(new_bytes.get().saturating_add(old_bytes.get()));

                // A Wasm memory limit of 0 means unlimited.
                if wasm_memory_limit.get() != 0 && wasm_memory_usage > wasm_memory_limit {
                    return Err(HypervisorError::WasmMemoryLimitExceeded {
                        bytes: wasm_memory_usage,
                        limit: wasm_memory_limit,
                    });
                }
            }

            match self.memory_usage.allocate_execution_memory(
                new_bytes,
                &self.api_type,
                &mut self.sandbox_safe_system_state,
                &self.execution_parameters.subnet_memory_saturation,
                ExecutionMemoryType::WasmMemory,
            ) {
                Ok(()) => Ok(()),
                Err(err @ HypervisorError::InsufficientCyclesInMemoryGrow { .. }) => {
                    // Return an out-of-cycles error instead of out-of-memory.
                    Err(err)
                }
                Err(err @ HypervisorError::ReservedCyclesLimitExceededInMemoryGrow { .. }) => {
                    // Return a reservation error instead of out-of-memory.
                    Err(err)
                }
                Err(_err) => Err(HypervisorError::OutOfMemory),
            }
        };
        trace_syscall!(
            self,
            TryGrowWasmMemory,
            result,
            native_memory_grow_res,
            additional_wasm_pages
        );
        result
    }

    fn try_grow_stable_memory(
        &mut self,
        current_size: u64,
        additional_pages: u64,
        max_size: u64,
        stable_memory_api: ic_interfaces::execution_environment::StableMemoryApi,
    ) -> HypervisorResult<StableGrowOutcome> {
        let resulting_size = current_size.saturating_add(additional_pages);
        if let StableMemoryApi::Stable32 = stable_memory_api {
            if current_size > MAX_32_BIT_STABLE_MEMORY_IN_PAGES {
                return Err(HypervisorError::Trapped {
                    trap_code: TrapCode::StableMemoryTooBigFor32Bit,
                    backtrace: None,
                });
            }
            if resulting_size > MAX_32_BIT_STABLE_MEMORY_IN_PAGES {
                return Ok(StableGrowOutcome::Failure);
            }
        }
        if resulting_size > max_size {
            return Ok(StableGrowOutcome::Failure);
        }
        let Ok(execution_bytes) =
            ic_replicated_state::num_bytes_try_from(NumWasmPages::new(additional_pages as usize))
        else {
            return Ok(StableGrowOutcome::Failure);
        };
        match self.memory_usage.allocate_execution_memory(
            execution_bytes,
            &self.api_type,
            &mut self.sandbox_safe_system_state,
            &self.execution_parameters.subnet_memory_saturation,
            ExecutionMemoryType::StableMemory,
        ) {
            Ok(()) => Ok(StableGrowOutcome::Success),
            Err(err @ HypervisorError::InsufficientCyclesInMemoryGrow { .. }) => {
                // Trap instead of returning -1 in order to give the developer
                // more actionable error message. Otherwise, they cannot
                // distinguish between out-of-memory and out-of-cycles.
                Err(err)
            }
            Err(err @ HypervisorError::ReservedCyclesLimitExceededInMemoryGrow { .. }) => {
                // Trap instead of returning -1 in order to give the developer
                // more actionable error message. Otherwise, they cannot
                // distinguish between out-of-memory and cycle reservation errors.
                Err(err)
            }
            Err(_) => Ok(StableGrowOutcome::Failure),
        }
    }

    fn ic0_canister_cycle_balance(&mut self) -> HypervisorResult<u64> {
        self.call_counters.canister_cycle_balance += 1;
        let result = {
            let (high_amount, low_amount) = self
                .ic0_canister_cycle_balance_helper("ic0_canister_cycle_balance")?
                .into_parts();
            if high_amount != 0 {
                return Err(HypervisorError::Trapped {
                    trap_code: CyclesAmountTooBigFor64Bit,
                    backtrace: None,
                });
            }
            Ok(low_amount)
        };
        trace_syscall!(self, CanisterCycleBalance, result);
        result
    }

    fn ic0_canister_cycle_balance128(
        &mut self,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        self.call_counters.canister_cycle_balance128 += 1;
        let result = {
            let method_name = "ic0_canister_cycle_balance128";
            let cycles = self.ic0_canister_cycle_balance_helper(method_name)?;
            copy_cycles_to_heap(cycles, dst, heap, method_name)?;
            Ok(())
        };
        trace_syscall!(self, CanisterCycleBalance128, dst, summarize(heap, dst, 16));
        result
    }

    fn ic0_canister_liquid_cycle_balance128(
        &mut self,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        self.call_counters.canister_liquid_cycle_balance128 += 1;
        let method_name = "ic0_canister_liquid_cycle_balance128";
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for(method_name)),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                let cycles = self.sandbox_safe_system_state.liquid_cycles_balance(
                    self.memory_usage.current_usage,
                    self.memory_usage.current_message_usage,
                );
                copy_cycles_to_heap(cycles, dst, heap, method_name)?;
                Ok(())
            }
        };
        trace_syscall!(
            self,
            CanisterLiquidCycleBalance128,
            dst,
            summarize(heap, dst, 16)
        );
        result
    }

    fn ic0_msg_cycles_available(&self) -> HypervisorResult<u64> {
        let result = {
            let (high_amount, low_amount) = self
                .ic0_msg_cycles_available_helper("ic0_msg_cycles_available")?
                .into_parts();
            if high_amount != 0 {
                return Err(HypervisorError::Trapped {
                    trap_code: CyclesAmountTooBigFor64Bit,
                    backtrace: None,
                });
            }
            Ok(low_amount)
        };
        trace_syscall!(self, MsgCyclesAvailable, result);
        result
    }

    fn ic0_msg_cycles_available128(&self, dst: usize, heap: &mut [u8]) -> HypervisorResult<()> {
        let result = {
            let method_name = "ic0_msg_cycles_available128";
            let cycles = self.ic0_msg_cycles_available_helper(method_name)?;
            copy_cycles_to_heap(cycles, dst, heap, method_name)?;
            Ok(())
        };
        trace_syscall!(self, MsgCyclesAvailable128, result);
        result
    }

    fn ic0_msg_cycles_refunded(&self) -> HypervisorResult<u64> {
        let result = {
            let (high_amount, low_amount) = self
                .ic0_msg_cycles_refunded_helper("ic0_msg_cycles_refunded")?
                .into_parts();
            if high_amount != 0 {
                return Err(HypervisorError::Trapped {
                    trap_code: CyclesAmountTooBigFor64Bit,
                    backtrace: None,
                });
            }
            Ok(low_amount)
        };
        trace_syscall!(self, MsgCyclesRefunded, result);
        result
    }

    fn ic0_msg_cycles_refunded128(&self, dst: usize, heap: &mut [u8]) -> HypervisorResult<()> {
        let result = {
            let method_name = "ic0_msg_cycles_refunded128";
            let cycles = self.ic0_msg_cycles_refunded_helper(method_name)?;
            copy_cycles_to_heap(cycles, dst, heap, method_name)?;
            Ok(())
        };
        trace_syscall!(self, MsgCyclesRefunded128, result, summarize(heap, dst, 16));
        result
    }

    fn ic0_msg_cycles_accept(&mut self, max_amount: u64) -> HypervisorResult<u64> {
        let result = {
            // Cannot accept more than max_amount.
            let (high_amount, low_amount) = self
                .ic0_msg_cycles_accept_helper("ic0_msg_cycles_accept", Cycles::from(max_amount))?
                .into_parts();
            if high_amount != 0 {
                error!(
                    self.log,
                    "ic0_msg_cycles_accept cannot accept more than max_amount {}; accepted amount {}",
                    max_amount,
                    Cycles::from_parts(high_amount, low_amount).get()
                )
            }
            Ok(low_amount)
        };
        trace_syscall!(self, MsgCyclesAccept, result, max_amount);
        result
    }

    fn ic0_msg_cycles_accept128(
        &mut self,
        max_amount: Cycles,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = {
            let method_name = "ic0_msg_cycles_accept128";
            let cycles = self.ic0_msg_cycles_accept_helper(method_name, max_amount)?;
            copy_cycles_to_heap(cycles, dst, heap, method_name)?;
            Ok(())
        };
        trace_syscall!(self, MsgCyclesAccept128, result);
        result
    }

    fn ic0_root_key_size(&self) -> HypervisorResult<usize> {
        let method_name = "ic0_root_key_size";
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for(method_name)),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. } => {
                // Reply and reject callbacks can be executed in non-replicated mode
                // iff from within a composite query call. Always disallow in that case.
                if self.execution_parameters.execution_mode == ExecutionMode::NonReplicated {
                    return Err(self.error_for(method_name));
                }

                let root_key = self.sandbox_safe_system_state.get_root_key();
                Ok(root_key.as_slice().len())
            }
        };

        trace_syscall!(self, RootKeySize, result);
        result
    }

    fn ic0_root_key_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let method_name = "ic0.root_key_copy";
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for(method_name)),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. } => {
                // Reply and reject callbacks can be executed in non-replicated mode
                // iff from within a composite query call. Always disallow in that case.
                if self.execution_parameters.execution_mode == ExecutionMode::NonReplicated {
                    return Err(self.error_for(method_name));
                }

                valid_subslice(
                    "ic0.root_key_copy heap",
                    InternalAddress::new(dst),
                    InternalAddress::new(size),
                    heap,
                )?;
                let root_key = self.sandbox_safe_system_state.get_root_key();
                let root_key_bytes = root_key.as_slice();
                let slice = valid_subslice(
                    "ic0.root_key_copy bytes",
                    InternalAddress::new(offset),
                    InternalAddress::new(size),
                    root_key_bytes,
                )?;
                deterministic_copy_from_slice(&mut heap[dst..dst + size], slice);

                Ok(())
            }
        };
        trace_syscall!(
            self,
            RootKeyCopy,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );

        result
    }

    fn ic0_data_certificate_present(&self) -> HypervisorResult<i32> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_data_certificate_present")),
            ApiType::Init { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::Update { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplicatedQuery { .. } => Ok(0),
            ApiType::NonReplicatedQuery {
                data_certificate, ..
            }
            | ApiType::CompositeQuery {
                data_certificate, ..
            } => match data_certificate {
                Some(_) => Ok(1),
                None => Ok(0),
            },
        };
        trace_syscall!(self, DataCertificatePresent, result);
        result
    }

    fn ic0_data_certificate_size(&self) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::ReplicatedQuery { .. } => Err(self.error_for("ic0_data_certificate_size")),
            ApiType::NonReplicatedQuery {
                data_certificate, ..
            }
            | ApiType::CompositeQuery {
                data_certificate, ..
            } => match data_certificate {
                Some(data_certificate) => Ok(data_certificate.len()),
                None => Err(self.error_for("ic0_data_certificate_size")),
            },
        };
        trace_syscall!(self, DataCertificateSize, result);
        result
    }

    fn ic0_data_certificate_copy(
        &mut self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        self.call_counters.data_certificate_copy += 1;
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::ReplicatedQuery { .. } => Err(self.error_for("ic0_data_certificate_copy")),
            ApiType::NonReplicatedQuery {
                data_certificate, ..
            }
            | ApiType::CompositeQuery {
                data_certificate, ..
            } => {
                match data_certificate {
                    Some(data_certificate) => {
                        let (upper_bound, overflow) = offset.overflowing_add(size);
                        if overflow || upper_bound > data_certificate.len() {
                            return Err(ToolchainContractViolation {
                                error: format!(
                                    "ic0_data_certificate_copy failed because offset + size is out \
                        of bounds. Found offset = {} and size = {} while offset + size \
                        must be <= {}",
                                    offset,
                                    size,
                                    data_certificate.len()
                                ),
                            });
                        }

                        let (upper_bound, overflow) = dst.overflowing_add(size);
                        if overflow || upper_bound > heap.len() {
                            return Err(ToolchainContractViolation {
                                error: format!(
                                    "ic0_data_certificate_copy failed because dst + size is out \
                        of bounds. Found dst = {} and size = {} while dst + size \
                        must be <= {}",
                                    dst,
                                    size,
                                    heap.len()
                                ),
                            });
                        }

                        // Copy the certificate into the canister.
                        deterministic_copy_from_slice(
                            &mut heap[dst..dst + size],
                            &data_certificate[offset..offset + size],
                        );
                        Ok(())
                    }
                    None => Err(self.error_for("ic0_data_certificate_copy")),
                }
            }
        };
        trace_syscall!(
            self,
            DataCertificateCopy,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );
        result
    }

    fn ic0_certified_data_set(
        &mut self,
        src: usize,
        size: usize,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let result = match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => {
                Err(self.error_for("ic0_certified_data_set"))
            }
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. } => {
                if size > CERTIFIED_DATA_MAX_LENGTH {
                    return Err(UserContractViolation {
                        error: format!(
                            "ic0_certified_data_set failed because the passed data must be \
                    no larger than {CERTIFIED_DATA_MAX_LENGTH} bytes. Found {size} bytes."
                        ),
                        suggestion: "Try certifying just the hash of your data instead of \
                        the full contents."
                            .to_string(),
                        doc_link: doc_ref("certified_data_set-payload-too-large"),
                    });
                }

                let (upper_bound, overflow) = src.overflowing_add(size);
                if overflow || upper_bound > heap.len() {
                    return Err(ToolchainContractViolation {
                        error: format!(
                            "ic0_certified_data_set failed because src + size is out \
                    of bounds. Found src = {} and size = {} while src + size \
                    must be <= {}",
                            src,
                            size,
                            heap.len()
                        ),
                    });
                }

                // Update the certified data.
                self.sandbox_safe_system_state
                    .system_state_modifications
                    .new_certified_data = Some(heap[src..src + size].to_vec());
                Ok(())
            }
        };
        trace_syscall!(
            self,
            CertifiedDataSet,
            result,
            src,
            size,
            summarize(heap, src, size)
        );
        result
    }

    fn ic0_canister_status(&self) -> HypervisorResult<u32> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_canister_status")),
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::Init { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Update { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => Ok(self.sandbox_safe_system_state.status as u32),
        };
        trace_syscall!(self, CanisterStatus, result);
        result
    }

    fn ic0_mint_cycles128(
        &mut self,
        amount: Cycles,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => Err(self.error_for("ic0_mint_cycles128")),
            ApiType::Update { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => {
                let actually_minted = self.sandbox_safe_system_state.mint_cycles(amount)?;
                copy_cycles_to_heap(actually_minted, dst, heap, "ic0_mint_cycles_128")?;
                Ok(())
            }
        };
        trace_syscall!(self, MintCycles128, result, amount);
        result
    }

    fn ic0_debug_print(&self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<()> {
        const MAX_DEBUG_MESSAGE_SIZE: usize = 32 * 1024;
        let size = size.min(MAX_DEBUG_MESSAGE_SIZE);
        let msg = match valid_subslice(
            "ic0.debug_print",
            InternalAddress::new(src),
            InternalAddress::new(size),
            heap,
        ) {
            Ok(bytes) => String::from_utf8_lossy(bytes).to_string(),
            // Do not trap here! `ic0_debug_print` should never fail!
            // If the specified memory range is invalid, ignore it and print the error message.
            Err(_) => "(debug message out of memory bounds)".to_string(),
        };
        match &self.api_type {
            ApiType::Start { time }
            | ApiType::Init { time, .. }
            | ApiType::SystemTask { time, .. }
            | ApiType::Update { time, .. }
            | ApiType::Cleanup { time, .. }
            | ApiType::CompositeCleanup { time, .. }
            | ApiType::NonReplicatedQuery { time, .. }
            | ApiType::CompositeQuery { time, .. }
            | ApiType::ReplicatedQuery { time, .. }
            | ApiType::PreUpgrade { time, .. }
            | ApiType::ReplyCallback { time, .. }
            | ApiType::CompositeReplyCallback { time, .. }
            | ApiType::RejectCallback { time, .. }
            | ApiType::CompositeRejectCallback { time, .. }
            | ApiType::InspectMessage { time, .. } => eprintln!(
                "{}: [Canister {}] {}",
                time, self.sandbox_safe_system_state.canister_id, msg
            ),
        }
        trace_syscall!(self, DebugPrint, src, size, summarize(heap, src, size));
        Ok(())
    }

    fn ic0_trap(&self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<()> {
        const MAX_ERROR_MESSAGE_SIZE: usize = 32 * 1024;
        let size = size.min(MAX_ERROR_MESSAGE_SIZE);
        let result = {
            let message = valid_subslice(
                "trap",
                InternalAddress::new(src),
                InternalAddress::new(size),
                heap,
            )
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .unwrap_or_else(|_| "(trap message out of memory bounds)".to_string());
            CalledTrap {
                message,
                backtrace: None,
            }
        };
        trace_syscall!(self, Trap, src, size, summarize(heap, src, size));
        Err(result)
    }

    fn ic0_is_controller(&self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<u32> {
        let msg_bytes = valid_subslice(
            "ic0.is_controller",
            InternalAddress::new(src),
            InternalAddress::new(size),
            heap,
        )?;
        let result = PrincipalId::try_from(msg_bytes)
            .map(|principal_id| {
                self.sandbox_safe_system_state
                    .is_controller(&principal_id)
                    .into()
            })
            .map_err(|e| HypervisorError::InvalidPrincipalId(PrincipalIdBlobParseError(e.0)));

        trace_syscall!(
            self,
            IsController,
            src,
            size,
            summarize(heap, src, size),
            result
        );
        result
    }

    /// Sets `timeout_seconds` to the provided value if not yet set, making this a best-effort call.
    /// The timeout is bounded from above by `MAX_CALL_TIMEOUT_SECONDS`.
    ///
    /// Fails and returns an error if `set_timeout()` was already called.
    fn ic0_call_with_best_effort_response(&mut self, timeout_seconds: u32) -> HypervisorResult<()> {
        let result = match &mut self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::InspectMessage { .. } => {
                Err(self.error_for("ic0_call_with_best_effort_response"))
            }
            ApiType::Update {
                outgoing_request, ..
            }
            | ApiType::CompositeQuery {
                    outgoing_request, ..
            }
            | ApiType::SystemTask {
                outgoing_request, ..
            }
            | ApiType::ReplyCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeReplyCallback {
                outgoing_request, ..
            }
            | ApiType::RejectCallback {
                outgoing_request, ..
            }
            | ApiType::CompositeRejectCallback {
                outgoing_request, ..
            } => match outgoing_request {
                None => Err(HypervisorError::ToolchainContractViolation {
                    error: "ic0.call_with_best_effort_response called when no call is under construction."
                        .to_string(),
                }),

                Some(request) if request.is_timeout_set() =>
                    Err(HypervisorError::ToolchainContractViolation {
                        error: "ic0_call_with_best_effort_response failed because a timeout is already set."
                            .to_string(),
                    }),

                Some(request) => {
                    let bounded_timeout =
                        std::cmp::min(timeout_seconds, MAX_CALL_TIMEOUT_SECONDS);
                    request.set_timeout(bounded_timeout);
                    Ok(())
                }
            },
        };
        trace_syscall!(self, CallWithBestEffortResponse, result, timeout_seconds);
        result
    }

    fn ic0_msg_deadline(&self) -> HypervisorResult<u64> {
        let result = match self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::InspectMessage { .. } => Err(self.error_for("ic0_msg_deadline")),
            ApiType::ReplicatedQuery { .. }
            | ApiType::Update { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. } => {
                let deadline = self.sandbox_safe_system_state.msg_deadline();
                Ok(Time::from(deadline).as_nanos_since_unix_epoch())
            }
        };

        trace_syscall!(self, CallWithBestEffortResponse, result);
        result
    }

    fn ic0_in_replicated_execution(&self) -> HypervisorResult<i32> {
        let result = match &self.api_type {
            ApiType::Start { .. }
            | ApiType::Init { .. }
            | ApiType::Cleanup { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Update { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => Ok(1),
            ApiType::InspectMessage { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. } => Ok(0),
        };
        trace_syscall!(self, ic0_in_replicated_execution, result);
        result
    }

    fn ic0_cycles_burn128(
        &mut self,
        amount: Cycles,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let method_name = "ic0_cycles_burn128";
        let result = match self.api_type {
            ApiType::Start { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::InspectMessage { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. } => Err(self.error_for(method_name)),
            ApiType::Init { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::Cleanup { .. }
            | ApiType::Update { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. } => {
                let cycles = self.sandbox_safe_system_state.cycles_burn128(
                    amount,
                    self.memory_usage.current_usage,
                    self.memory_usage.current_message_usage,
                );
                copy_cycles_to_heap(cycles, dst, heap, method_name)?;
                Ok(())
            }
        };
        trace_syscall!(self, CyclesBurn128, result, amount);
        result
    }

    fn ic0_cost_call(
        &self,
        method_name_size: u64,
        payload_size: u64,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let execution_mode =
            WasmExecutionMode::from_is_wasm64(self.sandbox_safe_system_state.is_wasm64_execution);
        let cost = self
            .sandbox_safe_system_state
            .get_cycles_account_manager()
            .xnet_call_total_fee(
                (method_name_size.saturating_add(payload_size)).into(),
                execution_mode,
                self.get_cost_schedule(),
            );
        copy_cycles_to_heap(cost, dst, heap, "ic0_cost_call")?;
        trace_syscall!(self, CostCall, cost);
        Ok(())
    }

    fn ic0_cost_create_canister(&self, dst: usize, heap: &mut [u8]) -> HypervisorResult<()> {
        let subnet_size = self.sandbox_safe_system_state.subnet_size;
        let cost = self
            .sandbox_safe_system_state
            .get_cycles_account_manager()
            .canister_creation_fee(subnet_size, self.get_cost_schedule());
        copy_cycles_to_heap(cost, dst, heap, "ic0_cost_create_canister")?;
        trace_syscall!(self, CostCreateCanister, cost);
        Ok(())
    }

    fn ic0_cost_http_request(
        &self,
        request_size: u64,
        max_res_bytes: u64,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let subnet_size = self.sandbox_safe_system_state.subnet_size;
        let cost = self
            .sandbox_safe_system_state
            .get_cycles_account_manager()
            .http_request_fee(
                request_size.into(),
                Some(max_res_bytes.into()),
                subnet_size,
                self.get_cost_schedule(),
            );
        copy_cycles_to_heap(cost, dst, heap, "ic0_cost_http_request")?;
        trace_syscall!(self, CostHttpRequest, cost);
        Ok(())
    }

    fn ic0_cost_http_request_v2(
        &self,
        params_src: usize,
        params_size: usize,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        #[derive(CandidType, Deserialize)]
        struct CostHttpRequestV2Params {
            request_bytes: u64,
            http_roundtrip_time_ms: u64,
            raw_response_bytes: u64,
            transformed_response_bytes: u64,
            transform_instructions: u64,
        }

        let params_bytes = valid_subslice(
            "ic0.cost_http_request_v2 heap",
            InternalAddress::new(params_src),
            InternalAddress::new(params_size),
            heap,
        )?;
        let mut decoder_config = DecoderConfig::new();
        decoder_config.set_skipping_quota(0);

        let cost_params_v2: CostHttpRequestV2Params =
            decode_one_with_config(params_bytes, &decoder_config).map_err(|e| {
                HypervisorError::ToolchainContractViolation {
                    error: format!(
                        "Failed to decode HttpRequestV2CostParams from Candid: {}",
                        e
                    ),
                }
            })?;

        let subnet_size = self.sandbox_safe_system_state.subnet_size;
        let cost = self
            .sandbox_safe_system_state
            .get_cycles_account_manager()
            .http_request_fee_v2(
                cost_params_v2.request_bytes.into(),
                Duration::from_millis(cost_params_v2.http_roundtrip_time_ms),
                cost_params_v2.raw_response_bytes.into(),
                cost_params_v2.transform_instructions.into(),
                cost_params_v2.transformed_response_bytes.into(),
                subnet_size,
                self.get_cost_schedule(),
            );
        copy_cycles_to_heap(cost, dst, heap, "ic0_cost_http_request_v2")?;
        trace_syscall!(self, CostHttpRequestV2, cost);
        Ok(())
    }

    fn ic0_cost_sign_with_ecdsa(
        &self,
        src: usize,
        size: usize,
        curve: u32,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<u32> {
        let key_bytes = valid_subslice(
            "ic0.cost_sign_with_ecdsa heap",
            InternalAddress::new(src),
            InternalAddress::new(size),
            heap,
        )?;
        let name = str::from_utf8(key_bytes)
            .map_err(|_| HypervisorError::ToolchainContractViolation {
                error: format!(
                    "Failed to decode key name {}",
                    String::from_utf8_lossy(key_bytes)
                ),
            })?
            .to_string();
        let Ok(curve) = EcdsaCurve::try_from(curve) else {
            return Ok(CostReturnCode::UnknownCurveOrAlgorithm as u32);
        };
        let key = MasterPublicKeyId::Ecdsa(EcdsaKeyId { curve, name });
        let Some((subnet_size, cost_schedule, _)) =
            self.sandbox_safe_system_state.get_key_subnet_details(key)
        else {
            return Ok(CostReturnCode::UnknownKey as u32);
        };
        let cost = self
            .sandbox_safe_system_state
            .get_cycles_account_manager()
            .ecdsa_signature_fee(subnet_size, cost_schedule);
        copy_cycles_to_heap(cost, dst, heap, "ic0_cost_sign_with_ecdsa")?;
        trace_syscall!(self, CostSignWithEcdsa, cost);
        Ok(CostReturnCode::Success as u32)
    }

    fn ic0_cost_sign_with_schnorr(
        &self,
        src: usize,
        size: usize,
        algorithm: u32,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<u32> {
        let key_bytes = valid_subslice(
            "ic0.cost_sign_with_schnorr heap",
            InternalAddress::new(src),
            InternalAddress::new(size),
            heap,
        )?;
        let name = str::from_utf8(key_bytes)
            .map_err(|_| HypervisorError::ToolchainContractViolation {
                error: format!(
                    "Failed to decode key name {}",
                    String::from_utf8_lossy(key_bytes)
                ),
            })?
            .to_string();
        let Ok(algorithm) = SchnorrAlgorithm::try_from(algorithm) else {
            return Ok(CostReturnCode::UnknownCurveOrAlgorithm as u32);
        };
        let key = MasterPublicKeyId::Schnorr(SchnorrKeyId { algorithm, name });
        let Some((subnet_size, cost_schedule, _)) =
            self.sandbox_safe_system_state.get_key_subnet_details(key)
        else {
            return Ok(CostReturnCode::UnknownKey as u32);
        };
        let cost = self
            .sandbox_safe_system_state
            .get_cycles_account_manager()
            .schnorr_signature_fee(subnet_size, cost_schedule);
        copy_cycles_to_heap(cost, dst, heap, "ic0_cost_sign_with_schnorr")?;
        trace_syscall!(self, CostSignWithSchnorr, cost);
        Ok(CostReturnCode::Success as u32)
    }

    fn ic0_cost_vetkd_derive_key(
        &self,
        src: usize,
        size: usize,
        curve: u32,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<u32> {
        let key_bytes = valid_subslice(
            "ic0.cost_vetkd_derive_key heap",
            InternalAddress::new(src),
            InternalAddress::new(size),
            heap,
        )?;
        let name = str::from_utf8(key_bytes)
            .map_err(|_| HypervisorError::ToolchainContractViolation {
                error: format!(
                    "Failed to decode key name {}",
                    String::from_utf8_lossy(key_bytes)
                ),
            })?
            .to_string();
        let Ok(curve) = VetKdCurve::try_from(curve) else {
            return Ok(CostReturnCode::UnknownCurveOrAlgorithm as u32);
        };
        let key = MasterPublicKeyId::VetKd(VetKdKeyId { curve, name });
        let Some((subnet_size, cost_schedule, _)) =
            self.sandbox_safe_system_state.get_key_subnet_details(key)
        else {
            return Ok(CostReturnCode::UnknownKey as u32);
        };
        let cost = self
            .sandbox_safe_system_state
            .get_cycles_account_manager()
            .vetkd_fee(subnet_size, cost_schedule);
        copy_cycles_to_heap(cost, dst, heap, "ic0_cost_vetkd_derive_key")?;
        trace_syscall!(self, CostVetkdDeriveEncryptedKey, cost);
        Ok(CostReturnCode::Success as u32)
    }

    fn ic0_subnet_self_size(&self) -> HypervisorResult<usize> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0_subnet_self_size")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::InspectMessage { .. } => {
                let subnet_id = self.sandbox_safe_system_state.get_subnet_id();
                Ok(subnet_id.get_ref().as_slice().len())
            }
        };

        trace_syscall!(self, SubnetSelfSize, result);
        result
    }

    fn ic0_subnet_self_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let result = match &self.api_type {
            ApiType::Start { .. } => Err(self.error_for("ic0.subnet_self_copy")),
            ApiType::Init { .. }
            | ApiType::SystemTask { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeCleanup { .. }
            | ApiType::Update { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::PreUpgrade { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::InspectMessage { .. } => {
                valid_subslice(
                    "ic0.subnet_self_copy heap",
                    InternalAddress::new(dst),
                    InternalAddress::new(size),
                    heap,
                )?;
                let subnet_id = self.sandbox_safe_system_state.get_subnet_id();
                let id_bytes = subnet_id.get_ref().as_slice();
                let slice = valid_subslice(
                    "ic0.subnet_self_copy id",
                    InternalAddress::new(offset),
                    InternalAddress::new(size),
                    id_bytes,
                )?;
                deterministic_copy_from_slice(&mut heap[dst..dst + size], slice);

                Ok(())
            }
        };
        trace_syscall!(
            self,
            SubnetSelfCopy,
            dst,
            offset,
            size,
            summarize(heap, dst, size)
        );

        result
    }
}

/// The default implementation of the `OutOfInstructionHandler` trait.
/// It simply returns an out-of-instructions error.
#[derive(Default)]
pub struct DefaultOutOfInstructionsHandler {
    message_instruction_limit: NumInstructions,
}

impl DefaultOutOfInstructionsHandler {
    pub fn new(message_instruction_limit: NumInstructions) -> Self {
        Self {
            message_instruction_limit,
        }
    }
}

impl OutOfInstructionsHandler for DefaultOutOfInstructionsHandler {
    fn out_of_instructions(&self, _instruction_counter: i64) -> HypervisorResult<i64> {
        Err(HypervisorError::InstructionLimitExceeded(
            self.message_instruction_limit,
        ))
    }

    fn yield_for_dirty_memory_copy(&self) -> HypervisorResult<i64> {
        // This is a no-op, should only happen if it is called on a subnet where DTS is completely disabled.
        // 0 instructions were executed as a result.
        Ok(0)
    }
}

pub(crate) fn copy_cycles_to_heap(
    cycles: Cycles,
    dst: usize,
    heap: &mut [u8],
    method_name: &str,
) -> HypervisorResult<()> {
    // Copy a 128-bit value to the canister memory.
    let bytes = cycles.get().to_le_bytes();
    let size = bytes.len();
    assert_eq!(size, 16);

    let (upper_bound, overflow) = dst.overflowing_add(size);
    if overflow || upper_bound > heap.len() {
        return Err(ToolchainContractViolation {
            error: format!(
                "{} failed because dst + size is out of bounds.\
        Found dst = {} and size = {} while must be <= {}",
                method_name,
                dst,
                size,
                heap.len()
            ),
        });
    }
    deterministic_copy_from_slice(&mut heap[dst..dst + size], &bytes);
    Ok(())
}

pub(crate) fn valid_subslice<'a>(
    ctx: &str,
    src: InternalAddress,
    len: InternalAddress,
    slice: &'a [u8],
) -> HypervisorResult<&'a [u8]> {
    let result_address = src.checked_add(len);

    match result_address {
        Ok(addr) => {
            if slice.len() < addr.get() {
                Err(ToolchainContractViolation {
                    error: format!(
                        "{}: src={} + length={} exceeds the slice size={}",
                        ctx,
                        src.get(),
                        len.get(),
                        slice.len()
                    ),
                })
            } else {
                Ok(&slice[src.get()..addr.get()])
            }
        }
        Err(_) => Err(ToolchainContractViolation {
            error: format!(
                "{}: src={} + length={} is an invalid address",
                ctx,
                src.get(),
                len.get()
            ),
        }),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_subslice() {
        // empty slice
        assert!(valid_subslice("", InternalAddress::new(0), InternalAddress::new(0), &[]).is_ok());
        // the only possible non-empty slice
        assert!(valid_subslice("", InternalAddress::new(0), InternalAddress::new(1), &[1]).is_ok());
        // valid empty slice
        assert!(valid_subslice("", InternalAddress::new(1), InternalAddress::new(0), &[1]).is_ok());

        // just some valid cases
        assert!(
            valid_subslice(
                "",
                InternalAddress::new(0),
                InternalAddress::new(4),
                &[1, 2, 3, 4]
            )
            .is_ok()
        );
        assert!(
            valid_subslice(
                "",
                InternalAddress::new(1),
                InternalAddress::new(3),
                &[1, 2, 3, 4]
            )
            .is_ok()
        );
        assert!(
            valid_subslice(
                "",
                InternalAddress::new(2),
                InternalAddress::new(2),
                &[1, 2, 3, 4]
            )
            .is_ok()
        );

        // invalid longer-than-the-heap subslices
        assert!(
            valid_subslice(
                "",
                InternalAddress::new(3),
                InternalAddress::new(2),
                &[1, 2, 3, 4]
            )
            .is_err()
        );
        assert!(
            valid_subslice(
                "",
                InternalAddress::new(0),
                InternalAddress::new(5),
                &[1, 2, 3, 4]
            )
            .is_err()
        );
        assert!(
            valid_subslice(
                "",
                InternalAddress::new(4),
                InternalAddress::new(1),
                &[1, 2, 3, 4]
            )
            .is_err()
        );
    }
}
