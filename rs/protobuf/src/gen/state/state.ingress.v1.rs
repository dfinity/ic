#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusUnknown {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusProcessing {
    #[prost(message, optional, tag = "1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag = "2")]
    pub time_nanos: u64,
    #[prost(message, optional, tag = "3")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusReceived {
    #[prost(message, optional, tag = "1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag = "2")]
    pub time_nanos: u64,
    #[prost(message, optional, tag = "3")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusCompleted {
    #[prost(message, optional, tag = "1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag = "4")]
    pub time_nanos: u64,
    #[prost(message, optional, tag = "5")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
    #[prost(oneof = "ingress_status_completed::WasmResult", tags = "2, 3")]
    pub wasm_result: ::core::option::Option<ingress_status_completed::WasmResult>,
}
/// Nested message and enum types in `IngressStatusCompleted`.
pub mod ingress_status_completed {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WasmResult {
        #[prost(bytes, tag = "2")]
        Reply(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "3")]
        Reject(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusFailed {
    #[prost(message, optional, tag = "1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(string, tag = "3")]
    pub err_description: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub time_nanos: u64,
    #[prost(message, optional, tag = "5")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
    #[prost(enumeration = "ErrorCode", tag = "6")]
    pub err_code: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusDone {
    #[prost(message, optional, tag = "1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag = "2")]
    pub time_nanos: u64,
    #[prost(message, optional, tag = "3")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PruningEntry {
    #[prost(uint64, tag = "1")]
    pub time_nanos: u64,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub messages: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatus {
    #[prost(oneof = "ingress_status::Status", tags = "1, 2, 3, 4, 5, 6")]
    pub status: ::core::option::Option<ingress_status::Status>,
}
/// Nested message and enum types in `IngressStatus`.
pub mod ingress_status {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Status {
        #[prost(message, tag = "1")]
        Unknown(super::IngressStatusUnknown),
        #[prost(message, tag = "2")]
        Processing(super::IngressStatusProcessing),
        #[prost(message, tag = "3")]
        Received(super::IngressStatusReceived),
        #[prost(message, tag = "4")]
        Completed(super::IngressStatusCompleted),
        #[prost(message, tag = "5")]
        Failed(super::IngressStatusFailed),
        #[prost(message, tag = "6")]
        Done(super::IngressStatusDone),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusEntry {
    #[prost(bytes = "vec", tag = "1")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub status: ::core::option::Option<IngressStatus>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressHistoryState {
    #[prost(message, repeated, tag = "1")]
    pub statuses: ::prost::alloc::vec::Vec<IngressStatusEntry>,
    #[prost(message, repeated, tag = "2")]
    pub pruning_times: ::prost::alloc::vec::Vec<PruningEntry>,
    /// The earliest time in `pruning_times` with associated message IDs that
    /// may still be of type completed or failed.
    #[prost(uint64, tag = "3")]
    pub next_terminal_time: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ingress {
    #[prost(message, optional, tag = "1")]
    pub source: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(message, optional, tag = "2")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(string, tag = "3")]
    pub method_name: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "4")]
    pub method_payload: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub expiry_time_nanos: u64,
    /// It may be present for a subnet message.
    /// Represents the id of the canister that the message is targeting.
    #[prost(message, optional, tag = "7")]
    pub effective_canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    Unspecified = 0,
    /// 1xx -- `RejectCode::SysFatal`
    SubnetOversubscribed = 101,
    MaxNumberOfCanistersReached = 102,
    /// 2xx -- `RejectCode::SysTransient`
    CanisterQueueFull = 201,
    IngressMessageTimeout = 202,
    CanisterQueueNotEmpty = 203,
    IngressHistoryFull = 204,
    CanisterIdAlreadyExists = 205,
    StopCanisterRequestTimeout = 206,
    CanisterOutOfCycles = 207,
    CertifiedStateUnavailable = 208,
    CanisterInstallCodeRateLimited = 209,
    CanisterHeapDeltaRateLimited = 210,
    /// 3xx -- `RejectCode::DestinationInvalid`
    CanisterNotFound = 301,
    CanisterSnapshotNotFound = 305,
    /// 4xx -- `RejectCode::CanisterReject`
    InsufficientMemoryAllocation = 402,
    InsufficientCyclesForCreateCanister = 403,
    SubnetNotFound = 404,
    CanisterNotHostedBySubnet = 405,
    CanisterRejectedMessage = 406,
    UnknownManagementMessage = 407,
    InvalidManagementPayload = 408,
    CanisterTrapped = 502,
    CanisterCalledTrap = 503,
    CanisterContractViolation = 504,
    CanisterInvalidWasm = 505,
    CanisterDidNotReply = 506,
    CanisterOutOfMemory = 507,
    CanisterStopped = 508,
    CanisterStopping = 509,
    CanisterNotStopped = 510,
    CanisterStoppingCancelled = 511,
    CanisterInvalidController = 512,
    CanisterFunctionNotFound = 513,
    CanisterNonEmpty = 514,
    QueryCallGraphLoopDetected = 517,
    InsufficientCyclesInCall = 520,
    CanisterWasmEngineError = 521,
    CanisterInstructionLimitExceeded = 522,
    CanisterMemoryAccessLimitExceeded = 524,
    QueryCallGraphTooDeep = 525,
    QueryCallGraphTotalInstructionLimitExceeded = 526,
    CompositeQueryCalledInReplicatedMode = 527,
    QueryTimeLimitExceeded = 528,
    QueryCallGraphInternal = 529,
    InsufficientCyclesInComputeAllocation = 530,
    InsufficientCyclesInMemoryAllocation = 531,
    InsufficientCyclesInMemoryGrow = 532,
    ReservedCyclesLimitExceededInMemoryAllocation = 533,
    ReservedCyclesLimitExceededInMemoryGrow = 534,
    InsufficientCyclesInMessageMemoryGrow = 535,
    CanisterMethodNotFound = 536,
    CanisterWasmModuleNotFound = 537,
    CanisterAlreadyInstalled = 538,
    CanisterWasmMemoryLimitExceeded = 539,
    ReservedCyclesLimitIsTooLow = 540,
}
impl ErrorCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ErrorCode::Unspecified => "ERROR_CODE_UNSPECIFIED",
            ErrorCode::SubnetOversubscribed => "ERROR_CODE_SUBNET_OVERSUBSCRIBED",
            ErrorCode::MaxNumberOfCanistersReached => "ERROR_CODE_MAX_NUMBER_OF_CANISTERS_REACHED",
            ErrorCode::CanisterQueueFull => "ERROR_CODE_CANISTER_QUEUE_FULL",
            ErrorCode::IngressMessageTimeout => "ERROR_CODE_INGRESS_MESSAGE_TIMEOUT",
            ErrorCode::CanisterQueueNotEmpty => "ERROR_CODE_CANISTER_QUEUE_NOT_EMPTY",
            ErrorCode::IngressHistoryFull => "ERROR_CODE_INGRESS_HISTORY_FULL",
            ErrorCode::CanisterIdAlreadyExists => "ERROR_CODE_CANISTER_ID_ALREADY_EXISTS",
            ErrorCode::StopCanisterRequestTimeout => "ERROR_CODE_STOP_CANISTER_REQUEST_TIMEOUT",
            ErrorCode::CanisterOutOfCycles => "ERROR_CODE_CANISTER_OUT_OF_CYCLES",
            ErrorCode::CertifiedStateUnavailable => "ERROR_CODE_CERTIFIED_STATE_UNAVAILABLE",
            ErrorCode::CanisterInstallCodeRateLimited => {
                "ERROR_CODE_CANISTER_INSTALL_CODE_RATE_LIMITED"
            }
            ErrorCode::CanisterHeapDeltaRateLimited => {
                "ERROR_CODE_CANISTER_HEAP_DELTA_RATE_LIMITED"
            }
            ErrorCode::CanisterNotFound => "ERROR_CODE_CANISTER_NOT_FOUND",
            ErrorCode::CanisterSnapshotNotFound => "ERROR_CODE_CANISTER_SNAPSHOT_NOT_FOUND",
            ErrorCode::InsufficientMemoryAllocation => "ERROR_CODE_INSUFFICIENT_MEMORY_ALLOCATION",
            ErrorCode::InsufficientCyclesForCreateCanister => {
                "ERROR_CODE_INSUFFICIENT_CYCLES_FOR_CREATE_CANISTER"
            }
            ErrorCode::SubnetNotFound => "ERROR_CODE_SUBNET_NOT_FOUND",
            ErrorCode::CanisterNotHostedBySubnet => "ERROR_CODE_CANISTER_NOT_HOSTED_BY_SUBNET",
            ErrorCode::CanisterRejectedMessage => "ERROR_CODE_CANISTER_REJECTED_MESSAGE",
            ErrorCode::UnknownManagementMessage => "ERROR_CODE_UNKNOWN_MANAGEMENT_MESSAGE",
            ErrorCode::InvalidManagementPayload => "ERROR_CODE_INVALID_MANAGEMENT_PAYLOAD",
            ErrorCode::CanisterTrapped => "ERROR_CODE_CANISTER_TRAPPED",
            ErrorCode::CanisterCalledTrap => "ERROR_CODE_CANISTER_CALLED_TRAP",
            ErrorCode::CanisterContractViolation => "ERROR_CODE_CANISTER_CONTRACT_VIOLATION",
            ErrorCode::CanisterInvalidWasm => "ERROR_CODE_CANISTER_INVALID_WASM",
            ErrorCode::CanisterDidNotReply => "ERROR_CODE_CANISTER_DID_NOT_REPLY",
            ErrorCode::CanisterOutOfMemory => "ERROR_CODE_CANISTER_OUT_OF_MEMORY",
            ErrorCode::CanisterStopped => "ERROR_CODE_CANISTER_STOPPED",
            ErrorCode::CanisterStopping => "ERROR_CODE_CANISTER_STOPPING",
            ErrorCode::CanisterNotStopped => "ERROR_CODE_CANISTER_NOT_STOPPED",
            ErrorCode::CanisterStoppingCancelled => "ERROR_CODE_CANISTER_STOPPING_CANCELLED",
            ErrorCode::CanisterInvalidController => "ERROR_CODE_CANISTER_INVALID_CONTROLLER",
            ErrorCode::CanisterFunctionNotFound => "ERROR_CODE_CANISTER_FUNCTION_NOT_FOUND",
            ErrorCode::CanisterNonEmpty => "ERROR_CODE_CANISTER_NON_EMPTY",
            ErrorCode::QueryCallGraphLoopDetected => "ERROR_CODE_QUERY_CALL_GRAPH_LOOP_DETECTED",
            ErrorCode::InsufficientCyclesInCall => "ERROR_CODE_INSUFFICIENT_CYCLES_IN_CALL",
            ErrorCode::CanisterWasmEngineError => "ERROR_CODE_CANISTER_WASM_ENGINE_ERROR",
            ErrorCode::CanisterInstructionLimitExceeded => {
                "ERROR_CODE_CANISTER_INSTRUCTION_LIMIT_EXCEEDED"
            }
            ErrorCode::CanisterMemoryAccessLimitExceeded => {
                "ERROR_CODE_CANISTER_MEMORY_ACCESS_LIMIT_EXCEEDED"
            }
            ErrorCode::QueryCallGraphTooDeep => "ERROR_CODE_QUERY_CALL_GRAPH_TOO_DEEP",
            ErrorCode::QueryCallGraphTotalInstructionLimitExceeded => {
                "ERROR_CODE_QUERY_CALL_GRAPH_TOTAL_INSTRUCTION_LIMIT_EXCEEDED"
            }
            ErrorCode::CompositeQueryCalledInReplicatedMode => {
                "ERROR_CODE_COMPOSITE_QUERY_CALLED_IN_REPLICATED_MODE"
            }
            ErrorCode::QueryTimeLimitExceeded => "ERROR_CODE_QUERY_TIME_LIMIT_EXCEEDED",
            ErrorCode::QueryCallGraphInternal => "ERROR_CODE_QUERY_CALL_GRAPH_INTERNAL",
            ErrorCode::InsufficientCyclesInComputeAllocation => {
                "ERROR_CODE_INSUFFICIENT_CYCLES_IN_COMPUTE_ALLOCATION"
            }
            ErrorCode::InsufficientCyclesInMemoryAllocation => {
                "ERROR_CODE_INSUFFICIENT_CYCLES_IN_MEMORY_ALLOCATION"
            }
            ErrorCode::InsufficientCyclesInMemoryGrow => {
                "ERROR_CODE_INSUFFICIENT_CYCLES_IN_MEMORY_GROW"
            }
            ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation => {
                "ERROR_CODE_RESERVED_CYCLES_LIMIT_EXCEEDED_IN_MEMORY_ALLOCATION"
            }
            ErrorCode::ReservedCyclesLimitExceededInMemoryGrow => {
                "ERROR_CODE_RESERVED_CYCLES_LIMIT_EXCEEDED_IN_MEMORY_GROW"
            }
            ErrorCode::InsufficientCyclesInMessageMemoryGrow => {
                "ERROR_CODE_INSUFFICIENT_CYCLES_IN_MESSAGE_MEMORY_GROW"
            }
            ErrorCode::CanisterMethodNotFound => "ERROR_CODE_CANISTER_METHOD_NOT_FOUND",
            ErrorCode::CanisterWasmModuleNotFound => "ERROR_CODE_CANISTER_WASM_MODULE_NOT_FOUND",
            ErrorCode::CanisterAlreadyInstalled => "ERROR_CODE_CANISTER_ALREADY_INSTALLED",
            ErrorCode::CanisterWasmMemoryLimitExceeded => {
                "ERROR_CODE_CANISTER_WASM_MEMORY_LIMIT_EXCEEDED"
            }
            ErrorCode::ReservedCyclesLimitIsTooLow => "ERROR_CODE_RESERVED_CYCLES_LIMIT_IS_TOO_LOW",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ERROR_CODE_UNSPECIFIED" => Some(Self::Unspecified),
            "ERROR_CODE_SUBNET_OVERSUBSCRIBED" => Some(Self::SubnetOversubscribed),
            "ERROR_CODE_MAX_NUMBER_OF_CANISTERS_REACHED" => Some(Self::MaxNumberOfCanistersReached),
            "ERROR_CODE_CANISTER_QUEUE_FULL" => Some(Self::CanisterQueueFull),
            "ERROR_CODE_INGRESS_MESSAGE_TIMEOUT" => Some(Self::IngressMessageTimeout),
            "ERROR_CODE_CANISTER_QUEUE_NOT_EMPTY" => Some(Self::CanisterQueueNotEmpty),
            "ERROR_CODE_INGRESS_HISTORY_FULL" => Some(Self::IngressHistoryFull),
            "ERROR_CODE_CANISTER_ID_ALREADY_EXISTS" => Some(Self::CanisterIdAlreadyExists),
            "ERROR_CODE_STOP_CANISTER_REQUEST_TIMEOUT" => Some(Self::StopCanisterRequestTimeout),
            "ERROR_CODE_CANISTER_OUT_OF_CYCLES" => Some(Self::CanisterOutOfCycles),
            "ERROR_CODE_CERTIFIED_STATE_UNAVAILABLE" => Some(Self::CertifiedStateUnavailable),
            "ERROR_CODE_CANISTER_INSTALL_CODE_RATE_LIMITED" => {
                Some(Self::CanisterInstallCodeRateLimited)
            }
            "ERROR_CODE_CANISTER_HEAP_DELTA_RATE_LIMITED" => {
                Some(Self::CanisterHeapDeltaRateLimited)
            }
            "ERROR_CODE_CANISTER_NOT_FOUND" => Some(Self::CanisterNotFound),
            "ERROR_CODE_CANISTER_SNAPSHOT_NOT_FOUND" => Some(Self::CanisterSnapshotNotFound),
            "ERROR_CODE_INSUFFICIENT_MEMORY_ALLOCATION" => Some(Self::InsufficientMemoryAllocation),
            "ERROR_CODE_INSUFFICIENT_CYCLES_FOR_CREATE_CANISTER" => {
                Some(Self::InsufficientCyclesForCreateCanister)
            }
            "ERROR_CODE_SUBNET_NOT_FOUND" => Some(Self::SubnetNotFound),
            "ERROR_CODE_CANISTER_NOT_HOSTED_BY_SUBNET" => Some(Self::CanisterNotHostedBySubnet),
            "ERROR_CODE_CANISTER_REJECTED_MESSAGE" => Some(Self::CanisterRejectedMessage),
            "ERROR_CODE_UNKNOWN_MANAGEMENT_MESSAGE" => Some(Self::UnknownManagementMessage),
            "ERROR_CODE_INVALID_MANAGEMENT_PAYLOAD" => Some(Self::InvalidManagementPayload),
            "ERROR_CODE_CANISTER_TRAPPED" => Some(Self::CanisterTrapped),
            "ERROR_CODE_CANISTER_CALLED_TRAP" => Some(Self::CanisterCalledTrap),
            "ERROR_CODE_CANISTER_CONTRACT_VIOLATION" => Some(Self::CanisterContractViolation),
            "ERROR_CODE_CANISTER_INVALID_WASM" => Some(Self::CanisterInvalidWasm),
            "ERROR_CODE_CANISTER_DID_NOT_REPLY" => Some(Self::CanisterDidNotReply),
            "ERROR_CODE_CANISTER_OUT_OF_MEMORY" => Some(Self::CanisterOutOfMemory),
            "ERROR_CODE_CANISTER_STOPPED" => Some(Self::CanisterStopped),
            "ERROR_CODE_CANISTER_STOPPING" => Some(Self::CanisterStopping),
            "ERROR_CODE_CANISTER_NOT_STOPPED" => Some(Self::CanisterNotStopped),
            "ERROR_CODE_CANISTER_STOPPING_CANCELLED" => Some(Self::CanisterStoppingCancelled),
            "ERROR_CODE_CANISTER_INVALID_CONTROLLER" => Some(Self::CanisterInvalidController),
            "ERROR_CODE_CANISTER_FUNCTION_NOT_FOUND" => Some(Self::CanisterFunctionNotFound),
            "ERROR_CODE_CANISTER_NON_EMPTY" => Some(Self::CanisterNonEmpty),
            "ERROR_CODE_QUERY_CALL_GRAPH_LOOP_DETECTED" => Some(Self::QueryCallGraphLoopDetected),
            "ERROR_CODE_INSUFFICIENT_CYCLES_IN_CALL" => Some(Self::InsufficientCyclesInCall),
            "ERROR_CODE_CANISTER_WASM_ENGINE_ERROR" => Some(Self::CanisterWasmEngineError),
            "ERROR_CODE_CANISTER_INSTRUCTION_LIMIT_EXCEEDED" => {
                Some(Self::CanisterInstructionLimitExceeded)
            }
            "ERROR_CODE_CANISTER_MEMORY_ACCESS_LIMIT_EXCEEDED" => {
                Some(Self::CanisterMemoryAccessLimitExceeded)
            }
            "ERROR_CODE_QUERY_CALL_GRAPH_TOO_DEEP" => Some(Self::QueryCallGraphTooDeep),
            "ERROR_CODE_QUERY_CALL_GRAPH_TOTAL_INSTRUCTION_LIMIT_EXCEEDED" => {
                Some(Self::QueryCallGraphTotalInstructionLimitExceeded)
            }
            "ERROR_CODE_COMPOSITE_QUERY_CALLED_IN_REPLICATED_MODE" => {
                Some(Self::CompositeQueryCalledInReplicatedMode)
            }
            "ERROR_CODE_QUERY_TIME_LIMIT_EXCEEDED" => Some(Self::QueryTimeLimitExceeded),
            "ERROR_CODE_QUERY_CALL_GRAPH_INTERNAL" => Some(Self::QueryCallGraphInternal),
            "ERROR_CODE_INSUFFICIENT_CYCLES_IN_COMPUTE_ALLOCATION" => {
                Some(Self::InsufficientCyclesInComputeAllocation)
            }
            "ERROR_CODE_INSUFFICIENT_CYCLES_IN_MEMORY_ALLOCATION" => {
                Some(Self::InsufficientCyclesInMemoryAllocation)
            }
            "ERROR_CODE_INSUFFICIENT_CYCLES_IN_MEMORY_GROW" => {
                Some(Self::InsufficientCyclesInMemoryGrow)
            }
            "ERROR_CODE_RESERVED_CYCLES_LIMIT_EXCEEDED_IN_MEMORY_ALLOCATION" => {
                Some(Self::ReservedCyclesLimitExceededInMemoryAllocation)
            }
            "ERROR_CODE_RESERVED_CYCLES_LIMIT_EXCEEDED_IN_MEMORY_GROW" => {
                Some(Self::ReservedCyclesLimitExceededInMemoryGrow)
            }
            "ERROR_CODE_INSUFFICIENT_CYCLES_IN_MESSAGE_MEMORY_GROW" => {
                Some(Self::InsufficientCyclesInMessageMemoryGrow)
            }
            "ERROR_CODE_CANISTER_METHOD_NOT_FOUND" => Some(Self::CanisterMethodNotFound),
            "ERROR_CODE_CANISTER_WASM_MODULE_NOT_FOUND" => Some(Self::CanisterWasmModuleNotFound),
            "ERROR_CODE_CANISTER_ALREADY_INSTALLED" => Some(Self::CanisterAlreadyInstalled),
            "ERROR_CODE_CANISTER_WASM_MEMORY_LIMIT_EXCEEDED" => {
                Some(Self::CanisterWasmMemoryLimitExceeded)
            }
            "ERROR_CODE_RESERVED_CYCLES_LIMIT_IS_TOO_LOW" => {
                Some(Self::ReservedCyclesLimitIsTooLow)
            }
            _ => None,
        }
    }
}
