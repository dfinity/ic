//! A crate that groups user-facing and internal error types and codes produced
//! by the Internet Computer.
use ic_protobuf::{
    proxy::ProxyDecodeError, state::ingress::v1::ErrorCode as ErrorCodeProto,
    types::v1::RejectCode as RejectCodeProto,
};
use ic_utils::str::StrEllipsize;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};
use strum_macros::EnumIter;

#[derive(Copy, Clone, Debug)]
pub enum TryFromError {
    ValueOutOfRange(u64),
}

/// Reject codes are integers that canisters should pass to msg.reject
/// system API calls. These errors are designed for programmatic error
/// handling, not for end-users. They are also used for classification
/// of user-facing errors.
///
/// See <https://internetcomputer.org/docs/current/references/ic-interface-spec#reject-codes>
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deserialize, EnumIter, Serialize)]
pub enum RejectCode {
    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,
}

impl std::fmt::Display for RejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl RejectCode {
    fn to_str(self) -> &'static str {
        match self {
            RejectCode::SysFatal => "SYS_FATAL",
            RejectCode::SysTransient => "SYS_TRANSIENT",
            RejectCode::DestinationInvalid => "DESTINATION_INVALID",
            RejectCode::CanisterReject => "CANISTER_REJECT",
            RejectCode::CanisterError => "CANISTER_ERROR",
        }
    }
}

impl From<RejectCode> for RejectCodeProto {
    fn from(value: RejectCode) -> Self {
        match value {
            RejectCode::SysFatal => RejectCodeProto::SysFatal,
            RejectCode::SysTransient => RejectCodeProto::SysTransient,
            RejectCode::DestinationInvalid => RejectCodeProto::DestinationInvalid,
            RejectCode::CanisterReject => RejectCodeProto::CanisterReject,
            RejectCode::CanisterError => RejectCodeProto::CanisterError,
        }
    }
}

impl TryFrom<RejectCodeProto> for RejectCode {
    type Error = ProxyDecodeError;

    fn try_from(value: RejectCodeProto) -> Result<Self, Self::Error> {
        match value {
            RejectCodeProto::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "RejectCode",
                err: format!("Unexpected value for reject code {:?}", value),
            }),
            RejectCodeProto::SysFatal => Ok(RejectCode::SysFatal),
            RejectCodeProto::SysTransient => Ok(RejectCode::SysTransient),
            RejectCodeProto::DestinationInvalid => Ok(RejectCode::DestinationInvalid),
            RejectCodeProto::CanisterReject => Ok(RejectCode::CanisterReject),
            RejectCodeProto::CanisterError => Ok(RejectCode::CanisterError),
        }
    }
}

impl TryFrom<u64> for RejectCode {
    type Error = TryFromError;
    fn try_from(code: u64) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(RejectCode::SysFatal),
            2 => Ok(RejectCode::SysTransient),
            3 => Ok(RejectCode::DestinationInvalid),
            4 => Ok(RejectCode::CanisterReject),
            5 => Ok(RejectCode::CanisterError),
            _ => Err(TryFromError::ValueOutOfRange(code)),
        }
    }
}

impl From<ErrorCode> for RejectCode {
    fn from(err: ErrorCode) -> RejectCode {
        use ErrorCode::*;
        use RejectCode::*;
        match err {
            // Fatal system errors.
            SubnetOversubscribed => SysFatal,
            MaxNumberOfCanistersReached => SysFatal,
            // Transient system errors.
            CanisterQueueFull => SysTransient,
            IngressMessageTimeout => SysTransient,
            CanisterQueueNotEmpty => SysTransient,
            IngressHistoryFull => SysTransient,
            CanisterIdAlreadyExists => SysTransient,
            StopCanisterRequestTimeout => SysTransient,
            CanisterOutOfCycles => SysTransient,
            CertifiedStateUnavailable => SysTransient,
            CanisterInstallCodeRateLimited => SysTransient,
            CanisterHeapDeltaRateLimited => SysTransient,
            // Invalid destination errors.
            CanisterNotFound => DestinationInvalid,
            CanisterSnapshotNotFound => DestinationInvalid,
            // Explicit reject errors.
            InsufficientCyclesForCreateCanister => CanisterReject,
            InsufficientMemoryAllocation => CanisterReject,
            SubnetNotFound => CanisterReject,
            CanisterRejectedMessage => CanisterReject,
            UnknownManagementMessage => CanisterReject,
            InvalidManagementPayload => CanisterReject,
            CanisterNotHostedBySubnet => CanisterReject,
            // Canister errors.
            CanisterInvalidController => CanisterError,
            CanisterFunctionNotFound => CanisterError,
            CanisterNonEmpty => CanisterError,
            CanisterTrapped => CanisterError,
            CanisterCalledTrap => CanisterError,
            CanisterContractViolation => CanisterError,
            CanisterInvalidWasm => CanisterError,
            CanisterDidNotReply => CanisterError,
            CanisterOutOfMemory => CanisterError,
            CanisterStopped => CanisterError,
            CanisterStopping => CanisterError,
            CanisterNotStopped => CanisterError,
            CanisterStoppingCancelled => CanisterError,
            QueryCallGraphLoopDetected => CanisterError,
            InsufficientCyclesInCall => CanisterError,
            CanisterWasmEngineError => CanisterError,
            CanisterInstructionLimitExceeded => CanisterError,
            CanisterMemoryAccessLimitExceeded => CanisterError,
            QueryCallGraphTooDeep => CanisterError,
            QueryCallGraphTotalInstructionLimitExceeded => CanisterError,
            CompositeQueryCalledInReplicatedMode => CanisterError,
            QueryTimeLimitExceeded => CanisterError,
            QueryCallGraphInternal => CanisterError,
            InsufficientCyclesInComputeAllocation => CanisterError,
            InsufficientCyclesInMemoryAllocation => CanisterError,
            InsufficientCyclesInMemoryGrow => CanisterError,
            ReservedCyclesLimitExceededInMemoryAllocation => CanisterError,
            ReservedCyclesLimitExceededInMemoryGrow => CanisterError,
            ReservedCyclesLimitIsTooLow => CanisterError,
            InsufficientCyclesInMessageMemoryGrow => CanisterError,
            CanisterMethodNotFound => CanisterError,
            CanisterWasmModuleNotFound => CanisterError,
            CanisterAlreadyInstalled => CanisterError,
            CanisterWasmMemoryLimitExceeded => CanisterError,
        }
    }
}

/// User-facing error codes.
///
/// The error codes are currently assigned using an HTTP-like
/// convention: the most significant digit is the corresponding reject
/// code and the rest is just a sequentially assigned two-digit
/// number.
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, EnumIter, Serialize,
)]
pub enum ErrorCode {
    // 1xx -- `RejectCode::SysFatal`
    SubnetOversubscribed = 101,
    MaxNumberOfCanistersReached = 102,
    // 2xx -- `RejectCode::SysTransient`
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
    // 3xx -- `RejectCode::DestinationInvalid`
    CanisterNotFound = 301,
    CanisterSnapshotNotFound = 305,
    // 4xx -- `RejectCode::CanisterReject`
    // 401
    InsufficientMemoryAllocation = 402,
    InsufficientCyclesForCreateCanister = 403,
    SubnetNotFound = 404,
    CanisterNotHostedBySubnet = 405,
    CanisterRejectedMessage = 406,
    UnknownManagementMessage = 407,
    InvalidManagementPayload = 408,
    // 5xx -- `RejectCode::CanisterError`
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

impl TryFrom<ErrorCodeProto> for ErrorCode {
    type Error = ProxyDecodeError;
    fn try_from(code: ErrorCodeProto) -> Result<ErrorCode, Self::Error> {
        match code {
            ErrorCodeProto::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "ErrorCode",
                err: format!("Unexpected value of error code: {:?}", code),
            }),
            ErrorCodeProto::SubnetOversubscribed => Ok(ErrorCode::SubnetOversubscribed),
            ErrorCodeProto::MaxNumberOfCanistersReached => {
                Ok(ErrorCode::MaxNumberOfCanistersReached)
            }
            ErrorCodeProto::CanisterQueueFull => Ok(ErrorCode::CanisterQueueFull),
            ErrorCodeProto::IngressMessageTimeout => Ok(ErrorCode::IngressMessageTimeout),
            ErrorCodeProto::CanisterQueueNotEmpty => Ok(ErrorCode::CanisterQueueNotEmpty),
            ErrorCodeProto::IngressHistoryFull => Ok(ErrorCode::IngressHistoryFull),
            ErrorCodeProto::CanisterIdAlreadyExists => Ok(ErrorCode::CanisterIdAlreadyExists),
            ErrorCodeProto::StopCanisterRequestTimeout => Ok(ErrorCode::StopCanisterRequestTimeout),
            ErrorCodeProto::CanisterOutOfCycles => Ok(ErrorCode::CanisterOutOfCycles),
            ErrorCodeProto::CertifiedStateUnavailable => Ok(ErrorCode::CertifiedStateUnavailable),
            ErrorCodeProto::CanisterInstallCodeRateLimited => {
                Ok(ErrorCode::CanisterInstallCodeRateLimited)
            }
            ErrorCodeProto::CanisterHeapDeltaRateLimited => {
                Ok(ErrorCode::CanisterHeapDeltaRateLimited)
            }
            ErrorCodeProto::CanisterNotFound => Ok(ErrorCode::CanisterNotFound),
            ErrorCodeProto::CanisterSnapshotNotFound => Ok(ErrorCode::CanisterSnapshotNotFound),
            ErrorCodeProto::InsufficientMemoryAllocation => {
                Ok(ErrorCode::InsufficientMemoryAllocation)
            }
            ErrorCodeProto::InsufficientCyclesForCreateCanister => {
                Ok(ErrorCode::InsufficientCyclesForCreateCanister)
            }
            ErrorCodeProto::SubnetNotFound => Ok(ErrorCode::SubnetNotFound),
            ErrorCodeProto::CanisterNotHostedBySubnet => Ok(ErrorCode::CanisterNotHostedBySubnet),
            ErrorCodeProto::CanisterRejectedMessage => Ok(ErrorCode::CanisterRejectedMessage),
            ErrorCodeProto::UnknownManagementMessage => Ok(ErrorCode::UnknownManagementMessage),
            ErrorCodeProto::InvalidManagementPayload => Ok(ErrorCode::InvalidManagementPayload),
            ErrorCodeProto::CanisterTrapped => Ok(ErrorCode::CanisterTrapped),
            ErrorCodeProto::CanisterCalledTrap => Ok(ErrorCode::CanisterCalledTrap),
            ErrorCodeProto::CanisterContractViolation => Ok(ErrorCode::CanisterContractViolation),
            ErrorCodeProto::CanisterInvalidWasm => Ok(ErrorCode::CanisterInvalidWasm),
            ErrorCodeProto::CanisterDidNotReply => Ok(ErrorCode::CanisterDidNotReply),
            ErrorCodeProto::CanisterOutOfMemory => Ok(ErrorCode::CanisterOutOfMemory),
            ErrorCodeProto::CanisterStopped => Ok(ErrorCode::CanisterStopped),
            ErrorCodeProto::CanisterStopping => Ok(ErrorCode::CanisterStopping),
            ErrorCodeProto::CanisterNotStopped => Ok(ErrorCode::CanisterNotStopped),
            ErrorCodeProto::CanisterStoppingCancelled => Ok(ErrorCode::CanisterStoppingCancelled),
            ErrorCodeProto::CanisterInvalidController => Ok(ErrorCode::CanisterInvalidController),
            ErrorCodeProto::CanisterFunctionNotFound => Ok(ErrorCode::CanisterFunctionNotFound),
            ErrorCodeProto::CanisterNonEmpty => Ok(ErrorCode::CanisterNonEmpty),
            ErrorCodeProto::QueryCallGraphLoopDetected => Ok(ErrorCode::QueryCallGraphLoopDetected),
            ErrorCodeProto::InsufficientCyclesInCall => Ok(ErrorCode::InsufficientCyclesInCall),
            ErrorCodeProto::CanisterWasmEngineError => Ok(ErrorCode::CanisterWasmEngineError),
            ErrorCodeProto::CanisterInstructionLimitExceeded => {
                Ok(ErrorCode::CanisterInstructionLimitExceeded)
            }
            ErrorCodeProto::CanisterMemoryAccessLimitExceeded => {
                Ok(ErrorCode::CanisterMemoryAccessLimitExceeded)
            }
            ErrorCodeProto::QueryCallGraphTooDeep => Ok(ErrorCode::QueryCallGraphTooDeep),
            ErrorCodeProto::QueryCallGraphTotalInstructionLimitExceeded => {
                Ok(ErrorCode::QueryCallGraphTotalInstructionLimitExceeded)
            }
            ErrorCodeProto::CompositeQueryCalledInReplicatedMode => {
                Ok(ErrorCode::CompositeQueryCalledInReplicatedMode)
            }
            ErrorCodeProto::QueryTimeLimitExceeded => Ok(ErrorCode::QueryTimeLimitExceeded),
            ErrorCodeProto::QueryCallGraphInternal => Ok(ErrorCode::QueryCallGraphInternal),
            ErrorCodeProto::InsufficientCyclesInComputeAllocation => {
                Ok(ErrorCode::InsufficientCyclesInComputeAllocation)
            }
            ErrorCodeProto::InsufficientCyclesInMemoryAllocation => {
                Ok(ErrorCode::InsufficientCyclesInMemoryAllocation)
            }
            ErrorCodeProto::InsufficientCyclesInMemoryGrow => {
                Ok(ErrorCode::InsufficientCyclesInMemoryGrow)
            }
            ErrorCodeProto::ReservedCyclesLimitExceededInMemoryAllocation => {
                Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation)
            }
            ErrorCodeProto::ReservedCyclesLimitExceededInMemoryGrow => {
                Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryGrow)
            }
            ErrorCodeProto::InsufficientCyclesInMessageMemoryGrow => {
                Ok(ErrorCode::InsufficientCyclesInMessageMemoryGrow)
            }
            ErrorCodeProto::CanisterMethodNotFound => Ok(ErrorCode::CanisterMethodNotFound),
            ErrorCodeProto::CanisterWasmModuleNotFound => Ok(ErrorCode::CanisterWasmModuleNotFound),
            ErrorCodeProto::CanisterAlreadyInstalled => Ok(ErrorCode::CanisterAlreadyInstalled),
            ErrorCodeProto::CanisterWasmMemoryLimitExceeded => {
                Ok(ErrorCode::CanisterWasmMemoryLimitExceeded)
            }
            ErrorCodeProto::ReservedCyclesLimitIsTooLow => {
                Ok(ErrorCode::ReservedCyclesLimitIsTooLow)
            }
        }
    }
}

impl From<ErrorCode> for ErrorCodeProto {
    fn from(item: ErrorCode) -> Self {
        match item {
            ErrorCode::SubnetOversubscribed => ErrorCodeProto::SubnetOversubscribed,
            ErrorCode::MaxNumberOfCanistersReached => ErrorCodeProto::MaxNumberOfCanistersReached,
            ErrorCode::CanisterQueueFull => ErrorCodeProto::CanisterQueueFull,
            ErrorCode::IngressMessageTimeout => ErrorCodeProto::IngressMessageTimeout,
            ErrorCode::CanisterQueueNotEmpty => ErrorCodeProto::CanisterQueueNotEmpty,
            ErrorCode::IngressHistoryFull => ErrorCodeProto::IngressHistoryFull,
            ErrorCode::CanisterIdAlreadyExists => ErrorCodeProto::CanisterIdAlreadyExists,
            ErrorCode::StopCanisterRequestTimeout => ErrorCodeProto::StopCanisterRequestTimeout,
            ErrorCode::CanisterOutOfCycles => ErrorCodeProto::CanisterOutOfCycles,
            ErrorCode::CertifiedStateUnavailable => ErrorCodeProto::CertifiedStateUnavailable,
            ErrorCode::CanisterInstallCodeRateLimited => {
                ErrorCodeProto::CanisterInstallCodeRateLimited
            }
            ErrorCode::CanisterHeapDeltaRateLimited => ErrorCodeProto::CanisterHeapDeltaRateLimited,
            ErrorCode::CanisterNotFound => ErrorCodeProto::CanisterNotFound,
            ErrorCode::CanisterSnapshotNotFound => ErrorCodeProto::CanisterSnapshotNotFound,
            ErrorCode::InsufficientMemoryAllocation => ErrorCodeProto::InsufficientMemoryAllocation,
            ErrorCode::InsufficientCyclesForCreateCanister => {
                ErrorCodeProto::InsufficientCyclesForCreateCanister
            }
            ErrorCode::SubnetNotFound => ErrorCodeProto::SubnetNotFound,
            ErrorCode::CanisterNotHostedBySubnet => ErrorCodeProto::CanisterNotHostedBySubnet,
            ErrorCode::CanisterRejectedMessage => ErrorCodeProto::CanisterRejectedMessage,
            ErrorCode::UnknownManagementMessage => ErrorCodeProto::UnknownManagementMessage,
            ErrorCode::InvalidManagementPayload => ErrorCodeProto::InvalidManagementPayload,
            ErrorCode::CanisterTrapped => ErrorCodeProto::CanisterTrapped,
            ErrorCode::CanisterCalledTrap => ErrorCodeProto::CanisterCalledTrap,
            ErrorCode::CanisterContractViolation => ErrorCodeProto::CanisterContractViolation,
            ErrorCode::CanisterInvalidWasm => ErrorCodeProto::CanisterInvalidWasm,
            ErrorCode::CanisterDidNotReply => ErrorCodeProto::CanisterDidNotReply,
            ErrorCode::CanisterOutOfMemory => ErrorCodeProto::CanisterOutOfMemory,
            ErrorCode::CanisterStopped => ErrorCodeProto::CanisterStopped,
            ErrorCode::CanisterStopping => ErrorCodeProto::CanisterStopping,
            ErrorCode::CanisterNotStopped => ErrorCodeProto::CanisterNotStopped,
            ErrorCode::CanisterStoppingCancelled => ErrorCodeProto::CanisterStoppingCancelled,
            ErrorCode::CanisterInvalidController => ErrorCodeProto::CanisterInvalidController,
            ErrorCode::CanisterFunctionNotFound => ErrorCodeProto::CanisterFunctionNotFound,
            ErrorCode::CanisterNonEmpty => ErrorCodeProto::CanisterNonEmpty,
            ErrorCode::QueryCallGraphLoopDetected => ErrorCodeProto::QueryCallGraphLoopDetected,
            ErrorCode::InsufficientCyclesInCall => ErrorCodeProto::InsufficientCyclesInCall,
            ErrorCode::CanisterWasmEngineError => ErrorCodeProto::CanisterWasmEngineError,
            ErrorCode::CanisterInstructionLimitExceeded => {
                ErrorCodeProto::CanisterInstructionLimitExceeded
            }
            ErrorCode::CanisterMemoryAccessLimitExceeded => {
                ErrorCodeProto::CanisterMemoryAccessLimitExceeded
            }
            ErrorCode::QueryCallGraphTooDeep => ErrorCodeProto::QueryCallGraphTooDeep,
            ErrorCode::QueryCallGraphTotalInstructionLimitExceeded => {
                ErrorCodeProto::QueryCallGraphTotalInstructionLimitExceeded
            }
            ErrorCode::CompositeQueryCalledInReplicatedMode => {
                ErrorCodeProto::CompositeQueryCalledInReplicatedMode
            }
            ErrorCode::QueryTimeLimitExceeded => ErrorCodeProto::QueryTimeLimitExceeded,
            ErrorCode::QueryCallGraphInternal => ErrorCodeProto::QueryCallGraphInternal,
            ErrorCode::InsufficientCyclesInComputeAllocation => {
                ErrorCodeProto::InsufficientCyclesInComputeAllocation
            }
            ErrorCode::InsufficientCyclesInMemoryAllocation => {
                ErrorCodeProto::InsufficientCyclesInMemoryAllocation
            }
            ErrorCode::InsufficientCyclesInMemoryGrow => {
                ErrorCodeProto::InsufficientCyclesInMemoryGrow
            }
            ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation => {
                ErrorCodeProto::ReservedCyclesLimitExceededInMemoryAllocation
            }
            ErrorCode::ReservedCyclesLimitExceededInMemoryGrow => {
                ErrorCodeProto::ReservedCyclesLimitExceededInMemoryGrow
            }
            ErrorCode::InsufficientCyclesInMessageMemoryGrow => {
                ErrorCodeProto::InsufficientCyclesInMessageMemoryGrow
            }
            ErrorCode::CanisterMethodNotFound => ErrorCodeProto::CanisterMethodNotFound,
            ErrorCode::CanisterWasmModuleNotFound => ErrorCodeProto::CanisterWasmModuleNotFound,
            ErrorCode::CanisterAlreadyInstalled => ErrorCodeProto::CanisterAlreadyInstalled,
            ErrorCode::CanisterWasmMemoryLimitExceeded => {
                ErrorCodeProto::CanisterWasmMemoryLimitExceeded
            }
            ErrorCode::ReservedCyclesLimitIsTooLow => ErrorCodeProto::ReservedCyclesLimitIsTooLow,
        }
    }
}

/// Maximum allowed length for UserError description.
const MAX_USER_ERROR_DESCRIPTION_LEN_BYTES: usize = 8 * 1024;

/// The error that is sent back to users of IC if something goes
/// wrong. It's designed to be copyable and serializable so that we
/// can persist it in ingress history.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct UserError {
    code: ErrorCode,
    description: String,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // E.g. "IC0301"
        write!(f, "IC{:04}", *self as i32)
    }
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // E.g. "IC0301: Canister 42 not found"
        write!(f, "{}: {}", self.code, self.description)
    }
}

impl UserError {
    pub fn new<S: ToString>(code: ErrorCode, description: S) -> Self {
        Self {
            code,
            description: description
                .to_string()
                .ellipsize(MAX_USER_ERROR_DESCRIPTION_LEN_BYTES, 50),
        }
    }

    /// Constructs a `UserError` retaining the original description without truncation.
    /// This ensures backward compatibility with ingress history.
    ///
    /// # Safety
    ///
    /// This constructor is specifically intended for state-loading. Avoid usage in other contexts.
    pub fn from_proto<S: ToString>(code: ErrorCode, description: S) -> Self {
        Self {
            code,
            description: description.to_string(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn reject_code(&self) -> RejectCode {
        self.code().into()
    }

    pub fn is_system_error(&self) -> bool {
        match self.code {
            ErrorCode::CanisterWasmEngineError | ErrorCode::QueryCallGraphInternal => true,
            ErrorCode::SubnetOversubscribed
            | ErrorCode::MaxNumberOfCanistersReached
            | ErrorCode::CanisterQueueFull
            | ErrorCode::IngressMessageTimeout
            | ErrorCode::CanisterQueueNotEmpty
            | ErrorCode::IngressHistoryFull
            | ErrorCode::CanisterIdAlreadyExists
            | ErrorCode::StopCanisterRequestTimeout
            | ErrorCode::CanisterOutOfCycles
            | ErrorCode::CertifiedStateUnavailable
            | ErrorCode::CanisterInstallCodeRateLimited
            | ErrorCode::CanisterNotFound
            | ErrorCode::CanisterMethodNotFound
            | ErrorCode::CanisterAlreadyInstalled
            | ErrorCode::CanisterWasmModuleNotFound
            | ErrorCode::InsufficientMemoryAllocation
            | ErrorCode::InsufficientCyclesForCreateCanister
            | ErrorCode::SubnetNotFound
            | ErrorCode::CanisterNotHostedBySubnet
            | ErrorCode::CanisterRejectedMessage
            | ErrorCode::UnknownManagementMessage
            | ErrorCode::InvalidManagementPayload
            | ErrorCode::CanisterTrapped
            | ErrorCode::CanisterCalledTrap
            | ErrorCode::CanisterContractViolation
            | ErrorCode::CanisterInvalidWasm
            | ErrorCode::CanisterDidNotReply
            | ErrorCode::CanisterOutOfMemory
            | ErrorCode::CanisterStopped
            | ErrorCode::CanisterStopping
            | ErrorCode::CanisterNotStopped
            | ErrorCode::CanisterStoppingCancelled
            | ErrorCode::CanisterInvalidController
            | ErrorCode::CanisterFunctionNotFound
            | ErrorCode::CanisterNonEmpty
            | ErrorCode::QueryCallGraphLoopDetected
            | ErrorCode::InsufficientCyclesInCall
            | ErrorCode::CanisterInstructionLimitExceeded
            | ErrorCode::CanisterMemoryAccessLimitExceeded
            | ErrorCode::QueryCallGraphTooDeep
            | ErrorCode::QueryCallGraphTotalInstructionLimitExceeded
            | ErrorCode::CompositeQueryCalledInReplicatedMode
            | ErrorCode::QueryTimeLimitExceeded
            | ErrorCode::InsufficientCyclesInComputeAllocation
            | ErrorCode::InsufficientCyclesInMemoryAllocation
            | ErrorCode::InsufficientCyclesInMemoryGrow
            | ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation
            | ErrorCode::ReservedCyclesLimitExceededInMemoryGrow
            | ErrorCode::ReservedCyclesLimitIsTooLow
            | ErrorCode::InsufficientCyclesInMessageMemoryGrow
            | ErrorCode::CanisterSnapshotNotFound
            | ErrorCode::CanisterHeapDeltaRateLimited
            | ErrorCode::CanisterWasmMemoryLimitExceeded => false,
        }
    }

    pub fn count_bytes(&self) -> usize {
        std::mem::size_of_val(self) + self.description.len()
    }

    /// Panics if the error doesn't have the expected code and description.
    /// Useful for tests to avoid matching exact error messages.
    pub fn assert_contains(&self, code: ErrorCode, description: &str) {
        assert_eq!(self.code, code);
        assert!(
            self.description.contains(description),
            "Error matching description \"{}\" with \"{}\"",
            self.description,
            description
        );
    }
}

impl std::error::Error for UserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_user_error_display() {
        assert_eq!(
            format!(
                "{}",
                UserError::new(
                    ErrorCode::CanisterOutOfCycles,
                    "Canister 42 ran out of cycles"
                )
            ),
            "IC0207: Canister 42 ran out of cycles"
        );
    }

    #[test]
    fn error_code_round_trip() {
        for initial in ErrorCode::iter() {
            let encoded = ErrorCodeProto::from(initial);
            let round_trip = ErrorCode::try_from(encoded).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    #[rustfmt::skip]
    fn compatibility_for_error_code() {
        // If this fails, you are making a potentially incompatible change to `ErrorCode`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            ErrorCode::iter().map(|x| x as i32).collect::<Vec<i32>>(),
            [
                101, 102,
                201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
                301, 305,
                402, 403, 404, 405, 406, 407, 408,
                502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514,
                517, 520, 521, 522, 524, 525, 526, 527, 528, 529, 530, 531, 532,
                533, 534, 535, 536, 537, 538, 539, 540,
            ]
        );
    }

    #[test]
    fn reject_code_round_trip() {
        for initial in RejectCode::iter() {
            let encoded = RejectCodeProto::from(initial);
            let round_trip = RejectCode::try_from(encoded).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn compatibility_for_reject_code() {
        // If this fails, you are making a potentially incompatible change to `RejectCode`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            RejectCode::iter().map(|x| x as i32).collect::<Vec<i32>>(),
            [1, 2, 3, 4, 5]
        );
    }
}
