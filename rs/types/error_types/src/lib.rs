//! A crate that groups user-facing and internal error types and codes produced
//! by the Internet Computer.
use ic_protobuf::{proxy::ProxyDecodeError, state::ingress::v1::ErrorCode as ErrorCodeProto};
use ic_utils::str::StrEllipsize;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug)]
pub enum TryFromError {
    ValueOutOfRange(u64),
}

/// Reject codes are integers that canisters should pass to msg.reject
/// system API calls. These errors are designed for programmatic error
/// handling, not for end-users. They are also used for classification
/// of user-facing errors.
///
/// See <https://internetcomputer.org/docs/current/references/ic-interface-spec#reject-codes>
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter)]
pub enum RejectCode {
    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,
}

impl ToString for RejectCode {
    fn to_string(&self) -> String {
        self.to_str().to_owned()
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
            DeprecatedCanisterMethodNotFound => DestinationInvalid,
            DeprecatedCanisterAlreadyInstalled => DestinationInvalid,
            DeprecatedCanisterWasmModuleNotFound => DestinationInvalid,
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
            DeprecatedCanisterOutOfCycles => CanisterError,
            CanisterInvalidController => CanisterError,
            CanisterFunctionNotFound => CanisterError,
            CanisterNonEmpty => CanisterError,
            DeprecatedCertifiedStateUnavailable => CanisterError,
            DeprecatedCanisterRejectedMessage => CanisterError,
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
            DeprecatedUnknownManagementMessage => CanisterError,
            DeprecatedInvalidManagementPayload => CanisterError,
            InsufficientCyclesInCall => CanisterError,
            CanisterWasmEngineError => CanisterError,
            CanisterInstructionLimitExceeded => CanisterError,
            DeprecatedCanisterInstallCodeRateLimited => CanisterError,
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
            InsufficientCyclesInMessageMemoryGrow => CanisterError,
            CanisterMethodNotFound => CanisterError,
            CanisterWasmModuleNotFound => CanisterError,
            CanisterAlreadyInstalled => CanisterError,
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
    PartialOrd, Ord, Clone, Copy, Debug, PartialEq, EnumIter, Eq, Hash, Serialize, Deserialize,
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
    DeprecatedCanisterMethodNotFound = 302,
    DeprecatedCanisterAlreadyInstalled = 303,
    DeprecatedCanisterWasmModuleNotFound = 304,
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
    DeprecatedCanisterOutOfCycles = 501,
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
    DeprecatedCertifiedStateUnavailable = 515,
    DeprecatedCanisterRejectedMessage = 516,
    QueryCallGraphLoopDetected = 517,
    DeprecatedUnknownManagementMessage = 518,
    DeprecatedInvalidManagementPayload = 519,
    InsufficientCyclesInCall = 520,
    CanisterWasmEngineError = 521,
    CanisterInstructionLimitExceeded = 522,
    DeprecatedCanisterInstallCodeRateLimited = 523,
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
}

impl TryFrom<u64> for ErrorCode {
    type Error = TryFromError;
    fn try_from(err: u64) -> Result<ErrorCode, Self::Error> {
        match err {
            // 1xx -- `RejectCode::SysFatal`
            101 => Ok(ErrorCode::SubnetOversubscribed),
            102 => Ok(ErrorCode::MaxNumberOfCanistersReached),
            // 2xx -- `RejectCode::SysTransient`
            201 => Ok(ErrorCode::CanisterQueueFull),
            202 => Ok(ErrorCode::IngressMessageTimeout),
            203 => Ok(ErrorCode::CanisterQueueNotEmpty),
            204 => Ok(ErrorCode::IngressHistoryFull),
            205 => Ok(ErrorCode::CanisterIdAlreadyExists),
            206 => Ok(ErrorCode::StopCanisterRequestTimeout),
            207 => Ok(ErrorCode::CanisterOutOfCycles),
            208 => Ok(ErrorCode::CertifiedStateUnavailable),
            209 => Ok(ErrorCode::CanisterInstallCodeRateLimited),
            210 => Ok(ErrorCode::CanisterHeapDeltaRateLimited),
            // 3xx -- `RejectCode::DestinationInvalid`
            301 => Ok(ErrorCode::CanisterNotFound),
            // TODO: RUN-948: Backward compatibility
            302 => Ok(ErrorCode::DeprecatedCanisterMethodNotFound),
            303 => Ok(ErrorCode::DeprecatedCanisterAlreadyInstalled),
            304 => Ok(ErrorCode::DeprecatedCanisterWasmModuleNotFound),
            305 => Ok(ErrorCode::CanisterSnapshotNotFound),
            // 4xx -- `RejectCode::CanisterReject`
            // 401
            402 => Ok(ErrorCode::InsufficientMemoryAllocation),
            403 => Ok(ErrorCode::InsufficientCyclesForCreateCanister),
            404 => Ok(ErrorCode::SubnetNotFound),
            405 => Ok(ErrorCode::CanisterNotHostedBySubnet),
            406 => Ok(ErrorCode::CanisterRejectedMessage),
            407 => Ok(ErrorCode::UnknownManagementMessage),
            408 => Ok(ErrorCode::InvalidManagementPayload),
            // 5xx -- `RejectCode::CanisterError`
            501 => Ok(ErrorCode::DeprecatedCanisterOutOfCycles),
            502 => Ok(ErrorCode::CanisterTrapped),
            503 => Ok(ErrorCode::CanisterCalledTrap),
            504 => Ok(ErrorCode::CanisterContractViolation),
            505 => Ok(ErrorCode::CanisterInvalidWasm),
            506 => Ok(ErrorCode::CanisterDidNotReply),
            507 => Ok(ErrorCode::CanisterOutOfMemory),
            508 => Ok(ErrorCode::CanisterStopped),
            509 => Ok(ErrorCode::CanisterStopping),
            510 => Ok(ErrorCode::CanisterNotStopped),
            511 => Ok(ErrorCode::CanisterStoppingCancelled),
            512 => Ok(ErrorCode::CanisterInvalidController),
            513 => Ok(ErrorCode::CanisterFunctionNotFound),
            514 => Ok(ErrorCode::CanisterNonEmpty),
            // TODO: RUN-948: Backward compatibility
            515 => Ok(ErrorCode::DeprecatedCertifiedStateUnavailable),
            516 => Ok(ErrorCode::DeprecatedCanisterRejectedMessage),
            517 => Ok(ErrorCode::QueryCallGraphLoopDetected),
            518 => Ok(ErrorCode::DeprecatedUnknownManagementMessage),
            519 => Ok(ErrorCode::DeprecatedInvalidManagementPayload),
            520 => Ok(ErrorCode::InsufficientCyclesInCall),
            521 => Ok(ErrorCode::CanisterWasmEngineError),
            522 => Ok(ErrorCode::CanisterInstructionLimitExceeded),
            523 => Ok(ErrorCode::DeprecatedCanisterInstallCodeRateLimited),
            524 => Ok(ErrorCode::CanisterMemoryAccessLimitExceeded),
            525 => Ok(ErrorCode::QueryCallGraphTooDeep),
            526 => Ok(ErrorCode::QueryCallGraphTotalInstructionLimitExceeded),
            527 => Ok(ErrorCode::CompositeQueryCalledInReplicatedMode),
            528 => Ok(ErrorCode::QueryTimeLimitExceeded),
            529 => Ok(ErrorCode::QueryCallGraphInternal),
            530 => Ok(ErrorCode::InsufficientCyclesInComputeAllocation),
            531 => Ok(ErrorCode::InsufficientCyclesInMemoryAllocation),
            532 => Ok(ErrorCode::InsufficientCyclesInMemoryGrow),
            533 => Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation),
            534 => Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryGrow),
            535 => Ok(ErrorCode::InsufficientCyclesInMessageMemoryGrow),
            536 => Ok(ErrorCode::CanisterMethodNotFound),
            537 => Ok(ErrorCode::CanisterWasmModuleNotFound),
            538 => Ok(ErrorCode::CanisterAlreadyInstalled),
            _ => Err(TryFromError::ValueOutOfRange(err)),
        }
    }
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
            ErrorCodeProto::DeprecatedCanisterMethodNotFound => {
                Ok(ErrorCode::DeprecatedCanisterMethodNotFound)
            }
            ErrorCodeProto::DeprecatedCanisterAlreadyInstalled => {
                Ok(ErrorCode::DeprecatedCanisterAlreadyInstalled)
            }
            ErrorCodeProto::DeprecatedCanisterWasmModuleNotFound => {
                Ok(ErrorCode::DeprecatedCanisterWasmModuleNotFound)
            }
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
            ErrorCodeProto::DeprecatedCanisterOutOfCycles => {
                Ok(ErrorCode::DeprecatedCanisterOutOfCycles)
            }
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
            ErrorCodeProto::DeprecatedCertifiedStateUnavailable => {
                Ok(ErrorCode::DeprecatedCertifiedStateUnavailable)
            }
            ErrorCodeProto::DeprecatedCanisterRejectedMessage => {
                Ok(ErrorCode::DeprecatedCanisterRejectedMessage)
            }
            ErrorCodeProto::QueryCallGraphLoopDetected => Ok(ErrorCode::QueryCallGraphLoopDetected),
            ErrorCodeProto::DeprecatedUnknownManagementMessage => {
                Ok(ErrorCode::DeprecatedUnknownManagementMessage)
            }
            ErrorCodeProto::DeprecatedInvalidManagementPayload => {
                Ok(ErrorCode::DeprecatedInvalidManagementPayload)
            }
            ErrorCodeProto::InsufficientCyclesInCall => Ok(ErrorCode::InsufficientCyclesInCall),
            ErrorCodeProto::CanisterWasmEngineError => Ok(ErrorCode::CanisterWasmEngineError),
            ErrorCodeProto::CanisterInstructionLimitExceeded => {
                Ok(ErrorCode::CanisterInstructionLimitExceeded)
            }
            ErrorCodeProto::DeprecatedCanisterInstallCodeRateLimited => {
                Ok(ErrorCode::DeprecatedCanisterInstallCodeRateLimited)
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
            ErrorCode::DeprecatedCanisterMethodNotFound => {
                ErrorCodeProto::DeprecatedCanisterMethodNotFound
            }
            ErrorCode::DeprecatedCanisterAlreadyInstalled => {
                ErrorCodeProto::DeprecatedCanisterAlreadyInstalled
            }
            ErrorCode::DeprecatedCanisterWasmModuleNotFound => {
                ErrorCodeProto::DeprecatedCanisterWasmModuleNotFound
            }
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
            ErrorCode::DeprecatedCanisterOutOfCycles => {
                ErrorCodeProto::DeprecatedCanisterOutOfCycles
            }
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
            ErrorCode::DeprecatedCertifiedStateUnavailable => {
                ErrorCodeProto::DeprecatedCertifiedStateUnavailable
            }
            ErrorCode::DeprecatedCanisterRejectedMessage => {
                ErrorCodeProto::DeprecatedCanisterRejectedMessage
            }
            ErrorCode::QueryCallGraphLoopDetected => ErrorCodeProto::QueryCallGraphLoopDetected,
            ErrorCode::DeprecatedUnknownManagementMessage => {
                ErrorCodeProto::DeprecatedUnknownManagementMessage
            }
            ErrorCode::DeprecatedInvalidManagementPayload => {
                ErrorCodeProto::DeprecatedInvalidManagementPayload
            }
            ErrorCode::InsufficientCyclesInCall => ErrorCodeProto::InsufficientCyclesInCall,
            ErrorCode::CanisterWasmEngineError => ErrorCodeProto::CanisterWasmEngineError,
            ErrorCode::CanisterInstructionLimitExceeded => {
                ErrorCodeProto::CanisterInstructionLimitExceeded
            }
            ErrorCode::DeprecatedCanisterInstallCodeRateLimited => {
                ErrorCodeProto::DeprecatedCanisterInstallCodeRateLimited
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
        }
    }
}

/// Maximum allowed length for UserError description.
const MAX_USER_ERROR_DESCRIPTION_LEN_BYTES: usize = 8 * 1024;

/// The error that is sent back to users of IC if something goes
/// wrong. It's designed to be copyable and serializable so that we
/// can persist it in ingress history.
#[derive(PartialOrd, Ord, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
            | ErrorCode::InsufficientCyclesInMessageMemoryGrow
            | ErrorCode::CanisterSnapshotNotFound
            | ErrorCode::CanisterHeapDeltaRateLimited => false,
            // TODO: RUN-948: Backward compatibility
            ErrorCode::DeprecatedCanisterMethodNotFound
            | ErrorCode::DeprecatedCanisterAlreadyInstalled
            | ErrorCode::DeprecatedCanisterWasmModuleNotFound
            | ErrorCode::DeprecatedCanisterOutOfCycles
            | ErrorCode::DeprecatedCertifiedStateUnavailable
            | ErrorCode::DeprecatedCanisterRejectedMessage
            | ErrorCode::DeprecatedUnknownManagementMessage
            | ErrorCode::DeprecatedInvalidManagementPayload
            | ErrorCode::DeprecatedCanisterInstallCodeRateLimited => false,
        }
    }

    pub fn count_bytes(&self) -> usize {
        std::mem::size_of_val(self) + self.description.len()
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
}
