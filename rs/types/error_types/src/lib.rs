//! A crate that groups user-facing and internal error types and codes produced
//! by the Internet Computer.
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
/// See <https://sdk.dfinity.org/docs/interface-spec/index.html#reject-codes>
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
            // Invalid destination errors.
            CanisterNotFound => DestinationInvalid,
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
    // 3xx -- `RejectCode::DestinationInvalid`
    CanisterNotFound = 301,
    // 302 (previously `CanisterMethodNotFound`)
    // 303 (previously `CanisterAlreadyInstalled`)
    // 304 (previously `CanisterWasmModuleNotFound`)
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
    // 501 (previously `CanisterOutOfCycles`)
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
    // 515 (previously `CertifiedStateUnavailable`)
    // 516 (previously `CanisterRejectedMessage`)
    QueryCallGraphLoopDetected = 517,
    // 518 (previously `UnknownManagementMessage`)
    // 519 (previously `InvalidManagementPayload`)
    InsufficientCyclesInCall = 520,
    CanisterWasmEngineError = 521,
    CanisterInstructionLimitExceeded = 522,
    // 523 (previously `CanisterInstallCodeRateLimited`)
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
            // 3xx -- `RejectCode::DestinationInvalid`
            301 => Ok(ErrorCode::CanisterNotFound),
            // 302 (previously `CanisterMethodNotFound`)
            // 303 (previously `CanisterAlreadyInstalled`)
            // 304 (previously `CanisterWasmModuleNotFound`)
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
            // 501 (previously `CanisterOutOfCycles`)
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
            // 515 (previously `CertifiedStateUnavailable`)
            // 516 (previously `CanisterRejectedMessage`)
            517 => Ok(ErrorCode::QueryCallGraphLoopDetected),
            // 518 (previously `UnknownManagementMessage`)
            // 519 (previously `InvalidManagementPayload`)
            520 => Ok(ErrorCode::InsufficientCyclesInCall),
            521 => Ok(ErrorCode::CanisterWasmEngineError),
            522 => Ok(ErrorCode::CanisterInstructionLimitExceeded),
            // 523 (previously `CanisterInstallCodeRateLimited`)
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
            | ErrorCode::InsufficientCyclesInMessageMemoryGrow => false,
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
    fn can_decode_error_code_from_u64() {
        for code in ErrorCode::iter() {
            let int_code = code as u64;
            match ErrorCode::try_from(int_code) {
                Ok(decoded_code) => assert_eq!(code, decoded_code),
                Err(err) => panic!("Could not decode {} to an ErrorCode: {:?}.", int_code, err),
            }
        }
    }
}
