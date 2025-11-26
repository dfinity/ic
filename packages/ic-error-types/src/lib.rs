//! A crate that groups user-facing and internal error types and codes produced
//! by the Internet Computer.

use ic_heap_bytes::DeterministicHeapBytes;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};
use str_traits::StrEllipsize;
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
    SysUnknown = 6,
}

impl std::fmt::Display for RejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl RejectCode {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectCode::SysFatal => "SYS_FATAL",
            RejectCode::SysTransient => "SYS_TRANSIENT",
            RejectCode::DestinationInvalid => "DESTINATION_INVALID",
            RejectCode::CanisterReject => "CANISTER_REJECT",
            RejectCode::CanisterError => "CANISTER_ERROR",
            RejectCode::SysUnknown => "SYS_UNKNOWN",
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
            6 => Ok(RejectCode::SysUnknown),
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
            CanisterSnapshotImmutable => CanisterReject,
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
            // Response unknown (best-effort calls only).
            DeadlineExpired => SysUnknown,
            ResponseDropped => SysUnknown,
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
    Copy,
    Clone,
    Eq,
    DeterministicHeapBytes,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    Deserialize,
    EnumIter,
    Serialize,
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
    CanisterSnapshotImmutable = 409,
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
    // 6xx -- `RejectCode::SysUnknown`
    DeadlineExpired = 601,
    ResponseDropped = 602,
}

/// Maximum allowed length for UserError description.
const MAX_USER_ERROR_DESCRIPTION_LEN_BYTES: usize = 8 * 1024;

/// The error that is sent back to users of IC if something goes
/// wrong. It's designed to be copyable and serializable so that we
/// can persist it in ingress history.
#[derive(
    Clone,
    Eq,
    DeterministicHeapBytes,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    Deserialize,
    Serialize,
)]
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
            | ErrorCode::CanisterSnapshotImmutable
            | ErrorCode::CanisterHeapDeltaRateLimited
            | ErrorCode::CanisterWasmMemoryLimitExceeded
            | ErrorCode::DeadlineExpired
            | ErrorCode::ResponseDropped => false,
        }
    }

    pub fn count_bytes(&self) -> usize {
        std::mem::size_of_val(self) + self.description.len()
    }

    /// Panics if the error doesn't have the expected code and description.
    /// Useful for tests to avoid matching exact error messages.
    pub fn assert_contains(&self, code: ErrorCode, description: &str) {
        assert_eq!(
            self.code, code,
            "Failed to match actual error \"{self:?}\" with expected \"{code}, {description}\""
        );
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
                402, 403, 404, 405, 406, 407, 408, 409,
                502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514,
                517, 520, 521, 522, 524, 525, 526, 527, 528, 529, 530, 531, 532,
                533, 534, 535, 536, 537, 538, 539, 540,
                601, 602,
            ]
        );
    }

    #[test]
    fn compatibility_for_reject_code() {
        // If this fails, you are making a potentially incompatible change to `RejectCode`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            RejectCode::iter().map(|x| x as i32).collect::<Vec<i32>>(),
            [1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn reject_code_from_error_code() {
        // If this fails, you are making a change to `RejectCode` which violates the property
        // that the reject code can be derived from the leading digit of an error code.
        for error_code in ErrorCode::iter() {
            let reject_code: RejectCode = error_code.into();
            let error_code_as_u64: u64 = error_code as u64;
            assert!((100..700).contains(&error_code_as_u64));
            let derived_reject_code: RejectCode = (error_code_as_u64 / 100).try_into().unwrap();
            assert_eq!(reject_code, derived_reject_code);
        }
    }
}

// ========================================================================= //

// Copy these internal traits, from rs/utils/src/str.rs, but keep them private.
// include!() did not work with bazel.
mod str_traits {
    /// Trait, implemented for `str`, for truncating string slices at character
    /// boundaries.
    pub trait StrTruncate {
        /// Returns a prefix of at most `max_len` bytes, cut at a character boundary.
        ///
        /// Calling this with a `max_len` greater than the slice length will return
        /// the whole slice.
        fn safe_truncate(&self, max_len: usize) -> &str;

        /// Returns a suffix of at most `max_len` bytes, cut at a character boundary.
        ///
        /// Calling this with a `max_len` greater than the slice length will return
        /// the whole slice.
        fn safe_truncate_right(&self, max_len: usize) -> &str;
    }

    impl StrTruncate for str {
        fn safe_truncate(&self, max_len: usize) -> &str {
            if self.len() > max_len {
                let mut len = max_len;
                while len > 0 && !self.is_char_boundary(len) {
                    len -= 1;
                }
                &self[..len]
            } else {
                self
            }
        }

        fn safe_truncate_right(&self, max_len: usize) -> &str {
            if self.len() > max_len {
                let mut left = self.len() - max_len;
                while left < self.len() && !self.is_char_boundary(left) {
                    left += 1;
                }
                &self[left..]
            } else {
                self
            }
        }
    }
    /// Trait for strings that can be represented in an ellipsis format.
    pub trait StrEllipsize {
        /// Ellipsize the string with a max length and prefix percentage `[0, 100]`.
        ///
        /// Returns the original string if it's shorter or equal than the max length;
        /// returns an empty string if the max length is shorter than the ellipsis.
        fn ellipsize(&self, max_len: usize, prefix_percentage: usize) -> String;
    }

    impl StrEllipsize for str {
        fn ellipsize(&self, max_len: usize, prefix_percentage: usize) -> String {
            if self.len() <= max_len {
                return self.to_string();
            }

            const ELLIPSIS: &str = "...";
            if max_len < ELLIPSIS.len() {
                return "".to_string();
            }

            // Deduct the ellipsis length to get the available space for prefix and suffix combined.
            let budget = max_len.saturating_sub(ELLIPSIS.len());

            // Calculate the length of the prefix based on the given percentage.
            let prefix_len = (max_len * prefix_percentage.clamp(0, 100) / 100).min(budget);
            let suffix_len = budget - prefix_len;

            // Construct the ellipsized string.
            let mut ellipsized = String::with_capacity(max_len);
            ellipsized.push_str(self.safe_truncate(prefix_len));
            ellipsized.push_str(ELLIPSIS);
            ellipsized.push_str(self.safe_truncate_right(suffix_len));
            ellipsized
        }
    }
}
