#![doc = include_str!("../README.md")]

use std::error::Error;
use std::fmt::Display;

/// Classifies why an API request or inter-canister call in the IC is rejected.
///
/// # Note
///
/// Zero (0) is not a valid reject code.
/// Converting 0 into this enum will return an error.
///
/// See [Reject codes](https://internetcomputer.org/docs/current/references/ic-interface-spec/#reject-codes) for more details.
#[repr(u32)]
#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RejectCode {
    /// Fatal system error, retry unlikely to be useful.
    SysFatal = 1,
    /// Transient system error, retry might be possible.
    SysTransient = 2,
    /// Invalid destination (e.g. canister/account does not exist).
    DestinationInvalid = 3,
    /// Explicit reject by the canister.
    CanisterReject = 4,
    /// Canister error (e.g., trap, no response).
    CanisterError = 5,
    /// Response unknown; system stopped waiting for it (e.g., timed out, or system under high load).
    SysUnknown = 6,

    /// Unrecognized reject code.
    ///
    /// # Note
    ///
    /// This variant is not part of the IC interface spec, and is used to represent
    /// reject codes that are not recognized by the library.
    ///
    /// This variant is needed just in case the IC introduces new reject codes in the future.
    /// If that happens, a Canister using existing library versions will still be able to convert
    /// the new reject codes to this variant without panicking.
    Unrecognized(u32),
}

impl Display for RejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectCode::SysFatal => write!(f, "SysFatal(1)"),
            RejectCode::SysTransient => write!(f, "SysTransient(2)"),
            RejectCode::DestinationInvalid => write!(f, "DestinationInvalid(3)"),
            RejectCode::CanisterReject => write!(f, "CanisterReject(4)"),
            RejectCode::CanisterError => write!(f, "CanisterError(5)"),
            RejectCode::SysUnknown => write!(f, "SysUnknown(6)"),
            RejectCode::Unrecognized(code) => write!(f, "Unrecognized({})", code),
        }
    }
}

/// Error type for [`RejectCode`] conversion.
///
/// The only case where this error can occur is when trying to convert a 0 to a [`RejectCode`].
#[derive(Clone, Copy, Debug)]
pub struct ZeroIsInvalidRejectCode;

impl Display for ZeroIsInvalidRejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "zero is invalid reject code")
    }
}

impl Error for ZeroIsInvalidRejectCode {}

impl TryFrom<u32> for RejectCode {
    type Error = ZeroIsInvalidRejectCode;

    fn try_from(code: u32) -> Result<Self, Self::Error> {
        match code {
            0 => Err(ZeroIsInvalidRejectCode),
            1 => Ok(RejectCode::SysFatal),
            2 => Ok(RejectCode::SysTransient),
            3 => Ok(RejectCode::DestinationInvalid),
            4 => Ok(RejectCode::CanisterReject),
            5 => Ok(RejectCode::CanisterError),
            6 => Ok(RejectCode::SysUnknown),
            _ => Ok(RejectCode::Unrecognized(code)),
        }
    }
}

impl From<RejectCode> for u32 {
    fn from(code: RejectCode) -> u32 {
        match code {
            RejectCode::SysFatal => 1,
            RejectCode::SysTransient => 2,
            RejectCode::DestinationInvalid => 3,
            RejectCode::CanisterReject => 4,
            RejectCode::CanisterError => 5,
            RejectCode::SysUnknown => 6,
            RejectCode::Unrecognized(code) => code,
        }
    }
}

impl PartialEq<u32> for RejectCode {
    fn eq(&self, other: &u32) -> bool {
        let self_as_u32: u32 = (*self).into();
        self_as_u32 == *other
    }
}
