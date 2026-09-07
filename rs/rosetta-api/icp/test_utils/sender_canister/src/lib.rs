use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct SendArg {
    pub to: Principal,
    pub method: String,
    pub arg: Vec<u8>,
    pub payment: u128,
}

/// The reject code returned by `send`.
///
/// The variants and their ordering define the `variant` this canister exposes over
/// Candid, so the numbering must stay in sync with the reject codes of the
/// [IC interface specification](https://docs.internetcomputer.org/references/ic-interface-spec/https-interface/#reject-codes).
#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    SysUnknown,
    /// The reject code reported by the system is not one the interface
    /// specification defines.
    Unknown,
}

impl RejectionCode {
    /// Translates the raw u32 reject code returned by `ic_cdk::call::CallRejected`
    /// into the variant the test canister exposes over Candid.
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::NoError,
            1 => Self::SysFatal,
            2 => Self::SysTransient,
            3 => Self::DestinationInvalid,
            4 => Self::CanisterReject,
            5 => Self::CanisterError,
            6 => Self::SysUnknown,
            _ => Self::Unknown,
        }
    }
}

pub type SendError = (RejectionCode, String);
pub type SendResult = Result<Vec<u8>, SendError>;
