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
/// Mirrors the variants exposed by the deprecated
/// `ic_cdk::api::call::RejectionCode` so the public Candid interface of this
/// test canister stays stable after the ic-cdk 0.18 upgrade.
#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
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
            _ => Self::Unknown,
        }
    }
}

pub type SendError = (RejectionCode, String);
pub type SendResult = Result<Vec<u8>, SendError>;
