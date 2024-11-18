use candid::CandidType;
use ic_agent::export::Principal;
use ic_management_canister_types::{CanisterStatusType, DefiniteCanisterSettingsArgs};
pub use ic_utils::interfaces::management_canister::builders::InstallMode;
use serde::Deserialize;

#[allow(dead_code)] // Not all reject codes are used yet.
#[derive(Copy, Clone)]
pub enum RejectCode {
    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,
}

#[derive(CandidType, Deserialize)]
pub struct CreateCanisterResult {
    pub canister_id: Principal,
}

#[derive(candid::CandidType)]
pub struct CanisterIdRecord {
    pub canister_id: Principal,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct CanisterStatusResult {
    pub status: CanisterStatusType,
    pub module_hash: Option<Vec<u8>>,
    pub controller: candid::Principal,
    pub settings: DefiniteCanisterSettingsArgs,
    pub memory_size: candid::Nat,
    pub cycles: candid::Nat,
}
