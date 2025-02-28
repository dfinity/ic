// ========================================================================= //
// Types associated with the IC management canister that are not specified,
// but nevertheless useful for PocketIC.

use candid::{CandidType, Deserialize, Principal};

pub type CanisterId = Principal;
pub type SubnetId = Principal;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterIdRecord {
    pub canister_id: CanisterId,
}

// ========================================================================= //
// Missing from ic-management-canister-types

// canister logs

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct CanisterLogRecord {
    pub idx: u64,
    pub timestamp_nanos: u64,
    pub content: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct FetchCanisterLogsResult {
    pub canister_log_records: Vec<CanisterLogRecord>,
}
