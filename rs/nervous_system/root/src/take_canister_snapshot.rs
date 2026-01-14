use candid::CandidType;
use ic_base_types::PrincipalId;
use serde::Deserialize;

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotRequest {
    pub canister_id: PrincipalId,
    pub replace_snapshot: Option</* snapshot ID */ Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum TakeCanisterSnapshotResponse {
    Ok(TakeCanisterSnapshotOk),
    Err(TakeCanisterSnapshotError),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotOk {
    pub id: Vec<u8>,
    pub taken_at_timestamp: u64,
    pub total_size: u64,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotError {
    pub code: Option<i32>,
    pub description: String,
}
