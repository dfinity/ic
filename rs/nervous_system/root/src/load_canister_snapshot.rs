use candid::CandidType;
use ic_base_types::PrincipalId;
use serde::Deserialize;

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotRequest {
    pub canister_id: PrincipalId,
    pub snapshot_id: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum LoadCanisterSnapshotResponse {
    Ok(LoadCanisterSnapshotOk),
    Err(LoadCanisterSnapshotError),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotOk {}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotError {
    pub code: Option<i32>,
    pub description: String,
}
