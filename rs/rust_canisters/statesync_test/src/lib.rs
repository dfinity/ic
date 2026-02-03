use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Copy, Clone, Serialize, Deserialize)]
pub enum CanisterCreationStatus {
    #[serde(rename = "idle")]
    Idle,
    #[serde(rename = "in_progress")]
    InProgress(u64),
    #[serde(rename = "done")]
    Done(u64),
}
