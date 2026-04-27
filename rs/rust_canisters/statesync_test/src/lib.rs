use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, CandidType, Deserialize, Serialize)]
pub enum CanisterCreationStatus {
    #[serde(rename = "idle")]
    Idle,
    #[serde(rename = "in_progress")]
    InProgress(u64),
    #[serde(rename = "done")]
    Done(u64),
}
