use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum CanisterCreationStatus {
    #[serde(rename = "idle")]
    Idle,
    #[serde(rename = "in_progress")]
    InProgress(u64),
    #[serde(rename = "done")]
    Done(Vec<Principal>),
}
