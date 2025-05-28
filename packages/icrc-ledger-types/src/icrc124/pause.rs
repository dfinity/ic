use candid::{CandidType, Deserialize};
use serde::Serialize;

/// The arguments for the [ICRC-124 `pause`](https://github.com/dfinity/ICRC/pull/135) endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PauseArgs {
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub created_at_time: Option<u64>,
}
