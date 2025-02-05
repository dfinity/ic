use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;

#[derive(CandidType, Debug, Deserialize, Serialize, Clone)]
/// Convenience structure for storing information about nodes
/// and their operators coming from NNS on recovery canister.
pub struct SimpleNodeOperatorRecord {
    pub operator_id: Principal,
    pub nodes: Vec<Principal>,
}
