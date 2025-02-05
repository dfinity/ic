use candid::{CandidType, Principal};
use serde::Deserialize;

#[derive(Debug, Clone, CandidType, Deserialize)]
/// Convenience structure for storing information about nodes
/// and their operators coming from NNS on recovery canister.
pub struct SimpleNodeOperatorRecord {
    pub operator_id: Principal,
    pub nodes: Vec<Principal>,
}
