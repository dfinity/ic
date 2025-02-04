use candid::{CandidType, Principal};
use serde::Deserialize;

#[derive(Debug, Clone, CandidType, Deserialize)]
/// Convenience structure for storing information about nodes
/// and their operators coming from NNS on recovery canister.
pub struct SimpleNodeRecord {
    pub node_principal: Principal,
    pub operator_principal: Principal,
}
