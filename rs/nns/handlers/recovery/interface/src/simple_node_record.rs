use candid::{CandidType, Principal};
use serde::Deserialize;

#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct SimpleNodeRecord {
    pub node_principal: Principal,
    pub operator_principal: Principal,
}
