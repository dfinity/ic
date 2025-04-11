use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

pub type GetSaltResponse = Result<SaltResponse, GetSaltError>;

// Size of the shared salt in bytes
pub const SALT_SIZE: usize = 32;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum SaltGenerationStrategy {
    StartOfMonth,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct InitArg {
    pub regenerate_now: bool,
    pub salt_generation_strategy: SaltGenerationStrategy,
    pub registry_polling_interval_secs: u64,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SaltResponse {
    pub salt: Vec<u8>,
    pub salt_id: u64,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
pub enum GetSaltError {
    SaltNotInitialized,
    Unauthorized,
    Internal(String),
}

#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct ApiBoundaryNodeIdRecord {
    pub id: Option<Principal>,
}

#[derive(CandidType, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct GetApiBoundaryNodeIdsRequest {}
