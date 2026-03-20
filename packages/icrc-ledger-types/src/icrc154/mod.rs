use candid::CandidType;
use candid::types::number::Nat;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct PauseArgs {
    pub reason: Option<String>,
    pub created_at_time: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct UnpauseArgs {
    pub reason: Option<String>,
    pub created_at_time: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct DeactivateArgs {
    pub reason: Option<String>,
    pub created_at_time: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum PauseError {
    Unauthorized { message: String },
    AlreadyPaused { message: String },
    AlreadyDeactivated { message: String },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum UnpauseError {
    Unauthorized { message: String },
    NotPaused { message: String },
    AlreadyDeactivated { message: String },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum DeactivateError {
    Unauthorized { message: String },
    AlreadyDeactivated { message: String },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}
