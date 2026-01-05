use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

use super::super::icrc1::account::Account;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SetFeeCollectorArgs {
    #[serde(default)]
    pub fee_collector: Option<Account>,
    pub created_at_time: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SetFeeCollectorError {
    AccessDenied(String),
    InvalidAccount(String),
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}
