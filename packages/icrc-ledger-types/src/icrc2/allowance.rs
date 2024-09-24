use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

use super::super::icrc1::account::Account;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AllowanceArgs {
    pub account: Account,
    pub spender: Account,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Allowance {
    pub allowance: Nat,
    #[serde(default)]
    pub expires_at: Option<u64>,
}
