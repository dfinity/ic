use candid::{CandidType, Deserialize, Nat};

use super::super::icrc1::account::Account;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AllowanceArgs {
    pub account: Account,
    pub spender: Account,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Allowance {
    pub allowance: Nat,
    #[serde(default)]
    pub expires_at: Option<u64>,
}
