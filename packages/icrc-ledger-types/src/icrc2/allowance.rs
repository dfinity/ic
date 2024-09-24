use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

use super::super::icrc1::account::Account;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct AllowanceArgs {
    pub account: Account,
    pub spender: Account,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct Allowance {
    pub allowance: Nat,
    #[serde(default)]
    pub expires_at: Option<u64>,
}
