use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

use super::super::icrc1::account::Account;

/// The arguments for the `icrc103_get_allowances` endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetAllowancesArgs {
    pub from_account: Option<Account>,
    pub prev_spender: Option<Account>,
    pub take: Option<Nat>,
}

/// Error returned by the `icrc103_get_allowances` endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum GetAllowancesError {
    AccessDenied { reason: String },
    GenericError { error_code: Nat, message: String },
}

/// The allowance returned by the `icrc103_get_allowances` endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Allowance {
    pub from_account: Account,
    pub to_spender: Account,
    pub allowance: Nat,
    pub expires_at: Option<u64>,
}

/// The allowances vector returned by the `icrc103_get_allowances` endpoint.
pub type Allowances = Vec<Allowance>;
