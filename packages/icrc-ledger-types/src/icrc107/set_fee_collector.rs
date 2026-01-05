use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

use super::super::icrc1::account::Account;

/// The arguments for the
/// [ICRC-107 `icrc107_set_fee_collector`](https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-107/ICRC-107.md#icrc107_set_fee_collector)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SetFeeCollectorArgs {
    #[serde(default)]
    pub fee_collector: Option<Account>,
    pub created_at_time: u64,
}

/// The error return type for the
/// [ICRC-107 `icrc107_set_fee_collector`](https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-107/ICRC-107.md#icrc107_set_fee_collector)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SetFeeCollectorError {
    AccessDenied(String),
    InvalidAccount(String),
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}
