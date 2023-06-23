use candid::{CandidType, Deserialize, Nat};

use super::super::icrc1::account::{Account, Subaccount};
use super::super::icrc1::transfer::Memo;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ApproveArgs {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    pub spender: Account,
    pub amount: Nat,
    #[serde(default)]
    pub expected_allowance: Option<Nat>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub fee: Option<Nat>,
    #[serde(default)]
    pub memo: Option<Memo>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ApproveError {
    BadFee { expected_fee: Nat },
    // The caller does not have enough funds to pay the approval fee.
    InsufficientFunds { balance: Nat },
    // The caller specified the [expected_allowance] field, and the current
    // allowance did not match the given value.
    AllowanceChanged { current_allowance: Nat },
    // The approval request expired before the ledger had a chance to apply it.
    Expired { ledger_time: u64 },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}
