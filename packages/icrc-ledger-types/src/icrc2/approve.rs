use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;
use std::fmt;

use super::super::icrc1::account::{Account, Subaccount};
use super::super::icrc1::transfer::Memo;

/// The arguments for the
/// [ICRC-2 `approve`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md#icrc2_approve)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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

/// The error return type for the
/// [ICRC-2 `approve`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md#icrc2_approve)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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

impl fmt::Display for ApproveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFee { expected_fee } => {
                write!(f, "approve fee should be {expected_fee}")
            }
            Self::InsufficientFunds { balance } => {
                write!(
                    f,
                    "the debit account doesn't have enough funds to complete the transaction, current balance: {balance}"
                )
            }
            Self::AllowanceChanged { current_allowance } => write!(
                f,
                "expected_allowance does not match actual allowance, current allowance is {current_allowance}"
            ),
            Self::Expired { ledger_time } => write!(
                f,
                "the transaction expired before the ledger had a chance to apply it, current time is {ledger_time}"
            ),
            Self::TooOld {} => write!(f, "transaction's created_at_time is too far in the past"),
            Self::CreatedInFuture { ledger_time } => write!(
                f,
                "transaction's created_at_time is in future, current ledger time is {ledger_time}"
            ),
            Self::Duplicate { duplicate_of } => write!(
                f,
                "transaction is a duplicate of another transaction in block {duplicate_of}"
            ),
            Self::TemporarilyUnavailable {} => write!(f, "the ledger is temporarily unavailable"),
            Self::GenericError {
                error_code,
                message,
            } => write!(f, "{error_code} {message}"),
        }
    }
}
