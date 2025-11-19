use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;
use std::fmt;

use super::super::icrc1::account::{Account, Subaccount};
use super::super::icrc1::transfer::Memo;

/// The arguments for the
/// [ICRC-2 `transfer_from`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md#icrc2_transfer_from)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransferFromArgs {
    #[serde(default)]
    pub spender_subaccount: Option<Subaccount>,
    pub from: Account,
    pub to: Account,
    pub amount: Nat,
    #[serde(default)]
    pub fee: Option<Nat>,
    #[serde(default)]
    pub memo: Option<Memo>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
}

/// The error return type for the
/// [ICRC-2 `transfer_from`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md#icrc2_transfer_from)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TransferFromError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    // The [from] account does not hold enough funds for the transfer.
    InsufficientFunds { balance: Nat },
    // The caller exceeded its allowance.
    InsufficientAllowance { allowance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

impl fmt::Display for TransferFromError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFee { expected_fee } => {
                write!(f, "transfer_from fee should be {expected_fee}")
            }
            Self::BadBurn { min_burn_amount } => write!(
                f,
                "the minimum number of tokens to be burned is {min_burn_amount}"
            ),
            Self::InsufficientFunds { balance } => write!(
                f,
                "the debit account doesn't have enough funds to complete the transaction, current balance: {balance}"
            ),
            Self::InsufficientAllowance { allowance } => write!(
                f,
                "the spender account does not have sufficient allowance, current allowance is {allowance}"
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
