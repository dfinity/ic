use candid::{CandidType, Deserialize, Nat};

use super::super::icrc1::account::{Account, Subaccount};
use super::super::icrc1::transfer::Memo;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
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

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
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
