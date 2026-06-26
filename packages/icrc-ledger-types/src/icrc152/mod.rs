use candid::types::number::Nat;
use candid::{CandidType, Deserialize};

use crate::icrc1::account::Account;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Icrc152MintArgs {
    pub to: Account,
    pub amount: Nat,
    pub created_at_time: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Icrc152MintError {
    Unauthorized(String),
    InvalidAccount(String),
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Icrc152BurnArgs {
    pub from: Account,
    pub amount: Nat,
    pub created_at_time: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Icrc152BurnError {
    Unauthorized(String),
    InvalidAccount(String),
    InsufficientBalance { balance: Nat },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}
