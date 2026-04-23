use candid::types::number::Nat;
use candid::{CandidType, Deserialize, Principal};

use crate::icrc1::account::Account;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Icrc153FreezeAccountArgs {
    pub account: Account,
    pub created_at_time: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Icrc153UnfreezeAccountArgs {
    pub account: Account,
    pub created_at_time: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Icrc153FreezePrincipalArgs {
    pub principal: Principal,
    pub created_at_time: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Icrc153UnfreezePrincipalArgs {
    pub principal: Principal,
    pub created_at_time: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Icrc153FreezeAccountError {
    Unauthorized(String),
    InvalidAccount(String),
    AlreadyFrozen(String),
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Icrc153UnfreezeAccountError {
    Unauthorized(String),
    InvalidAccount(String),
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Icrc153FreezePrincipalError {
    Unauthorized(String),
    InvalidPrincipal(String),
    AlreadyFrozen(String),
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum Icrc153UnfreezePrincipalError {
    Unauthorized(String),
    InvalidPrincipal(String),
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FrozenAccountsRequest {
    pub start_after: Option<Account>,
    pub max_results: Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FrozenAccountsResponse {
    pub accounts: Vec<Account>,
    pub has_more: bool,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FrozenPrincipalsRequest {
    pub start_after: Option<Principal>,
    pub max_results: Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FrozenPrincipalsResponse {
    pub principals: Vec<Principal>,
    pub has_more: bool,
}
