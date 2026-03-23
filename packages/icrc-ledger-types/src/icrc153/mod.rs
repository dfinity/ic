use candid::types::number::Nat;
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

use crate::icrc1::account::Account;

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct FreezeAccountArgs {
    pub account: Account,
    pub reason: Option<String>,
    pub created_at_time: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct UnfreezeAccountArgs {
    pub account: Account,
    pub reason: Option<String>,
    pub created_at_time: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct FreezePrincipalArgs {
    pub principal: Principal,
    pub reason: Option<String>,
    pub created_at_time: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct UnfreezePrincipalArgs {
    pub principal: Principal,
    pub reason: Option<String>,
    pub created_at_time: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum FreezeAccountError {
    Unauthorized { message: String },
    InvalidAccount { message: String },
    AlreadyFrozen { message: String },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum UnfreezeAccountError {
    Unauthorized { message: String },
    InvalidAccount { message: String },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum FreezePrincipalError {
    Unauthorized { message: String },
    InvalidPrincipal { message: String },
    AlreadyFrozen { message: String },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum UnfreezePrincipalError {
    Unauthorized { message: String },
    InvalidPrincipal { message: String },
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct FrozenAccountsRequest {
    pub start: Option<Account>,
    pub limit: Option<Nat>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct FrozenAccountsResponse {
    pub frozen_accounts: Vec<Account>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct FrozenPrincipalsRequest {
    pub start: Option<Principal>,
    pub limit: Option<Nat>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct FrozenPrincipalsResponse {
    pub frozen_principals: Vec<Principal>,
}
