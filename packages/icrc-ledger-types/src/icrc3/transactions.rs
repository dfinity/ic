use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

use crate::{
    icrc::generic_value::Value,
    icrc1::{
        account::Account,
        transfer::{BlockIndex, Memo},
    },
};

use super::{
    archive::{ArchivedRange, QueryTxArchiveFn},
    blocks::GetBlocksRequest,
};

pub type GenericTransaction = Value;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Mint {
    pub amount: Nat,
    pub to: Account,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub amount: Nat,
    pub from: Account,
    pub spender: Option<Account>,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub amount: Nat,
    pub from: Account,
    pub to: Account,
    pub spender: Option<Account>,
    pub memo: Option<Memo>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Approve {
    pub from: Account,
    pub spender: Account,
    pub amount: Nat,
    pub expected_allowance: Option<Nat>,
    pub expires_at: Option<u64>,
    pub memo: Option<Memo>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

// Representation of a Transaction which supports the Icrc1 Standard functionalities
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub kind: String,
    pub mint: Option<Mint>,
    pub burn: Option<Burn>,
    pub transfer: Option<Transfer>,
    pub approve: Option<Approve>,
    pub timestamp: u64,
}

impl Transaction {
    pub fn burn(burn: Burn, timestamp: u64) -> Self {
        Self {
            kind: "burn".into(),
            timestamp,
            mint: None,
            burn: Some(burn),
            transfer: None,
            approve: None,
        }
    }

    pub fn mint(mint: Mint, timestamp: u64) -> Self {
        Self {
            kind: "mint".into(),
            timestamp,
            mint: Some(mint),
            burn: None,
            transfer: None,
            approve: None,
        }
    }

    pub fn transfer(transfer: Transfer, timestamp: u64) -> Self {
        Self {
            kind: "transfer".into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: Some(transfer),
            approve: None,
        }
    }

    pub fn approve(approve: Approve, timestamp: u64) -> Self {
        Self {
            kind: "approve".into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: None,
            approve: Some(approve),
        }
    }
}

/// Deprecated. Use [`GetBlocksResponse`] returned from the
/// [`icrc3_get_blocks`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md)
/// endpoint instead.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionsResponse {
    pub log_length: Nat,
    pub first_index: BlockIndex,
    pub transactions: Vec<Transaction>,
    pub archived_transactions: Vec<ArchivedRange<QueryTxArchiveFn>>,
}

/// Deprecated. Use Vec<[`ICRC3GenericBlock`]> instead
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransactionRange {
    pub transactions: Vec<Transaction>,
}

pub type GetTransactionsRequest = GetBlocksRequest;
