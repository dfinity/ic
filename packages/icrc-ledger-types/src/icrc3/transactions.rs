use candid::{CandidType, Deserialize, Nat};

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

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Mint {
    pub amount: Nat,
    pub to: Account,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub amount: Nat,
    pub from: Account,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub amount: Nat,
    pub from: Account,
    pub to: Account,
    pub memo: Option<Memo>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

// Representation of a Transaction which supports the Icrc1 Standard functionalities
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub kind: String,
    pub mint: Option<Mint>,
    pub burn: Option<Burn>,
    pub transfer: Option<Transfer>,
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
        }
    }

    pub fn mint(mint: Mint, timestamp: u64) -> Self {
        Self {
            kind: "mint".into(),
            timestamp,
            mint: Some(mint),
            burn: None,
            transfer: None,
        }
    }

    pub fn transfer(transfer: Transfer, timestamp: u64) -> Self {
        Self {
            kind: "transfer".into(),
            timestamp,
            mint: None,
            burn: None,
            transfer: Some(transfer),
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionsResponse {
    pub log_length: Nat,
    pub first_index: BlockIndex,
    pub transactions: Vec<Transaction>,
    pub archived_transactions: Vec<ArchivedRange<QueryTxArchiveFn>>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransactionRange {
    pub transactions: Vec<Transaction>,
}

pub type GetTransactionsRequest = GetBlocksRequest;
