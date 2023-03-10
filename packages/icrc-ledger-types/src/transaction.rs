use crate::{Account, ArchivedRange, GetTransactionsRequest, QueryArchiveFn};
use candid::types::number::Nat;
use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Mint {
    pub amount: Nat,
    pub to: Account,
    pub memo: Option<ByteBuf>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub amount: Nat,
    pub from: Account,
    pub memo: Option<ByteBuf>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub amount: Nat,
    pub from: Account,
    pub to: Account,
    pub memo: Option<ByteBuf>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub kind: String,
    pub mint: Option<Mint>,
    pub burn: Option<Burn>,
    pub transfer: Option<Transfer>,
    pub timestamp: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionsResponse {
    pub log_length: Nat,
    pub first_index: Nat,
    pub transactions: Vec<Transaction>,
    pub archived_transactions: Vec<ArchivedRange<QueryTxArchiveFn>>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransactionRange {
    pub transactions: Vec<Transaction>,
}

pub type QueryTxArchiveFn = QueryArchiveFn<GetTransactionsRequest, TransactionRange>;
