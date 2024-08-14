use candid::{CandidType, Deserialize, Nat, Principal};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::BlockIndex;
use icrc_ledger_types::icrc3::blocks::GenericBlock;
use icrc_ledger_types::icrc3::transactions::Transaction;

/// The maximum number of blocks to return in a single [get_blocks] request.
pub const DEFAULT_MAX_BLOCKS_PER_RESPONSE: u64 = 2000;

#[derive(CandidType, Debug, Deserialize, Clone)]
pub enum IndexArg {
    Init(InitArg),
    Upgrade(UpgradeArg),
}

#[derive(CandidType, Debug, Deserialize, Clone)]
pub struct InitArg {
    pub ledger_id: Principal,
    pub retrieve_blocks_from_ledger_interval_seconds: Option<u64>,
}

#[derive(CandidType, Debug, Deserialize, Clone)]
pub struct UpgradeArg {
    pub ledger_id: Option<Principal>,
    pub retrieve_blocks_from_ledger_interval_seconds: Option<u64>,
}

#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct GetBlocksResponse {
    // The length of the chain indexed.
    pub chain_length: u64,

    // The blocks in the requested range.
    pub blocks: Vec<GenericBlock>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct GetAccountTransactionsArgs {
    pub account: Account,
    // The txid of the last transaction seen by the client.
    // If None then the results will start from the most recent
    // txid. If set then the results will start from the next
    // most recent txid after start (start won't be included).
    pub start: Option<BlockIndex>,
    // Maximum number of transactions to fetch.
    pub max_results: Nat,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TransactionWithId {
    pub id: BlockIndex,
    pub transaction: Transaction,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct GetAccountTransactionsResponse {
    pub balance: Nat,
    pub transactions: Vec<TransactionWithId>,
    // The txid of the oldest transaction the account has
    pub oldest_tx_id: Option<BlockIndex>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct GetAccountTransactionsError {
    pub message: String,
}

pub type GetAccountTransactionsResult =
    Result<GetAccountTransactionsResponse, GetAccountTransactionsError>;

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct ListSubaccountsArgs {
    pub owner: Principal,
    // The last subaccount seen by the client for the given principal.
    // This subaccount is excluded in the result.
    // If None then the results will start from the first
    // in natural order.
    pub start: Option<Subaccount>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub num_blocks_synced: BlockIndex,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct FeeCollectorRanges {
    pub ranges: Vec<(Account, Vec<(BlockIndex, BlockIndex)>)>,
}

#[derive(Clone, serde::Serialize, Deserialize, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub file: String,
    pub line: u32,
    pub message: String,
}

#[derive(Clone, Default, serde::Serialize, Deserialize, Debug)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GetBlocksMethod {
    // The `get_blocks` endpoint used by the Ledger
    // before ICRC-3 was implemented.
    GetBlocks,
    // The `icrc3_get_blocks` endpoint supported by
    // ICRC-3 compatible Ledgers.
    ICRC3GetBlocks,
}
