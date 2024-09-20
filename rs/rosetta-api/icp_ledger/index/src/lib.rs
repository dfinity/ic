use candid::{CandidType, Deserialize, Principal};
use ic_ledger_core::block::EncodedBlock;
use ic_ledger_core::timestamp::TimeStamp;
use icp_ledger::{AccountIdentifier, Block, BlockIndex, Memo, Operation};
use serde_bytes::ByteBuf;

pub mod logs;

#[derive(Debug, CandidType, Deserialize)]
pub struct InitArg {
    pub ledger_id: Principal,
}

#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct GetBlocksResponse {
    // The length of the chain indexed.
    pub chain_length: u64,

    // The blocks in the requested range.
    pub blocks: Vec<EncodedBlock>,
}
#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct GetAccountIdentifierTransactionsArgs {
    pub account_identifier: AccountIdentifier,
    // The txid of the last transaction seen by the client.
    // If None then the results will start from the most recent
    // txid. If set then the results will start from the next
    // most recent txid after start (start won't be included).
    pub start: Option<BlockIndex>,
    // Maximum number of transactions to fetch.
    pub max_results: u64,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SettledTransaction {
    pub operation: Operation,
    pub memo: Memo,
    /// The time this transaction was created on the client side.
    pub created_at_time: Option<TimeStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icrc1_memo: Option<ByteBuf>,
    /// The time the block with this transaction was created.
    pub timestamp: Option<TimeStamp>,
}

impl From<Block> for SettledTransaction {
    fn from(block: Block) -> Self {
        SettledTransaction {
            operation: block.transaction.operation,
            memo: block.transaction.memo,
            created_at_time: block.transaction.created_at_time,
            icrc1_memo: block.transaction.icrc1_memo,
            timestamp: Some(block.timestamp),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct SettledTransactionWithId {
    pub id: BlockIndex,
    pub transaction: SettledTransaction,
}

#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct GetAccountIdentifierTransactionsResponse {
    pub balance: u64,
    pub transactions: Vec<SettledTransactionWithId>,
    // The txid of the oldest transaction the account_identifier has
    pub oldest_tx_id: Option<BlockIndex>,
}

#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct GetAccountIdentifierTransactionsError {
    pub message: String,
}

pub type GetAccountIdentifierTransactionsResult =
    Result<GetAccountIdentifierTransactionsResponse, GetAccountIdentifierTransactionsError>;
pub type GetAccountTransactionsResult = GetAccountIdentifierTransactionsResult;

#[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct Status {
    pub num_blocks_synced: BlockIndex,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub enum Priority {
    P0,
    P1,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub priority: Priority,
    pub file: String,
    pub line: u32,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}
