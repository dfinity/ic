use candid::{CandidType, Deserialize, Principal};
use ic_ledger_core::block::EncodedBlock;
use icp_ledger::{AccountIdentifier, BlockIndex, Transaction};

#[derive(CandidType, Debug, Deserialize)]
pub struct InitArg {
    pub ledger_id: Principal,
}

#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct GetBlocksResponse {
    // The length of the chain indexed.
    pub chain_length: u64,

    // The blocks in the requested range.
    pub blocks: Vec<EncodedBlock>,
}
#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
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

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TransactionWithId {
    pub id: BlockIndex,
    pub transaction: Transaction,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct GetAccountIdentifierTransactionsResponse {
    pub balance: u64,
    pub transactions: Vec<TransactionWithId>,
    // The txid of the oldest transaction the account_identifier has
    pub oldest_tx_id: Option<BlockIndex>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct GetAccountIdentifierTransactionsError {
    pub message: String,
}

pub type GetAccountIdentifierTransactionsResult =
    Result<GetAccountIdentifierTransactionsResponse, GetAccountIdentifierTransactionsError>;

#[derive(CandidType, Debug, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub num_blocks_synced: BlockIndex,
}
