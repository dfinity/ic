use crate::value::Value;
use crate::{ArchivedRange, BlockIndex, GetTransactionsRequest, QueryArchiveFn};
use candid::{CandidType, Deserialize};

pub type Block = Value;

pub type GetBlocksArgs = GetTransactionsRequest;

#[derive(Debug, CandidType, Deserialize)]
pub struct GetBlocksResponse {
    pub first_index: BlockIndex,
    pub chain_length: u64,
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub blocks: Vec<Block>,
    pub archived_blocks: Vec<ArchivedRange<QueryBlockArchiveFn>>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockRange {
    pub blocks: Vec<Block>,
}

pub type QueryBlockArchiveFn = QueryArchiveFn<GetBlocksArgs, BlockRange>;

#[derive(Debug, CandidType, Deserialize)]
pub struct BlockCertificate {
    pub block_index: u64,
    pub certificate: Option<serde_bytes::ByteBuf>,
}
