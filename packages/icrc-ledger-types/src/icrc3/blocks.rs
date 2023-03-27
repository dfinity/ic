use candid::{CandidType, Deserialize, Nat};
use serde_bytes::ByteBuf;

use crate::{
    icrc::generic_value::Value,
    icrc1::{account::Account, transfer::BlockIndex},
};

use super::{
    archive::{ArchivedRange, QueryBlockArchiveFn},
    transactions::Transaction,
};

pub type GenericBlock = Value;

// Representation of a Block supporting the Icrc3 Standard
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent_hash: Option<ByteBuf>,
    pub transaction: Transaction,
    pub effective_fee: Option<u64>,
    pub timestamp: u64,
    pub fee_collector: Option<Account>,
    pub fee_collector_block_index: Option<u64>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct GetBlocksResponse {
    pub first_index: BlockIndex,
    pub chain_length: u64,
    pub certificate: Option<ByteBuf>,
    pub blocks: Vec<GenericBlock>,
    pub archived_blocks: Vec<ArchivedRange<QueryBlockArchiveFn>>,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetBlocksRequest {
    pub start: BlockIndex,
    pub length: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockRange {
    pub blocks: Vec<GenericBlock>,
}

impl GetBlocksRequest {
    pub fn as_start_and_length(&self) -> Result<(u64, u64), String> {
        use num_traits::cast::ToPrimitive;

        let start = self.start.0.to_u64().ok_or_else(|| {
            format!(
                "transaction index {} is too large, max allowed: {}",
                self.start,
                u64::MAX
            )
        })?;
        let length = self.length.0.to_u64().ok_or_else(|| {
            format!(
                "requested length {} is too large, max allowed: {}",
                self.length,
                u64::MAX
            )
        })?;
        Ok((start, length))
    }
}

#[derive(Debug, CandidType, Deserialize)]
pub struct BlockCertificate {
    pub block_index: u64,
    pub certificate: Option<serde_bytes::ByteBuf>,
}
