use crate::icrc::generic_value::ICRC3Value;
use crate::icrc3::archive::ArchivedRange;
use crate::icrc3::archive::QueryBlockArchiveFn;
use crate::{icrc::generic_value::Value, icrc1::transfer::BlockIndex};
use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;
use serde_bytes::ByteBuf;

use super::archive::QueryArchiveFn;

/// Deprecated, use `ICRC3GenericBlock` instead
pub type GenericBlock = Value;
pub type ICRC3GenericBlock = ICRC3Value;

/// Deprecated, use `GetBlocksResult` instead
#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetBlocksResponse {
    pub first_index: BlockIndex,
    pub chain_length: u64,
    pub certificate: Option<ByteBuf>,
    pub blocks: Vec<GenericBlock>,
    pub archived_blocks: Vec<ArchivedRange<QueryBlockArchiveFn>>,
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockWithId {
    pub id: Nat,
    pub block: ICRC3GenericBlock,
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivedBlocks {
    pub args: Vec<GetBlocksRequest>,
    pub callback: QueryArchiveFn<Vec<GetBlocksRequest>, GetBlocksResult>,
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetBlocksResult {
    pub log_length: Nat,
    pub blocks: Vec<BlockWithId>,
    pub archived_blocks: Vec<ArchivedBlocks>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetBlocksRequest {
    pub start: BlockIndex,
    pub length: Nat,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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

/// Deprecated, use `ICRC3DataCertificate` instead"
#[derive(Debug, CandidType, Serialize, Deserialize)]
pub struct DataCertificate {
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub hash_tree: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Serialize, Deserialize)]
pub struct ICRC3DataCertificate {
    pub certificate: serde_bytes::ByteBuf,
    pub hash_tree: serde_bytes::ByteBuf,
}

#[derive(Debug, CandidType, Serialize, Deserialize)]
pub struct SupportedBlockType {
    pub block_type: String,
    pub url: String,
}
