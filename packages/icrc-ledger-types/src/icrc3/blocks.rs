use crate::icrc3::archive::ArchivedRange;
use crate::icrc3::archive::QueryBlockArchiveFn;
use crate::{icrc::generic_value::Value, icrc1::transfer::BlockIndex};
use candid::{CandidType, Deserialize, Nat};
use serde_bytes::ByteBuf;

pub type GenericBlock = Value;

#[derive(Debug, CandidType, Clone, Deserialize, PartialEq, Eq)]
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
pub struct DataCertificate {
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub hash_tree: serde_bytes::ByteBuf,
}
