use candid::CandidType;
use serde::Deserialize;

#[derive(CandidType, Deserialize)]
pub struct RetrieveBtcStatusRequest {
    pub block_index: u64,
}
