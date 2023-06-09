use candid::{CandidType, Deserialize, Principal};
use ic_ledger_core::block::EncodedBlock;

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
