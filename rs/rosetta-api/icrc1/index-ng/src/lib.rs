use candid::{CandidType, Deserialize, Principal};
use icrc_ledger_types::icrc3::blocks::GenericBlock;

#[derive(CandidType, Debug, Deserialize)]
pub struct InitArg {
    pub ledger_id: Principal,
}

#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct GetBlocksResponse {
    // The length of the chain indexed.
    pub chain_length: u64,

    // The blocks in the requested range.
    pub blocks: Vec<GenericBlock>,
}
