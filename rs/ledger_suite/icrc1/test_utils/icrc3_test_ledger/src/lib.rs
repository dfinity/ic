use candid::{CandidType, Nat, Principal};
use serde::Deserialize;

pub type AddBlockResult = Result<Nat, String>;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct ArchiveBlocksArgs {
    pub archive_id: Principal,
    pub num_blocks: u64,
}
