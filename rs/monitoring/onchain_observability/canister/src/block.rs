use candid::{CandidType, Deserialize, Principal};
use ic_certified_map::Hash;

pub type Blob = Vec<u8>;
pub type Data = Vec<Blob>;
pub type Callers = Vec<Principal>;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Block {
    pub certificate: Blob,
    pub tree: Blob,
    pub data: Data,
    pub callers: Callers,
    pub previous_hash: Hash,
}
