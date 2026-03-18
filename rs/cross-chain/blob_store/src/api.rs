//! Types used for the Candid API when interacting with the BlobStore canister.
use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct InsertRequest {
    pub hash: String,
    pub data: Vec<u8>,
    pub tags: Option<Vec<String>>,
}

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum InsertError {
    NotAuthorized,
    InvalidHash { reason: String },
    HashMismatch { expected: String, actual: String },
    AlreadyExists,
    InvalidTag { reason: String },
}

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum GetError {
    InvalidHash { reason: String },
    NotFound,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlobMetadata {
    pub uploader: candid::Principal,
    pub inserted_at_ns: u64,
    pub size: u64,
    pub tags: Vec<String>,
}
