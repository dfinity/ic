//! Types used for the Candid API when interacting with the BlobStore canister.
use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct InsertRequest {
    pub hash: String,
    pub data: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum InsertError {
    NotAuthorized,
    InvalidHash { reason: String },
    HashMismatch { expected: String, actual: String },
    AlreadyExists,
}

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum GetError {
    InvalidHash { reason: String },
    NotFound,
}

#[derive(CandidType, serde::Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlobMetadata {
    pub uploader: candid::Principal,
    pub inserted_at_ns: u64,
    pub size: u64,
}
