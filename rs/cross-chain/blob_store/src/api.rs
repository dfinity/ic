//! Types used for the Candid API when interacting with the BlobStore canister.
use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub struct RecordRequest {
    pub hash: String,
    pub data: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq)]
pub enum RecordError {
    NotAuthorized,
    InvalidHash(String),
    HashMismatch { expected: String, actual: String },
    AlreadyExists,
}
