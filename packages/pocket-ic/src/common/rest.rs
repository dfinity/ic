//! Rust structs that reflect the structure of JSON-objects used in the v2-REST-API.

use serde::{Deserialize, Serialize};

use super::blob::BlobId;

pub type InstanceId = usize;

// ================================================================================================================= //
// HTTP JSON Request types

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Checkpoint {
    pub checkpoint_name: String,
}

// ================================================================================================================= //
// HTTP JSON Response types

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreateInstanceResponse {
    Created { instance_id: InstanceId },
    Error { message: String },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawTime {
    pub nanos_since_epoch: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawCanisterCall {
    // #[serde(with = "base64")]
    pub sender: Vec<u8>,
    // #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub method: String,
    // #[serde(with = "base64")]
    pub payload: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawSetStableMemory {
    pub canister_id: Vec<u8>,
    pub blob_id: BlobId,
}
