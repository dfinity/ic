//! Rust structs that reflect the structure of JSON-objects used in the v2-REST-API.

use candid::Principal;
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
    #[serde(with = "base64")]
    pub sender: Vec<u8>,
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub method: String,
    #[serde(with = "base64")]
    pub payload: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawSetStableMemory {
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub blob_id: BlobId,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawAddCycles {
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub amount: u128,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawCanisterId {
    // raw bytes of the principal
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
}

impl From<Principal> for RawCanisterId {
    fn from(principal: Principal) -> Self {
        Self {
            canister_id: principal.as_slice().to_vec(),
        }
    }
}

// By default, serde serializes Vec<u8> to a list of numbers, which is inefficient.
// This enables serializing Vec<u8> to a compact base64 representation.
#[allow(deprecated)]
pub mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(|e| serde::de::Error::custom(e))
    }
}
