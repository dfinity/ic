//! The PocketIC server and the PocketIc library interface with HTTP/JSON.
//! The types in this module are used to serialize and deserialize data
//! from and to JSON, and are used by both crates.

use crate::UserError;

use candid::Principal;
use reqwest::blocking::Response;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub type InstanceId = usize;

// ================================================================================================================= //
// HTTP JSON Request types

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawCheckpoint {
    pub checkpoint_name: String,
}

// ================================================================================================================= //
// HTTP JSON Response types

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreateInstanceResponse {
    Created { instance_id: InstanceId },
    Error { message: String },
}

#[derive(Clone, Serialize, Deserialize, Debug, Copy)]
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
pub enum RawCanisterResult {
    Ok(RawWasmResult),
    Err(UserError),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RawWasmResult {
    /// Raw response, returned in a "happy" case
    Reply(#[serde(with = "base64")] Vec<u8>),
    /// Returned with an error message when the canister decides to reject the
    /// message
    Reject(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawSetStableMemory {
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub blob_id: BlobId,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawStableMemory {
    #[serde(with = "base64")]
    pub blob: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ApiError {
    message: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StartedOrBusyResponse {
    pub state_label: String,
    pub op_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ApiResponse<T> {
    Success(T),
    Busy { state_label: String, op_id: String },
    Started { state_label: String, op_id: String },
    Error { message: String },
}

impl<T: DeserializeOwned> From<Response> for ApiResponse<T> {
    fn from(resp: Response) -> Self {
        match resp.status() {
            reqwest::StatusCode::OK => {
                let result = resp.json::<T>();
                match result {
                    Ok(t) => ApiResponse::Success(t),
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {}", e),
                    },
                }
            }
            reqwest::StatusCode::ACCEPTED => {
                let result = resp.json::<StartedOrBusyResponse>();
                match result {
                    Ok(StartedOrBusyResponse { state_label, op_id }) => {
                        ApiResponse::Started { state_label, op_id }
                    }
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {}", e),
                    },
                }
            }
            reqwest::StatusCode::CONFLICT => {
                let result = resp.json::<StartedOrBusyResponse>();
                match result {
                    Ok(StartedOrBusyResponse { state_label, op_id }) => {
                        ApiResponse::Busy { state_label, op_id }
                    }
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse response: {}", e),
                    },
                }
            }
            _ => {
                let result = resp.json::<ApiError>();
                match result {
                    Ok(e) => ApiResponse::Error { message: e.message },
                    Err(e) => ApiResponse::Error {
                        message: format!("Could not parse error: {}", e),
                    },
                }
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawAddCycles {
    #[serde(with = "base64")]
    pub canister_id: Vec<u8>,
    pub amount: u128,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawCycles {
    pub cycles: u128,
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

#[derive(Serialize, Deserialize)]
pub struct RawVerifyCanisterSigArg {
    #[serde(with = "base64")]
    pub msg: Vec<u8>,
    #[serde(with = "base64")]
    pub sig: Vec<u8>,
    #[serde(with = "base64")]
    pub pubkey: Vec<u8>,
    #[serde(with = "base64")]
    pub root_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct BlobId(pub [u8; 32]);

#[derive(Clone, Debug)]
pub struct BinaryBlob {
    pub data: Vec<u8>,
    pub compression: BlobCompression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobCompression {
    Gzip,
    NoCompression,
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
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    }
}
