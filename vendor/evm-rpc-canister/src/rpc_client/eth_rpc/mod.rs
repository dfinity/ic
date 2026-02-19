//! This module contains definitions for communicating witEthereum API using the [JSON RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/)
//! interface.

use crate::rpc_client::{
    eth_rpc_error::{sanitize_send_raw_transaction_result, Parser},
    json::responses::{Block, FeeHistory, LogEntry, TransactionReceipt},
};
use canhttp::http::json::{Id, JsonRpcResponse};
use derive_more::From;
use ic_cdk::query;
use ic_management_canister_types::{HttpRequestResult, TransformArgs};
use minicbor::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, fmt::Debug};

#[cfg(test)]
mod tests;

// This constant is our approximation of the expected header size.
// The HTTP standard doesn't define any limit, and many implementations limit
// the headers size to 8 KiB. We chose a lower limit because headers observed on most providers
// fit in the constant defined below, and if there is a spike, then the payload size adjustment
// should take care of that.
pub const HEADER_SIZE_LIMIT: u64 = 2 * 1024;

// This constant comes from the IC specification:
// > If provided, the value must not exceed 2MB
const HTTP_MAX_SIZE: u64 = 2_000_000;

pub const MAX_PAYLOAD_SIZE: u64 = HTTP_MAX_SIZE - HEADER_SIZE_LIMIT;

#[derive(Debug, Decode, Encode, From)]
pub enum ResponseTransformEnvelope {
    #[n(0)]
    Single(#[n(0)] ResponseTransform),
    #[n(1)]
    Batch(#[n(0)] BTreeMap<String, ResponseTransform>),
}

impl From<BTreeMap<Id, ResponseTransform>> for ResponseTransformEnvelope {
    fn from(transforms: BTreeMap<Id, ResponseTransform>) -> Self {
        Self::from(BTreeMap::from_iter(transforms.into_iter().map(
            |(id, transform)| {
                (
                    serde_json::to_string(&id).expect("Failed to serialize request ID"),
                    transform,
                )
            },
        )))
    }
}

impl ResponseTransformEnvelope {
    fn apply(&self, body: &mut Vec<u8>) {
        match self {
            ResponseTransformEnvelope::Single(transform) => {
                if let Ok(response) =
                    serde_json::from_slice::<JsonRpcResponse<serde_json::Value>>(body)
                {
                    let response = transform.apply(response);
                    *body = serde_json::to_string(&response)
                        .expect("BUG: failed to serialize response")
                        .into_bytes();
                }
            }
            ResponseTransformEnvelope::Batch(transforms) => {
                if let Ok(responses) =
                    serde_json::from_slice::<Vec<JsonRpcResponse<serde_json::Value>>>(body)
                {
                    let mut responses: Vec<_> = responses
                        .into_iter()
                        .map(|response| {
                            let id = serde_json::to_string(response.id())
                                .expect("BUG: Failed to serialize response ID");
                            match transforms.get(&id) {
                                Some(transform) => transform.apply(response),
                                None => response,
                            }
                        })
                        .collect();
                    responses.sort_by_key(|response| {
                        serde_json::to_string(response.id())
                            .expect("BUG: Failed to serialize response ID")
                    });

                    *body = serde_json::to_string(&responses)
                        .expect("BUG: failed to serialize response")
                        .into_bytes();
                }
            }
        }
    }
}

/// Describes a payload transformation to execute before passing the HTTP response to consensus.
/// The purpose of these transformations is to ensure that the response encoding is deterministic
/// (the field order is the same).
#[derive(Debug, Decode, Encode)]
pub enum ResponseTransform {
    #[n(0)]
    Call,
    #[n(1)]
    FeeHistory,
    #[n(2)]
    GetBlockByNumber,
    #[n(3)]
    GetLogs,
    #[n(4)]
    GetTransactionCount,
    #[n(5)]
    GetTransactionReceipt,
    #[n(6)]
    SendRawTransaction,
    #[n(7)]
    Raw,
}

impl ResponseTransform {
    fn apply(
        &self,
        response: JsonRpcResponse<serde_json::Value>,
    ) -> JsonRpcResponse<serde_json::Value> {
        fn canonicalize_response<T>(response: serde_json::Value) -> serde_json::Value
        where
            T: Serialize + DeserializeOwned,
        {
            let response = match T::deserialize(&response) {
                Ok(response) => response,
                Err(_) => return response,
            };

            serde_json::to_value(&response).expect("BUG: failed to serialize response")
        }

        fn canonicalize_collection_response<T>(response: serde_json::Value) -> serde_json::Value
        where
            T: Serialize + DeserializeOwned,
        {
            let mut response = match Vec::<T>::deserialize(&response) {
                Ok(response) => response,
                Err(_) => return response,
            };

            sort_by_hash(&mut response);

            serde_json::to_value(&response).expect("BUG: failed to serialize response")
        }

        match self {
            Self::GetBlockByNumber => response.map(canonicalize_response::<Block>),
            Self::GetLogs => response.map(canonicalize_collection_response::<LogEntry>),
            Self::GetTransactionReceipt => {
                response.map(canonicalize_response::<TransactionReceipt>)
            }
            Self::FeeHistory => response.map(canonicalize_response::<FeeHistory>),
            ResponseTransform::SendRawTransaction => {
                sanitize_send_raw_transaction_result(response, Parser::new())
            }
            Self::Call | Self::GetTransactionCount | Self::Raw => {
                response.map(canonicalize_response::<serde_json::Value>)
            }
        }
    }
}

#[query]
fn cleanup_response(args: TransformArgs) -> HttpRequestResult {
    let mut args = args;
    args.response.headers.clear();
    let status_ok = args.response.status >= 200u16 && args.response.status < 300u16;
    if status_ok && !args.context.is_empty() {
        if let Ok(transform) = minicbor::decode::<ResponseTransformEnvelope>(&args.context[..]) {
            transform.apply(&mut args.response.body);
        }
    }
    args.response
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResponseSizeEstimate(u64);

impl ResponseSizeEstimate {
    pub fn new(num_bytes: u64) -> Self {
        assert!(num_bytes > 0);
        assert!(num_bytes <= MAX_PAYLOAD_SIZE);
        Self(num_bytes)
    }

    /// Describes the expected (90th percentile) number of bytes in the HTTP response body.
    /// This number should be less than `MAX_PAYLOAD_SIZE`.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ResponseSizeEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn sort_by_hash<T: Serialize + DeserializeOwned>(to_sort: &mut [T]) {
    fn hash(input: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().into()
    }

    to_sort.sort_by(|a, b| {
        let a_hash = hash(&serde_json::to_vec(a).expect("BUG: failed to serialize"));
        let b_hash = hash(&serde_json::to_vec(b).expect("BUG: failed to serialize"));
        a_hash.cmp(&b_hash)
    });
}
