//! Defines a canister which is used in testing Canister HTTP Calls feature.
//!
//! The canister receives HTTP request through inbound message, decodes the HTTP request
//! and forwards it to targeted service. Canister returns the remote service call response
//! as a canister message to client if the call was successful and agreed by majority nodes,
//! otherwise errors out.
//!
#![allow(deprecated)]
use std::time::Duration;

use candid::{CandidType, Deserialize};
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{
    BoundedHttpHeaders, HttpHeader, HttpMethod, Payload, TransformContext,
};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RemoteHttpRequest {
    pub request: UnvalidatedCanisterHttpRequestArgs,
    pub cycles: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RemoteHttpStressRequest {
    pub request: RemoteHttpRequest,
    /// Number of requests to send concurrently.
    pub count: u64,
}

/// We create a custom type instead of reusing [`ic_management_canister_types_private::CanisterHttpRequestArgs`]
/// as we don't want the body to be deserialized as a bounded vec.
/// This allows us to test sending headers that are longer than the default limit and test.
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct UnvalidatedCanisterHttpRequestArgs {
    pub url: String,
    pub max_response_bytes: Option<u64>,
    pub headers: Vec<HttpHeader>,
    pub body: Option<Vec<u8>>,
    pub method: HttpMethod,
    pub transform: Option<TransformContext>,
    pub is_replicated: Option<bool>,
    pub pricing_version: Option<u32>,
}
impl Payload<'_> for UnvalidatedCanisterHttpRequestArgs {}

impl From<UnvalidatedCanisterHttpRequestArgs>
    for ic_management_canister_types_private::CanisterHttpRequestArgs
{
    fn from(args: UnvalidatedCanisterHttpRequestArgs) -> Self {
        Self {
            url: args.url,
            max_response_bytes: args.max_response_bytes,
            headers: BoundedHttpHeaders::new(args.headers),
            body: args.body,
            method: args.method,
            transform: args.transform,
            is_replicated: args.is_replicated,
            pricing_version: args.pricing_version,
        }
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RemoteHttpResponse {
    pub status: u128,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ResponseWithRefundedCycles {
    pub result: Result<RemoteHttpResponse, (RejectionCode, String)>,
    pub refunded_cycles: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RemoteHttpStressResponse {
    pub response: RemoteHttpResponse,
    pub duration: Duration,
}

impl RemoteHttpResponse {
    pub fn new(status: u128, headers: Vec<(String, String)>, body: String) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}
