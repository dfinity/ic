//! Defines a canister which is used in testing Canister HTTP Calls feature.
//!
//! The canister receives HTTP request through inbound message, decodes the HTTP request
//! and forwards it to targeted service. Canister returns the remote service call response
//! as a canister message to client if the call was successful and agreed by majority nodes,
//! otherwise errors out.
//!
use std::time::Duration;

use candid::{CandidType, Deserialize};
use ic_management_canister_types_private::{
    BoundedHttpHeaders, FlexibleCanisterHttpRequestArgs, HttpHeader, HttpMethod, Payload,
    TransformContext,
};

/// The reject code that this canister reports back to its callers.
///
/// The variants and their ordering define the `variant` this canister exposes
/// over Candid, so the numbering must stay in sync with the reject codes of the
/// [IC interface specification](https://internetcomputer.org/docs/references/ic-interface-spec#reject-codes).
#[derive(Copy, Clone, Debug, CandidType, Deserialize)]
pub enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    Unknown,
}

impl RejectionCode {
    /// Translates a raw reject code, as reported by the system, into the variant
    /// this canister exposes over Candid.
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::NoError,
            1 => Self::SysFatal,
            2 => Self::SysTransient,
            3 => Self::DestinationInvalid,
            4 => Self::CanisterReject,
            5 => Self::CanisterError,
            _ => Self::Unknown,
        }
    }
}

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

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FlexibleRemoteHttpRequest {
    pub request: FlexibleCanisterHttpRequestArgs,
    pub cycles: u64,
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

/// The reply to a flexible outcall, with the cycles that came back on it.
///
/// `result` is the raw Candid encoding of a `flexible_http_request_result`, or the
/// rejection the management canister answered with.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FlexibleResponseWithRefundedCycles {
    pub result: Result<Vec<u8>, (RejectionCode, String)>,
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
