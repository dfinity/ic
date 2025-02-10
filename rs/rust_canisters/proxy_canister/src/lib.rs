//! Defines a canister which is used in testing Canister HTTP Calls feature.
//!
//! The canister receives HTTP request through inbound message, decodes the HTTP request
//! and forwards it to targeted service. Canister returns the remote service call response
//! as a canister message to client if the call was successful and agreed by majority nodes,
//! otherwise errors out.
//!
use candid::{CandidType, Deserialize};
use ic_management_canister_types_private::{HttpHeader, HttpMethod, Payload, TransformContext};
// use ic_management_canister_types_private::CanisterHttpRequestArgs;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RemoteHttpRequest {
    pub request: CanisterHttpRequestArgs,
    pub cycles: u64,
}

/// We create a custom type instead of reusing [`ic_management_canister_types_private::CanisterHttpRequestArgs`]
/// as we don't want the body to be deserialized as a bounded vec.
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct CanisterHttpRequestArgs {
    pub url: String,
    pub max_response_bytes: Option<u64>,
    pub headers: Vec<HttpHeader>,
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub body: Option<Vec<u8>>,
    pub method: HttpMethod,
    pub transform: Option<TransformContext>,
}
impl Payload<'_> for CanisterHttpRequestArgs {}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RemoteHttpResponse {
    pub status: u128,
    pub headers: Vec<(String, String)>,
    pub body: String,
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
