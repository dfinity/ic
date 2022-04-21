use crate::Payload;
use candid::{CandidType, Deserialize};
use serde::Serialize;

/// Struct used for encoding/decoding
/// `(http_request : (record {
//     url : text;
//     headers : vec http_header;
//     method : variant { get };
//     body : opt blob;
//     transform : opt variant { function: func (http_response) -> (http_response) query };
//   })`
#[derive(CandidType, Deserialize, Debug)]
pub struct CanisterHttpRequestArgs {
    pub url: String,
    pub headers: Vec<HttpHeader>,
    pub body: Option<Vec<u8>>,
    pub http_method: HttpMethod,
    pub transform_method_name: Option<String>,
}

impl Payload<'_> for CanisterHttpRequestArgs {}

/// Struct used for encoding/decoding
/// `(record {
/// name: text;
/// value: text;
/// })`;
#[derive(CandidType, Clone, Deserialize, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl Payload<'_> for HttpHeader {}

#[derive(Clone, Debug, PartialEq, CandidType, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
}

/// Represents the response for a canister http request.
/// Struct used for encoding/decoding
/// `(record {
/// status: nat;
/// headers: vec http_header;
/// body: blob;
/// })`;
#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponsePayload {
    pub status: u64,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl Payload<'_> for CanisterHttpResponsePayload {}
