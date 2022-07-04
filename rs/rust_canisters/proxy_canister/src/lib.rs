//! Defines a canister which is used in testing Canister HTTP Calls feature.
//!
//! The canister receives HTTP request through inbound message, decodes the HTTP request
//! and forwards it to targeted service. Canister returns the remote service call response
//! as a canister message to client if the call was successful and agreed by majority nodes,
//! otherwise errors out.
//!
use candid::CandidType;
use ic_ic00_types::HttpMethod;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct RemoteHttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub method: HttpMethod,
    pub body: String,
    pub transform: Option<String>,
    pub max_response_size: Option<u64>,
    pub cycles: u64,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct RemoteHttpResponse {
    pub status: u8,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl RemoteHttpResponse {
    pub fn new(status: u8, headers: Vec<(String, String)>, body: String) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}
