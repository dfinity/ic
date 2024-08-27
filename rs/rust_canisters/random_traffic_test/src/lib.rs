use candid::CandidType;
use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};

/// A full config for generating random calls and replies.
#[derive(Serialize, Deserialize, Clone, Default, Debug, CandidType)]
pub struct Config {
    pub call_bytes_min: u32,
    pub call_bytes_max: u32,
    pub receivers: Vec<CanisterId>,
    pub reply_bytes_min: u32,
    pub reply_bytes_max: u32,
    pub instructions_count_min: u32,
    pub instructions_count_max: u32,
    pub downstream_call_weight: u32,
    pub reply_weight: u32,
}

/// Indicate whether a request was sent successfully including the size of the payload; or rejected
/// synchronously by the IC including the error code.
#[derive(Serialize, Deserialize, Clone, Debug, CandidType)]
pub enum Request {
    Data(u32),
    Rejected(i32),
}

/// Indicates whether a data response was received including the size of the payload; or rejected
/// including the message in the reject response.
#[derive(Serialize, Deserialize, Clone, Debug, CandidType)]
pub enum Response {
    Data(u32),
    Rejected(String),
}

/// Record for one message cycle. Records whether and how many bytes were sent out; and received..
#[derive(Serialize, Deserialize, Clone, Debug, CandidType)]
pub struct Record {
    pub sent: Request,
    pub received: Option<Response>,
}
