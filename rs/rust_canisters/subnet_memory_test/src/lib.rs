use candid::CandidType;
use ic_base_types::{CanisterId, NumBytes};
use ic_types::NumInstructions;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

/// A full config for sending messages. This is sent to the `start` method of the canister.
#[derive(Serialize, Deserialize, Debug, CandidType)]
pub struct Config {
    pub request_payloads: VecDeque<(NumBytes, CanisterId)>,
    pub response_payloads: BTreeMap<CanisterId, VecDeque<(NumBytes, NumInstructions)>>,
}

/// Indicate whether a request was sent successfully including the size of the payload; or rejected
/// synchronously by the IC including the error code.
#[derive(Serialize, Deserialize, Clone, Debug, CandidType)]
pub enum Request {
    Data(NumBytes),
    Rejected(i32),
    EncodeFailed,
}

/// Indicates whether a data response was received including the size of the payload; or rejected
/// including the message in the reject response.
#[derive(Serialize, Deserialize, Clone, Debug, CandidType)]
pub enum Response {
    Data(NumBytes),
    Rejected(String),
    DecodeFailed,
}

/// Record for one message cycle. Records whether and how many bytes were sent out; and received..
#[derive(Serialize, Deserialize, Clone, Debug, CandidType)]
pub struct Record {
    pub sent: Request,
    pub received: Option<Response>,
}
