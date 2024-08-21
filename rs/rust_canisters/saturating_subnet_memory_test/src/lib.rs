use candid::CandidType;
use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};

/// A receiver canister ID and a vector of payload sizes to use for the requests to be sent to this
/// canister.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, CandidType)]
pub struct RequestConfig {
    pub payload_bytes: u32,
    pub receiver: CanisterId,
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, CandidType)]
pub struct ResponseConfig {
    pub payload_bytes: u32,
    pub instructions_count: u64,
}

/// A full config for sending messages. This is sent to the `start` method of the canister.
#[derive(Serialize, Deserialize, Debug, CandidType)]
pub struct Config {
    pub requests_per_round: u32,
    pub request_configs: Vec<RequestConfig>,
    pub response_configs: Vec<ResponseConfig>,
}

/// Enum for whether a response was `Received` and the size of the payload, or whether it was
/// `Rejected` including the rejection message.
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, CandidType)]
pub enum Response {
    PayloadBytes(u32),
    Rejected(String),
}

/// Stats for a request sent and the response it received.
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, CandidType)]
pub struct RequestStats {
    pub receiver: CanisterId,
    pub payload_bytes_sent: u32,
    pub response: Response,
}

/// Stats of the messages and bytes sent by the canister. This is returned by the `stats` query of
/// the canister.
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Default, CandidType)]
pub struct Metrics {
    /// Counter for failures on sending requests.
    pub send_request_error_count: u32,
    pub send_request_success_count: u32,
    pub decode_error_count: u32,

    /// Metrics vector with entries for each request.
    pub sent_requests_stats: Vec<RequestStats>,
}
