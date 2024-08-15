use candid::CandidType;
use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};

/// A receiver canister ID and a vector of payload sizes to use for the requests to be sent to this
/// canister.
#[derive(Serialize, Deserialize, Debug, CandidType)]
pub struct RequestConfig {
    pub receiver: CanisterId,
    pub payload_bytes: Vec<u32>,
}

/// A full config for sending messages. This is sent to the `start` method of the canister.
#[derive(Serialize, Deserialize, Debug, CandidType)]
pub struct Config {
    pub requests_per_round: u32,
    pub request_configs: Vec<RequestConfig>,
    pub response_bytes: Vec<u32>,
}

/// Stats of the messages and bytes sent by the canister. This is returned by the `stats` query of
/// the canister.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, Default, CandidType)]
pub struct Metrics {
    /// Counter for failures on sending requests.
    pub send_request_error_count: u32,
    /// Counter for successfully sent requests.
    pub send_request_success_count: u32,
    /// Counter for the number of bytes sent in request payloads.
    pub request_bytes_sent: u32,
    /// Counter for responses received.
    pub received_response_count: u32,
    /// Counter for the number of bytes received in response payloads.
    pub response_bytes_received: u32,
    /// Counter for requests received.
    pub received_request_count: u32,
    /// Counter for the number of bytes received in request payloads.
    pub request_bytes_received: u32,
    /// Counter for responses sent.
    pub sent_response_count: u32,
    /// Counter for the number of bytes sent in response payloads.
    pub response_bytes_sent: u32,
}
