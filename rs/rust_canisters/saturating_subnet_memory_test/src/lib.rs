use candid::CandidType;
use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// A receiver canister ID and a vector of payload sizes to use for the requests to be sent to this
/// canister.
#[derive(Serialize, Deserialize, Debug, CandidType)]
pub struct RequestsConfig {
    receiver: CanisterId,
    payload_num_bytes: Vec<u32>,
}
