use candid::CandidType;
use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// An action for a 'downstream_calls_test' canister, i.e. either call another such
/// canister or respond to the calling canister.
#[derive(Serialize, Deserialize, Debug, CandidType)]
pub enum CallOrResponse {
    Call(CanisterId),
    Response,
}

/// The state that is passed from ('downstream_calls_test') canister to canister.
/// It keeps track of call tree information and contains a sequence of actions. At each
/// step the action at the front is popped from the queue and executed, while the rest
/// is passed on to the next canister. We are using a queue over a vector so that it is
/// straightforward to execute the list of actions front to back.
#[derive(Serialize, Deserialize, Debug, CandidType)]
pub struct State {
    pub actions: VecDeque<CallOrResponse>,
    pub call_count: u64,
    pub current_depth: u64,
    pub depth_total: u64,
}
