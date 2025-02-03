use std::cell::RefCell;

use candid::CandidType;
use ic_base_types::{NodeId, PrincipalId};
use serde::Deserialize;

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum Ballot {
    Yes,
    No,
    Undecided,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct NodeOperatorBallot {
    pub principal: PrincipalId,
    pub nodes_tied_to_ballot: Vec<NodeId>,
    pub ballot: Ballot,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum RecoveryPayload {
    Halt,
    DoRecovery { height: u64, state_hash: String },
    Unhalt,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RecoveryProposal {
    /// The principal id of the proposer (must be one of the node
    /// operators of the NNS subnet according to the registry at
    /// time of submission).
    pub proposer: PrincipalId,
    /// The timestamp, in seconds, at which the proposal was submitted.
    pub submission_timestamp_seconds: u64,
    /// The ballots cast by node operators.
    pub node_operator_ballots: Vec<NodeOperatorBallot>,
    /// Payload for the proposal
    pub payload: RecoveryPayload,
}

thread_local! {
  static PROPOSALS: RefCell<Vec<RecoveryProposal>> = const { RefCell::new(Vec::new()) };
}
