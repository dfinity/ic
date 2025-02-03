use std::cell::RefCell;

use candid::CandidType;
use ic_base_types::{NodeId, PrincipalId};
use serde::Deserialize;

use crate::node_operator_sync::get_node_operators_in_nns;

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

impl RecoveryProposal {
    fn is_byzantine_majority(&self, ballot: Ballot) -> bool {
        let total_nodes_nodes = self
            .node_operator_ballots
            .iter()
            .map(|bal| bal.nodes_tied_to_ballot.len())
            .sum::<usize>();
        let max_faults = (total_nodes_nodes - 1) / 3;
        let votes_for_ballot = self
            .node_operator_ballots
            .iter()
            .map(|vote| match vote.ballot == ballot {
                // Each vote has the weight of 1 times
                // the amount of nodes the node operator
                // has in the nns subnet
                true => 1 * vote.nodes_tied_to_ballot.len(),
                false => 0,
            })
            .sum::<usize>();
        votes_for_ballot >= (total_nodes_nodes - max_faults)
    }

    /// For a root proposal to have a byzantine majority of no, it
    /// needs to collect f + 1 "no" votes, where N s the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    fn is_byzantine_majority_no(&self) -> bool {
        self.is_byzantine_majority(Ballot::No)
    }

    /// For a root proposal to have a byzantine majority of no, it
    /// needs to collect f + 1 "no" votes, where N s the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    fn is_byzantine_majority_yes(&self) -> bool {
        self.is_byzantine_majority(Ballot::Yes)
    }
}

thread_local! {
  static PROPOSALS: RefCell<Vec<RecoveryProposal>> = const { RefCell::new(Vec::new()) };
}

pub struct NewRecoveryProposal {
    pub payload: RecoveryPayload,
    pub signature: Vec<u8>,
}

pub fn get_recovery_proposals() -> Vec<RecoveryProposal> {
    PROPOSALS.with_borrow(|proposals| proposals.clone())
}

pub fn submit_new_recovery_proposal(new_proposal: NewRecoveryProposal, caller: PrincipalId) {
    let nodes_in_nns = get_node_operators_in_nns();

    // Check if the caller has nodes in nns

    // Check if the proposal of the same type exists
}
