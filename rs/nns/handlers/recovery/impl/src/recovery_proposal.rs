use std::cell::RefCell;

use candid::CandidType;
use ic_base_types::{NodeId, PrincipalId};
use ic_nns_handler_root::now_seconds;
use serde::Deserialize;

use crate::node_operator_sync::{get_node_operators_in_nns, SimpleNodeRecord};

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

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
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
    pub fn is_byzantine_majority_no(&self) -> bool {
        self.is_byzantine_majority(Ballot::No)
    }

    /// For a root proposal to have a byzantine majority of no, it
    /// needs to collect f + 1 "no" votes, where N s the total number
    /// of nodes (same as the number of ballots) and f = (N - 1) / 3.
    pub fn is_byzantine_majority_yes(&self) -> bool {
        self.is_byzantine_majority(Ballot::Yes)
    }
}

thread_local! {
  static PROPOSALS: RefCell<Vec<RecoveryProposal>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, CandidType, Deserialize, Clone)]
pub struct NewRecoveryProposal {
    pub payload: RecoveryPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, CandidType, Deserialize, Clone)]
pub struct VoteOnRecoveryProposal {
    pub signature: Vec<u8>,
    pub ballot: Ballot,
}

pub fn get_recovery_proposals() -> Vec<RecoveryProposal> {
    PROPOSALS.with_borrow(|proposals| proposals.clone())
}

pub fn submit_recovery_proposal(
    new_proposal: NewRecoveryProposal,
    caller: PrincipalId,
) -> Result<(), String> {
    let nodes_in_nns = get_node_operators_in_nns();

    // Check if the caller has nodes in nns
    if !nodes_in_nns
        .iter()
        .any(|node| node.operator_principal == caller)
    {
        let message = format!(
            "Caller: {} is not eligible to submit proposals to this canister",
            caller
        );
        ic_cdk::println!("{}", message);
        return Err(message);
    }

    PROPOSALS.with_borrow_mut(|proposals| {
        match proposals.len() {
            0 => {
                // There is no proposals currently and the only possible proposal to be placed is
                // HALT NNS Subnet
                match &new_proposal.payload {
                    RecoveryPayload::Halt => {
                        proposals.push(RecoveryProposal {
                            proposer: caller,
                            submission_timestamp_seconds: now_seconds(),
                            node_operator_ballots: initialize_ballots(&nodes_in_nns),
                            payload: RecoveryPayload::Halt,
                        });
                    }
                    _ => {
                        let message = format!(
                            "Caller {} tried to place proposal {:?} which is currently not allowed",
                            caller, new_proposal
                        );
                        ic_cdk::println!("{}", message);
                        return Err(message);
                    }
                }
            }
            1 => {
                // The only possible previous proposal is a proposal to HALT NNS subnet
                // Ensure that previous proposal is voted in
                let first = proposals.first().expect("Must have at least one proposal");

                // No need to check if it is a majority no because it will be removed if it is
                if !first.is_byzantine_majority_yes() {
                    let message = format!("Can't submit a proposal until the previous is decided");
                    ic_cdk::println!("{}", message);
                    return Err(message);
                }

                // Its possible to either request recovery or unhalt the nns subnet if the issues
                // self corrected
                match &new_proposal.payload {
                    RecoveryPayload::DoRecovery {
                        height: _,
                        state_hash: _,
                    }
                    | RecoveryPayload::Unhalt => {
                        proposals.push(RecoveryProposal {
                            proposer: caller,
                            submission_timestamp_seconds: now_seconds(),
                            node_operator_ballots: initialize_ballots(&nodes_in_nns),
                            payload: new_proposal.payload.clone(),
                        });
                    }
                    _ => {
                        let message = format!(
                            "Caller {} tried to place proposal {:?} which is currently not allowed",
                            caller, new_proposal
                        );
                        ic_cdk::println!("{}", message);
                        return Err(message);
                    }
                }
            }
            2 => {
                // There are two previous options:
                //     1. Recovery - if this is previous proposal allow placing of the next only if it is voted in
                //     2. Unhalt - if this is previous proposal don't allow placing new proposal
                let second_proposal = proposals.get(1).expect("Must have at least two proposals");
                match (&second_proposal.payload, &new_proposal.payload) {
                    (
                        RecoveryPayload::DoRecovery {
                            height: _,
                            state_hash: _,
                        },
                        RecoveryPayload::Unhalt,
                    ) => {
                        if !second_proposal.is_byzantine_majority_yes() {
                            let message =
                                format!("Can't submit a proposal until the previous is decided");
                            ic_cdk::println!("{}", message);
                            return Err(message);
                        }
                        proposals.push(RecoveryProposal {
                            proposer: caller,
                            submission_timestamp_seconds: now_seconds(),
                            node_operator_ballots: initialize_ballots(&nodes_in_nns),
                            payload: RecoveryPayload::Unhalt,
                        });
                    }
                    (_, _) => {
                        let message = format!(
                            "Caller {} tried to place proposal {:?} which is currently not allowed",
                            caller, new_proposal
                        );
                        ic_cdk::println!("{}", message);
                        return Err(message);
                    }
                }
            }
            3 => {
                // Already submited all three proposals.
                let message = format!(
                    "Caller {} tried to place proposal {:?} which is currently not allowed",
                    caller, new_proposal
                );
                ic_cdk::println!("{}", message);
                return Err(message);
            }
            _ => unreachable!(
                "There is an error in the logic since its not possible to have more than 3 proposals"
            ),
        }
        vote_on_last_proposal(caller, proposals, Ballot::Yes, new_proposal.signature)
    })
}

fn initialize_ballots(simple_node_records: &Vec<SimpleNodeRecord>) -> Vec<NodeOperatorBallot> {
    simple_node_records
        .iter()
        .fold(Vec::new(), |mut acc, next| {
            match acc
                .iter_mut()
                .find(|operator_ballot| operator_ballot.principal == next.operator_principal)
            {
                Some(existing_ballot) => {
                    existing_ballot
                        .nodes_tied_to_ballot
                        .push(next.node_principal);
                }
                None => acc.push(NodeOperatorBallot {
                    principal: next.operator_principal,
                    nodes_tied_to_ballot: vec![next.node_principal],
                    ballot: Ballot::Undecided,
                    signature: vec![],
                }),
            }
            acc
        })
}

pub fn vote_on_proposal_inner(
    caller: PrincipalId,
    ballot: Ballot,
    signature: Vec<u8>,
) -> Result<(), String> {
    PROPOSALS
        .with_borrow_mut(|proposals| vote_on_last_proposal(caller, proposals, ballot, signature))
}

fn vote_on_last_proposal(
    caller: PrincipalId,
    proposals: &mut Vec<RecoveryProposal>,
    ballot: Ballot,
    signature: Vec<u8>,
) -> Result<(), String> {
    let last_proposal = proposals
        .last_mut()
        .ok_or(format!("There are no proposals"))?;

    let correlated_ballot = last_proposal
        .node_operator_ballots
        .iter_mut()
        .find(|ballot| ballot.principal.eq(&caller))
        .ok_or(format!(
            "Caller {} is not eligible to vote on this proposal",
            caller
        ))?;

    if correlated_ballot.ballot != Ballot::Undecided {
        return Err("Vote already submitted".to_string());
    }

    correlated_ballot.ballot = ballot;
    correlated_ballot.signature = signature;

    // If the outcome is no, remove this proposal
    if last_proposal.is_byzantine_majority_no() {
        proposals.pop();
    } else if last_proposal.is_byzantine_majority_yes() {
        if let RecoveryPayload::Unhalt = last_proposal.payload {
            proposals.clear();
        }
    }

    Ok(())
}
