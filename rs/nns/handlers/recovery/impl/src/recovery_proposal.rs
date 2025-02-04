use std::cell::RefCell;

use candid::CandidType;
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
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
    pub signature: [[u8; 32]; 2],
    pub payload: Vec<u8>,
    pub pub_key: [u8; 32],
}

// struct {
//     pub pub_key: 32 bytes,
//     pub proposal_type: &str,
//     pub payload: Vec<u8>,
//     pub signature: 64 bytes
// }

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
    pub fn sign(&self, signing_key: &mut SigningKey) -> [u8; 64] {
        let signature = signing_key.sign(
            &self
                .signature_payload()
                .expect("Should be able to encode recovery proposal"),
        );
        signature.to_bytes()
    }

    pub fn signature_payload(&self) -> Result<Vec<u8>, candid::Error> {
        let self_without_ballots = Self {
            node_operator_ballots: vec![],
            ..self.clone()
        };
        candid::encode_one(self_without_ballots)
    }
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
}

#[derive(Debug, CandidType, Deserialize, Clone)]
pub struct VoteOnRecoveryProposal {
    pub payload: Vec<u8>,
    pub signature: [[u8; 32]; 2],
    pub public_key: [u8; 32],

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
                if !second_proposal.is_byzantine_majority_yes() {
                    let message =
                        format!("Can't submit a proposal until the previous is decided");
                    ic_cdk::println!("{}", message);
                    return Err(message);
                }
                match (&second_proposal.payload, &new_proposal.payload) {
                    (
                        RecoveryPayload::DoRecovery {
                            height: _,
                            state_hash: _,
                        },
                        RecoveryPayload::Unhalt,
                    ) => {
                        proposals.push(RecoveryProposal {
                            proposer: caller,
                            submission_timestamp_seconds: now_seconds(),
                            node_operator_ballots: initialize_ballots(&nodes_in_nns),
                            payload: RecoveryPayload::Unhalt,
                        });
                    },
                    // Allow submitting a new recovery proposal only if the current one
                    // is voted in. This could happen if the recovery from this proposal
                    // failed and we need to submit a new one with different args.
                    (RecoveryPayload::DoRecovery { height: _, state_hash: _ }, RecoveryPayload::DoRecovery { height: _, state_hash: _ }) => {
                        // Remove the second_one
                        proposals.pop();

                        proposals.push(RecoveryProposal { proposer: caller, submission_timestamp_seconds: now_seconds(), node_operator_ballots: initialize_ballots(&nodes_in_nns), payload: new_proposal.payload.clone() });
                    },
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
        Ok(())
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
                    signature: [[0; 32]; 2],
                    payload: vec![],
                    pub_key: [0; 32],
                }),
            }
            acc
        })
}

pub fn vote_on_proposal_inner(
    caller: PrincipalId,
    vote: VoteOnRecoveryProposal,
) -> Result<(), String> {
    PROPOSALS.with_borrow_mut(|proposals| vote_on_last_proposal(caller, proposals, vote))
}

fn vote_on_last_proposal(
    caller: PrincipalId,
    proposals: &mut Vec<RecoveryProposal>,
    vote: VoteOnRecoveryProposal,
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

    // Ensure that the payload can be deserialized in last proposal
    // This ensures that the versions match

    // Ensure that the signature is valid
    is_valid_signature(&caller, &vote.public_key, &vote.signature, &vote.payload)?;

    correlated_ballot.ballot = vote.ballot;
    correlated_ballot.signature = vote.signature;
    correlated_ballot.payload = vote.payload;
    correlated_ballot.pub_key = vote.public_key;

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

fn is_valid_signature(
    caller: &PrincipalId,
    pub_key: &[u8; 32],
    submitted_signature: &[[u8; 32]; 2],
    raw_payload: &Vec<u8>,
) -> Result<(), String> {
    let principal_from_pub_key = PrincipalId::new_self_authenticating(pub_key.as_slice());
    if !principal_from_pub_key.eq(caller) {
        return Err("Caller and public key sent differ!".to_string());
    }

    let loaded_public_key = ed25519_dalek::VerifyingKey::from_bytes(pub_key)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;
    let signature = ed25519_dalek::Signature::from_slice(submitted_signature.as_flattened())
        .map_err(|e| format!("Invalid signature: {:?}", e))?;

    loaded_public_key
        .verify_strict(&raw_payload, &signature)
        .map_err(|e| format!("Signature not doesn't match: {:?}", e))
}
