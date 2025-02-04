use std::cell::RefCell;

use ic_base_types::PrincipalId;
use ic_nns_handler_recovery_interface::{
    recovery::{
        NewRecoveryProposal, NodeOperatorBallot, RecoveryPayload, RecoveryProposal,
        VoteOnRecoveryProposal,
    },
    security_metadata::SecurityMetadata,
    simple_node_record::SimpleNodeRecord,
    Ballot,
};
use ic_nns_handler_root::now_seconds;

use crate::node_operator_sync::get_node_operators_in_nns;

thread_local! {
  static PROPOSALS: RefCell<Vec<RecoveryProposal>> = const { RefCell::new(Vec::new()) };
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
        .any(|node| node.operator_principal == caller.0)
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
                            proposer: caller.0.clone(),
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
                            proposer: caller.0.clone(),
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
                            proposer: caller.0.clone(),
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

                        proposals.push(RecoveryProposal { proposer: caller.0.clone(), submission_timestamp_seconds: now_seconds(), node_operator_ballots: initialize_ballots(&nodes_in_nns), payload: new_proposal.payload.clone() });
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
                    security_metadata: SecurityMetadata::empty(),
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
        .find(|ballot| ballot.principal.eq(&caller.0))
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
    vote.security_metadata
        .validate_metadata(&caller.0)
        .map_err(|e| e.to_string())?;

    correlated_ballot.ballot = vote.ballot;
    correlated_ballot.security_metadata = vote.security_metadata.clone();

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
