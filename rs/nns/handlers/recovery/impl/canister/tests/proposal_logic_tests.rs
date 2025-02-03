use candid::Principal;
use ic_nns_handler_recovery::recovery_proposal::{
    Ballot, NewRecoveryProposal, RecoveryPayload, VoteOnRecoveryProposal,
};
use ic_registry_subnet_type::SubnetType;

use crate::tests::{get_pending, vote};

use super::{
    extract_node_operators_from_init_data, init_pocket_ic, submit_proposal,
    RegistryPreparationArguments,
};

// First proposal tests

#[test]
fn place_first_proposal() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let first = node_operators.keys().next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
            signature: "Not important yet".as_bytes().to_vec(),
        },
    );

    assert!(response.is_ok());

    let pending_proposals = get_pending(&pic, canister);

    assert!(pending_proposals.len().eq(&1));
    let only_proposal = pending_proposals.first().unwrap();

    let registered_votes: Vec<_> = only_proposal
        .node_operator_ballots
        .iter()
        .filter(|ballot| ballot.ballot != Ballot::Undecided)
        .collect();

    assert!(registered_votes.len().eq(&1));

    let only_vote = registered_votes.first().unwrap();
    assert_eq!(only_vote.ballot, Ballot::Yes);

    let number_of_nodes_for_first = node_operators.get(first).unwrap();
    assert!(only_vote
        .nodes_tied_to_ballot
        .len()
        .eq(&(*number_of_nodes_for_first as usize)));
    assert_eq!(&only_vote.principal, first)
}

#[test]
fn place_non_halt_first_proposal() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let first = node_operators.keys().next().unwrap();

    let invalid_first_proposals = vec![
        NewRecoveryProposal {
            payload: RecoveryPayload::DoRecovery {
                height: 123,
                state_hash: "123".to_string(),
            },
            signature: "Not important yet".as_bytes().to_vec(),
        },
        NewRecoveryProposal {
            payload: RecoveryPayload::Unhalt,
            signature: "Not important yet".as_bytes().to_vec(),
        },
    ];

    for proposal in invalid_first_proposals {
        let response = submit_proposal(&pic, canister, first.0.clone(), proposal);

        assert!(response.is_err());
        let pending_proposals = get_pending(&pic, canister);
        assert!(pending_proposals.is_empty());
    }
}

#[test]
fn replace_first_proposal_after_voting_no_on_the_first() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.keys();
    let first = node_operators_iterator.next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
            signature: "Not important yet".as_bytes().to_vec(),
        },
    );
    assert!(response.is_ok());

    // Try resubmitting
    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
            signature: "Not important yet".as_bytes().to_vec(),
        },
    );
    assert!(response.is_err());

    // To achieve byzantine majority in default setup 7
    // node operators should vote "no"
    // This will remove the proposal
    for _ in 0..7 {
        let next = node_operators_iterator.next().unwrap();

        let response = vote(
            &pic,
            canister,
            next.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::No,
            },
        );

        assert!(response.is_ok());
    }

    // Resubmit
    let response = submit_proposal(
        &pic,
        canister,
        first.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
            signature: "Not important yet".as_bytes().to_vec(),
        },
    );
    assert!(response.is_ok());
}

#[test]
fn disallow_unknown_node_operators_from_placing_proposals() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let response = submit_proposal(
        &pic,
        canister,
        Principal::anonymous(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
            signature: "Not important yet".as_bytes().to_vec(),
        },
    );
    assert!(response.is_err());
}

#[test]
fn disallow_node_operators_from_different_subnets_from_placing_proposals() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let non_system_subnet = args
        .subnet_node_operators
        .iter()
        .find_map(|subnet| match !subnet.subnet_type.eq(&SubnetType::System) {
            false => None,
            true => Some(subnet.node_operators.clone()),
        })
        .unwrap();
    let first_node_operator = non_system_subnet.keys().next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first_node_operator.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
            signature: "Not important yet".as_bytes().to_vec(),
        },
    );
    assert!(response.is_err());
}
// Second proposal tests

// Third proposal tests

// Nth proposal tests
