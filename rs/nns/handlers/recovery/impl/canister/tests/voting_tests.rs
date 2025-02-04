use candid::Principal;
use ic_nns_handler_recovery::recovery_proposal::{
    Ballot, NewRecoveryProposal, RecoveryPayload, VoteOnRecoveryProposal,
};

use crate::tests::{
    extract_node_operators_from_init_data, init_pocket_ic, submit_proposal, vote,
    RegistryPreparationArguments,
};

#[test]
fn disallow_double_vote() {
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

    let second = node_operators_iterator.next().unwrap();
    let response = vote(
        &pic,
        canister,
        second.0.clone(),
        VoteOnRecoveryProposal {
            signature: "Not important yet".as_bytes().to_vec(),
            ballot: Ballot::Yes,
        },
    );
    assert!(response.is_ok());

    let response = vote(
        &pic,
        canister,
        second.0.clone(),
        VoteOnRecoveryProposal {
            signature: "Not important yet".as_bytes().to_vec(),
            ballot: Ballot::Yes,
        },
    );
    assert!(response.is_err());
}

#[test]
fn disallow_vote_anonymous() {
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

    let response = vote(
        &pic,
        canister,
        Principal::anonymous(),
        VoteOnRecoveryProposal {
            signature: "Not important yet".as_bytes().to_vec(),
            ballot: Ballot::Yes,
        },
    );
    assert!(response.is_err());
}

#[test]
fn allow_votes_even_if_executed() {
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

    for no in node_operators_iterator {
        let response = vote(
            &pic,
            canister,
            no.0.clone(),
            VoteOnRecoveryProposal {
                signature: "Not important yet".as_bytes().to_vec(),
                ballot: Ballot::Yes,
            },
        );
        assert!(response.is_ok());
    }
}
