use ic_nns_handler_recovery::recovery_proposal::{Ballot, NewRecoveryProposal, RecoveryPayload};

use crate::tests::{
    extract_node_operators_from_init_data, init_pocket_ic, submit_proposal, vote_with_only_ballot,
    NodeOperatorArg, RegistryPreparationArguments,
};

#[test]
fn disallow_double_vote() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let mut node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.iter_mut();
    let first = node_operators_iterator.next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.principal.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );

    assert!(response.is_ok());

    let second = node_operators_iterator.next().unwrap();
    let response = vote_with_only_ballot(&pic, canister, second, Ballot::Yes);
    assert!(response.is_ok());

    let response = vote_with_only_ballot(&pic, canister, second, Ballot::Yes);
    assert!(response.is_err());
}

#[test]
fn disallow_vote_anonymous() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.iter();
    let first = node_operators_iterator.next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.principal.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );

    assert!(response.is_ok());

    let response =
        vote_with_only_ballot(&pic, canister, &mut NodeOperatorArg::new(10), Ballot::Yes);
    assert!(response.is_err());
}

#[test]
fn allow_votes_even_if_executed() {
    let mut args = RegistryPreparationArguments::default();
    let (pic, canister) = init_pocket_ic(&mut args);

    let mut node_operators = extract_node_operators_from_init_data(&args);
    let mut node_operators_iterator = node_operators.iter_mut();
    let first = node_operators_iterator.next().unwrap();

    let response = submit_proposal(
        &pic,
        canister,
        first.principal.0.clone(),
        NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        },
    );

    assert!(response.is_ok());

    for no in node_operators_iterator {
        let response = vote_with_only_ballot(&pic, canister, no, Ballot::Yes);
        assert!(response.is_ok());
    }
}

#[test]
fn disallow_votes_bad_signature() {}
