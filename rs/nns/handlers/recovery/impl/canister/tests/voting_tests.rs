use candid::Principal;
use ed25519_dalek::SigningKey;
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryPayload, VoteOnRecoveryProposal},
    security_metadata::SecurityMetadata,
    Ballot,
};

use crate::tests::{
    extract_node_operators_from_init_data, init_pocket_ic, submit_proposal, vote,
    vote_with_only_ballot, NodeOperatorArg, RegistryPreparationArguments,
};

use super::get_pending;

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
fn disallow_votes_bad_signature() {
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

    let response = vote(
        &pic,
        canister,
        first.principal.0.clone(),
        VoteOnRecoveryProposal {
            ballot: Ballot::Yes,
            security_metadata: SecurityMetadata {
                payload: vec![],
                signature: [[0; 32]; 2],
                pub_key: first.signing_key.verifying_key().to_bytes(),
            },
        },
    );
    assert!(response.is_err());

    let response = vote_with_only_ballot(&pic, canister, first, Ballot::Yes);
    assert!(response.is_ok())
}

#[test]
fn disallow_votes_wrong_public_key() {
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

    let pending = get_pending(&pic, canister);
    let last_proposal = pending.last().unwrap();

    let mut new_key_pair = SigningKey::generate(&mut rand::rngs::OsRng);
    let signature = last_proposal.sign(&mut new_key_pair).unwrap();
    let mut parts = [[0; 32]; 2];
    parts[0].copy_from_slice(&signature[..32]);
    parts[1].copy_from_slice(&signature[32..]);

    let response = vote(
        &pic,
        canister,
        first.principal.0.clone(),
        VoteOnRecoveryProposal {
            security_metadata: SecurityMetadata {
                payload: last_proposal
                    .signature_payload()
                    .expect("Should be able to serialize payload"),
                signature: parts,
                pub_key: new_key_pair.verifying_key().to_bytes(),
            },
            ballot: Ballot::Yes,
        },
    );

    assert!(response.is_err())
}

#[test]
fn disallow_votes_anonymous() {
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

    let response = vote(
        &pic,
        canister,
        Principal::anonymous(),
        VoteOnRecoveryProposal {
            security_metadata: SecurityMetadata {
                payload: vec![],
                signature: [[0; 32]; 2],
                pub_key: [0; 32],
            },
            ballot: Ballot::Yes,
        },
    );
    assert!(response.is_err())
}
