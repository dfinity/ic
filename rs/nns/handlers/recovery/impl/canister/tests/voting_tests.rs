use candid::Principal;
use ed25519_dalek::{ed25519::signature::SignerMut, pkcs8::EncodePublicKey, SigningKey};
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
                signature: vec![],
                pub_key_der: first
                    .signing_key
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .into_vec(),
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
    let payload = last_proposal
        .signature_payload()
        .expect("Should be able to serialize payload");
    let signature = new_key_pair.sign(&payload);
    let signature = signature.to_vec();

    let response = vote(
        &pic,
        canister,
        first.principal.0.clone(),
        VoteOnRecoveryProposal {
            security_metadata: SecurityMetadata {
                payload,
                signature,
                pub_key_der: new_key_pair
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .into_vec(),
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
            security_metadata: SecurityMetadata::empty(),
            ballot: Ballot::Yes,
        },
    );
    assert!(response.is_err())
}
