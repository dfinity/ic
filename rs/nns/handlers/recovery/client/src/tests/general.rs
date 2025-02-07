use std::sync::Arc;

use ed25519_dalek::SigningKey as EdSigningKey;
use ic_agent::identity::{BasicIdentity, Prime256v1Identity};
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryPayload},
    signing::{ed25519::EdwardsCurve, p256::Prime256, Verifier},
    Ballot,
};
use p256::{elliptic_curve::rand_core::OsRng, SecretKey};

use crate::{
    implementation::RecoveryCanisterImpl,
    tests::{generate_node_operators, get_ic_agent, preconfigured_recovery_init_args},
    RecoveryCanister,
};

use super::init_pocket_ic;

#[tokio::test]
async fn can_get_node_operators() {
    let key = EdSigningKey::generate(&mut OsRng);
    let signer = EdwardsCurve::new(key.clone());

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let identity = BasicIdentity::from_signing_key((key.to_bytes()).into());

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    let response = client.get_node_operators_in_nns().await;

    assert!(response.is_ok());
    let current_operators = response.unwrap();
    assert!(current_operators.len().eq(&node_operators_with_keys.len()))
}

#[tokio::test]
async fn can_place_proposals_edwards() {
    let key = EdSigningKey::generate(&mut OsRng);
    let signer = EdwardsCurve::new(key.clone());

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let identity = BasicIdentity::from_signing_key((key.to_bytes()).into());

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    let response = client
        .submit_new_recovery_proposal(NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        })
        .await;

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_place_proposals_prime256() {
    let secret_key = SecretKey::random(&mut OsRng);
    let signing_key = secret_key.clone().into();

    let signer = Prime256::new(signing_key);

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let identity = Prime256v1Identity::from_private_key(secret_key);

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    let response = client
        .submit_new_recovery_proposal(NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        })
        .await;

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_vote_on_proposals_edwards() {
    let key = EdSigningKey::generate(&mut OsRng);
    let signer = EdwardsCurve::new(key.clone());

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let identity = BasicIdentity::from_signing_key((key.to_bytes()).into());

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    client
        .submit_new_recovery_proposal(NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        })
        .await
        .unwrap();

    let response = client.vote_on_latest_proposal(Ballot::Yes).await;
    println!("{:?}", response);

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_vote_on_proposals_prime256() {
    let secret_key = SecretKey::random(&mut OsRng);
    let signing_key = secret_key.clone().into();

    let signer = Prime256::new(signing_key);

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let identity = Prime256v1Identity::from_private_key(secret_key);

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    client
        .submit_new_recovery_proposal(NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        })
        .await
        .unwrap();

    let response = client.vote_on_latest_proposal(Ballot::Yes).await;
    println!("{:?}", response);

    assert!(response.is_ok());
}
