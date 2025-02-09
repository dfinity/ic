use std::sync::Arc;

use ic_agent::identity::{BasicIdentity, Prime256v1Identity, Secp256k1Identity};
use ic_ed25519::PrivateKey as EdwardPrivateKey;
use ic_nns_handler_recovery_interface::{
    recovery::RecoveryPayload,
    signing::{ed25519::EdwardsCurve, k256::Secp256k1, p256::Prime256, Verifier},
    Ballot,
};
use ic_secp256k1::PrivateKey as SecpPrivateKey;
use p256::{elliptic_curve::rand_core::OsRng, SecretKey as p256SecretKey};

use crate::{
    implementation::RecoveryCanisterImpl,
    tests::{generate_node_operators, get_ic_agent, preconfigured_recovery_init_args},
    RecoveryCanister,
};

use super::init_pocket_ic;

#[tokio::test]
async fn can_get_node_operators() {
    let key = EdwardPrivateKey::generate();
    let signer = EdwardsCurve::new(key.clone());

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let pem = key.serialize_pkcs8_pem(ic_ed25519::PrivateKeyFormat::Pkcs8v1);
    let pem = pem.as_bytes();
    let identity = BasicIdentity::from_pem(pem).unwrap();

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
    let key = EdwardPrivateKey::generate();
    let signer = EdwardsCurve::new(key.clone());

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let pem = key.serialize_pkcs8_pem(ic_ed25519::PrivateKeyFormat::Pkcs8v1);
    let pem = pem.as_bytes();
    let identity = BasicIdentity::from_pem(pem).unwrap();

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    let response = client
        .submit_new_recovery_proposal(RecoveryPayload::Halt)
        .await;

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_place_proposals_prime256() {
    let secret_key = p256SecretKey::random(&mut OsRng);
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
        .submit_new_recovery_proposal(RecoveryPayload::Halt)
        .await;

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_place_proposals_secp256() {
    let private_key = SecpPrivateKey::generate();

    let signer = Secp256k1::new(private_key.clone());

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let pem = private_key.serialize_rfc5915_pem();
    let pem = pem.as_bytes();
    let identity = Secp256k1Identity::from_pem(pem).unwrap();

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    let response = client
        .submit_new_recovery_proposal(RecoveryPayload::Halt)
        .await;

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_vote_on_proposals_edwards() {
    let key: EdwardPrivateKey = EdwardPrivateKey::generate();
    let signer = EdwardsCurve::new(key.clone());

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let pem = key.serialize_pkcs8_pem(ic_ed25519::PrivateKeyFormat::Pkcs8v1);
    let pem = pem.as_bytes();
    let identity = BasicIdentity::from_pem(pem).unwrap();

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    client
        .submit_new_recovery_proposal(RecoveryPayload::Halt)
        .await
        .unwrap();

    let response = client.vote_on_latest_proposal(Ballot::Yes).await;
    println!("{:?}", response);

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_vote_on_proposals_prime256() {
    let secret_key = p256SecretKey::random(&mut OsRng);
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
        .submit_new_recovery_proposal(RecoveryPayload::Halt)
        .await
        .unwrap();

    let response = client.vote_on_latest_proposal(Ballot::Yes).await;
    println!("{:?}", response);

    assert!(response.is_ok());
}

#[tokio::test]
async fn can_vote_on_proposals_secp256() {
    let secret_key = SecpPrivateKey::generate();
    let pem = secret_key.serialize_rfc5915_pem();
    let pem = pem.as_bytes();
    let signer = Secp256k1::new(secret_key);

    let node_operators_with_keys =
        generate_node_operators(vec![signer.to_public_key_der().unwrap()]);
    let (pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let identity = Secp256k1Identity::from_pem(pem).unwrap();

    let client = RecoveryCanisterImpl::new(
        get_ic_agent(Box::new(identity), pic.url().unwrap().as_str()).await,
        canister,
        Arc::new(signer),
    );

    client
        .submit_new_recovery_proposal(RecoveryPayload::Halt)
        .await
        .unwrap();

    let response = client.vote_on_latest_proposal(Ballot::Yes).await;
    println!("{:?}", response);

    assert!(response.is_ok());
}
