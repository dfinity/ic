use std::sync::Arc;

use ic_agent::identity::BasicIdentity;
use ic_ed25519::PrivateKey;
use ic_nns_handler_recovery_interface::{
    recovery::RecoveryPayload,
    signing::{ed25519::EdwardsCurve, Verifier},
    Ballot,
};
use pocket_ic::nonblocking::PocketIc;

use crate::{implementation::RecoveryCanisterImpl, RecoveryCanister};

use super::{
    generate_node_operators, get_ic_agent, init_pocket_ic, preconfigured_recovery_init_args,
};

async fn prepare_client() -> (PocketIc, RecoveryCanisterImpl) {
    let key = PrivateKey::generate();
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

    (pic, client)
}

async fn place_proposal(client: &RecoveryCanisterImpl, payload: RecoveryPayload) {
    let response = client.submit_new_recovery_proposal(payload).await;
    assert!(response.is_ok());
}

async fn place_and_vote_in_proposal(
    client: &RecoveryCanisterImpl,
    payload: RecoveryPayload,
    ballot: Ballot,
) {
    place_proposal(client, payload).await;
    let response = client.vote_on_latest_proposal(ballot).await;
    assert!(response.is_ok())
}

#[tokio::test]
async fn no_proposals() {
    let (_, client) = prepare_client().await;

    let latest_state = client.latest_adopted_state().await;

    assert_eq!(latest_state, RecoveryPayload::Unhalt)
}

#[tokio::test]
async fn placed_proposal_for_halt() {
    let (_, client) = prepare_client().await;

    place_proposal(&client, RecoveryPayload::Halt).await;
    let latest_state = client.latest_adopted_state().await;

    assert_eq!(latest_state, RecoveryPayload::Unhalt)
}

#[tokio::test]
async fn voted_in_halt_proposal() {
    let (_, client) = prepare_client().await;
    place_and_vote_in_proposal(&client, RecoveryPayload::Halt, Ballot::Yes).await;

    let latest_state = client.latest_adopted_state().await;
    assert_eq!(latest_state, RecoveryPayload::Halt);
}

#[tokio::test]
async fn voted_in_recovery() {
    let (_, client) = prepare_client().await;
    place_and_vote_in_proposal(&client, RecoveryPayload::Halt, Ballot::Yes).await;
    let payload = RecoveryPayload::DoRecovery {
        height: 123,
        state_hash: "123".to_string(),
        time_ns: 123,
    };
    place_and_vote_in_proposal(&client, payload.clone(), Ballot::Yes).await;

    let latest_state = client.latest_adopted_state().await;
    assert_eq!(latest_state, payload);
}

#[tokio::test]
async fn voted_in_unhalt() {
    let (_, client) = prepare_client().await;
    place_and_vote_in_proposal(&client, RecoveryPayload::Halt, Ballot::Yes).await;
    place_and_vote_in_proposal(
        &client,
        RecoveryPayload::DoRecovery {
            height: 123,
            state_hash: "123".to_string(),
            time_ns: 123,
        },
        Ballot::Yes,
    )
    .await;
    place_and_vote_in_proposal(&client, RecoveryPayload::Unhalt, Ballot::Yes).await;

    let latest_state = client.latest_adopted_state().await;
    assert_eq!(latest_state, RecoveryPayload::Unhalt);
}
