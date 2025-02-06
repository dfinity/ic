use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryPayload},
    Ballot, VerifyIntegirty,
};

use crate::{
    tests::{generate_node_operators, preconfigured_recovery_init_args},
    RecoveryCanister,
};

use super::{get_client, init_pocket_ic};

#[tokio::test]
async fn can_get_node_operators() {
    let node_operators_with_keys = generate_node_operators();
    let (mut pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;
    let client = get_client(&mut pic, canister).await;

    let response = client.get_node_operators_in_nns().await;

    assert!(response.is_ok());
    let current_operators = response.unwrap();
    assert!(current_operators.len().eq(&node_operators_with_keys.len()))
}

#[tokio::test]
async fn can_place_proposals() {
    let node_operators_with_keys = generate_node_operators();
    let (mut pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let mut node_operator_iter = node_operators_with_keys.iter();
    let first = node_operator_iter.next().unwrap();
    let first_client = first
        .into_recovery_canister_client(&mut pic, canister)
        .await;

    let response = first_client
        .submit_new_recovery_proposal(NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        })
        .await;

    println!("{:?}", response);
    assert!(response.is_ok());
}

#[tokio::test]
async fn can_vote_on_proposals() {
    let node_operators_with_keys = generate_node_operators();
    let (mut pic, canister) =
        init_pocket_ic(preconfigured_recovery_init_args(&node_operators_with_keys)).await;

    let mut node_operator_iter = node_operators_with_keys.iter();
    let first = node_operator_iter.next().unwrap();
    let mut first_client = first
        .into_recovery_canister_client(&mut pic, canister)
        .await;

    first_client
        .submit_new_recovery_proposal(NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        })
        .await
        .unwrap();

    let response = first_client.vote_on_latest_proposal(Ballot::Yes).await;
    assert!(response.is_ok());

    let latest = first_client.get_pending_recovery_proposals().await.unwrap();
    assert!(latest.iter().verify().is_ok())
}
