use candid::Principal;
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryPayload, RecoveryProposal, VoteOnRecoveryProposal},
    recovery_init::RecoveryInitArgs,
    security_metadata::SecurityMetadata,
    simple_node_operator_record::SimpleNodeOperatorRecord,
    Ballot, VerifyIntegirty,
};
use p256::{
    ecdsa::{self, signature::SignerMut, SigningKey},
    elliptic_curve::{rand_core::OsRng, SecretKey},
    pkcs8::EncodePublicKey,
    NistP256,
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
    assert!(latest.iter().verify_integrity().is_ok())
}

#[tokio::test]
async fn can_use_prime256_keys() {
    let new_key_pair: SecretKey<NistP256> = SecretKey::random(&mut OsRng);
    let pub_key = new_key_pair.public_key();
    let node_operator = SimpleNodeOperatorRecord {
        operator_id: Principal::self_authenticating(pub_key.to_public_key_der().unwrap()),
        nodes: vec![Principal::anonymous()],
    };

    let (pic, canister) = init_pocket_ic(RecoveryInitArgs {
        initial_node_operator_records: vec![node_operator.clone()],
    })
    .await;

    pic.update_call(
        canister,
        node_operator.operator_id,
        "submit_new_recovery_proposal",
        candid::encode_one(NewRecoveryProposal {
            payload: RecoveryPayload::Halt,
        })
        .unwrap(),
    )
    .await
    .unwrap();

    let pending = pic
        .query_call(
            canister,
            Principal::anonymous(),
            "get_pending_recovery_proposals",
            candid::encode_one(()).unwrap(),
        )
        .await
        .unwrap();

    let pending: Vec<RecoveryProposal> = candid::decode_one(&pending).unwrap();
    let last = pending.last().unwrap();

    let mut signing_key: SigningKey = new_key_pair.into();
    let signature: ecdsa::Signature = signing_key
        .try_sign(&last.signature_payload().unwrap())
        .unwrap();

    let mut r = [0; 32];
    let mut s = [0; 32];
    r.copy_from_slice(&signature.r().as_ref().to_bytes());
    s.copy_from_slice(&signature.s().as_ref().to_bytes());

    let response = pic
        .update_call(
            canister,
            node_operator.operator_id,
            "vote_on_proposal",
            candid::encode_one(VoteOnRecoveryProposal {
                security_metadata: SecurityMetadata {
                    signature: [r, s],
                    payload: last.signature_payload().unwrap(),
                    pub_key_der: pub_key.to_public_key_der().unwrap().into_vec(),
                },
                ballot: Ballot::Yes,
            })
            .unwrap(),
        )
        .await;

    assert!(response.is_ok())
}
