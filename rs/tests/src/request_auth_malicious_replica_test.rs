/* tag::catalog[]
Title:: Malicious replica injects messages with faulty authentication into
block proposals.

Goal:: All such blocks should be flagged as invalid and rejected by the
notaries.

Runbook::
. Create subnet with one malicious and three honest replicas.
. Install a universal canister.
. Let the malicious replica make blocks that contain update calls to store random bytes in the canister's memory, but have bogus authentication (for completeness, this is checked for Ed25519 and ECDSA signature schemes):
.. Public key and signatures are both missing
.. Sender principal and public key match, but signature is wrong
.. Sender principal and signature match, but public key is wrong
.. Signature is correct for specified public key, but sender principal does not match public key.
.. Correct signature and public key, but request is expired.
.. Authentication uses key delegation, all signatures are correct, but delegation is expired.
.. Authentication uses key delegation, all signatures are correct, but canister is not in scope of the delegation.
. Query the canister's memory on all honest nodes.

Success::
After a complete run, the network is still live and the canister's memory still has the initial value.

Coverage::
Authentication checks in block validation.
end::catalog[] */

use crate::request_signature_test::{expiry_time, random_ecdsa_identity, sign_update};
use crate::util::*;
use ic_agent::export::Principal;
use ic_agent::{agent::status::Value, Identity};
use ic_fondue::log::info;
use ic_fondue::{
    ic_manager::{IcEndpoint, IcHandle},
    internet_computer::{InternetComputer, Subnet},
};
use ic_registry_subnet_type::SubnetType;
use ic_types::crypto::SignedBytesWithoutDomainSeparator;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::messages::{
    Blob, Delegation, HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent, SignedDelegation,
};
use ic_types::{CanisterId, Time};
use ic_universal_canister::wasm;
use std::convert::TryFrom;
use url::Url;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .add_nodes(3)
            .add_malicious_nodes(
                1,
                MaliciousBehaviour::new(true).set_maliciously_disable_ingress_validation(),
            ),
    )
}

pub fn test(mut handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let malicious_node = handle
                .take_one_malicious(&mut rng)
                .expect("Not enough malicious nodes");
            malicious_node.assert_ready(ctx).await;

            let identity = random_ed25519_identity();

            let agent = agent_with_identity(malicious_node.url.as_str(), identity)
                .await
                .unwrap();

            // System tests do not automatically wait for malicious nodes to be healthy,
            // so we have to manually wait for it to be healthy.
            loop {
                let status = agent.status().await.unwrap();

                if let Value::String(health_status) =
                    &**(status.values.get("replica_health_status").unwrap())
                {
                    if health_status.as_str() == "healthy" {
                        // Node is ready.
                        break;
                    }
                }

                // Wait a bit and check the status again.
                info!(
                    ctx.logger,
                    "Malicious node not yet ready. Checking again in a bit..."
                );
                std::thread::sleep(std::time::Duration::from_secs(2));
            }

            let canister = UniversalCanister::new(&agent).await;

            // Set some random data in the canister's memory.
            agent
                .update(&canister.canister_id(), "update")
                .with_arg(wasm().set_global_data(&[1, 2, 3]).reply())
                .call_and_wait(delay())
                .await
                .unwrap();

            // The previous request is valid, so the memory should be updated.
            assert_eq!(
                canister
                    .query(wasm().get_global_data().append_and_reply())
                    .await,
                Ok(vec![1, 2, 3])
            );

            // Send different types of invalid requests to update the canister's memory.
            play_malicious_requests(
                random_ed25519_identity(),
                &malicious_node,
                canister.canister_id(),
            )
            .await;

            play_malicious_requests(
                random_ecdsa_identity(),
                &malicious_node,
                canister.canister_id(),
            )
            .await;

            // Wait for all the requests to be gossiped to the honest nodes. `read_state`
            // cannot be used here because these requests are never executed to begin with.

            std::thread::sleep(std::time::Duration::from_secs(30));

            // Query all the honest nodes and verify that the memory is unchanged.
            let honest_nodes = vec![
                handle.take_one(&mut rng).unwrap(),
                handle.take_one(&mut rng).unwrap(),
                handle.take_one(&mut rng).unwrap(),
            ];

            for node in &honest_nodes {
                node.assert_ready(ctx).await;
                let agent = assert_create_agent(node.url.as_str()).await;

                assert_eq!(
                    agent
                        .query(&canister.canister_id(), "query")
                        .with_arg(wasm().get_global_data().append_and_reply().build())
                        .call()
                        .await,
                    Ok(vec![1, 2, 3]) // Data is unchanged.
                );
            }

            // To verify that our implementation is correct, let's try sending a valid
            // request to an honest node. The canister's memory should then be
            // updated.
            test_request_with_delegation(
                &random_ed25519_identity(),
                &honest_nodes[0].url,
                canister.canister_id(),
                expiry_time().as_nanos() as u64,
                Some(vec![canister.canister_id()]),
            )
            .await;

            std::thread::sleep(std::time::Duration::from_secs(30));

            // Query all the honest nodes and verify that the memory has been updated.
            for node in honest_nodes {
                let agent = assert_create_agent(node.url.as_str()).await;

                assert_eq!(
                    agent
                        .query(&canister.canister_id(), "query")
                        .with_arg(wasm().get_global_data().append_and_reply().build())
                        .call()
                        .await,
                    Ok(vec![4, 5, 6])
                );
            }
        }
    });
}

async fn play_malicious_requests<T: Identity + 'static>(
    identity: T,
    malicious_node: &IcEndpoint,
    canister_id: Principal,
) {
    test_request_with_no_signature_and_no_pubkey(&identity, malicious_node, canister_id).await;

    test_request_with_correct_signature_and_incorrect_pubkey(
        &identity,
        malicious_node,
        canister_id,
    )
    .await;

    test_request_with_incorrect_signature_and_correct_pubkey(
        &identity,
        malicious_node,
        canister_id,
    )
    .await;

    test_request_with_incorrect_sender(&identity, malicious_node, canister_id).await;

    test_request_with_expired_ingress(&identity, malicious_node, canister_id).await;

    test_request_with_delegation(
        &identity,
        &malicious_node.url,
        canister_id,
        0,    // wrong expiry
        None, // no delegation targets (all canisters allowed)
    )
    .await;

    test_request_with_delegation(
        &identity,
        &malicious_node.url,
        canister_id,
        expiry_time().as_nanos() as u64, // valid expiration
        Some(vec![Principal::management_canister()]), // wrong target
    )
    .await;
}

async fn test_request_with_no_signature_and_no_pubkey<T: Identity + 'static>(
    identity: &T,
    malicious_node: &IcEndpoint,
    canister_id: Principal,
) {
    // An update call to set the global data to [4, 5, 6].
    let content = HttpSubmitContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().set_global_data(&[4, 5, 6]).reply().build()),
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    // No public key or signature in the envelope.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: None,
        sender_sig: None,
    };

    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/call",
            malicious_node.url,
            canister_id.to_text()
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    // Even though the request is invalid, the malicious node accepts it.
    assert_eq!(res.status(), 202);
}

async fn test_request_with_correct_signature_and_incorrect_pubkey<T: Identity + 'static>(
    identity: &T,
    malicious_node: &IcEndpoint,
    canister_id: Principal,
) {
    let wrong_identity = random_ed25519_identity();

    // An update call to set the global data to [4, 5, 6].
    let content = HttpSubmitContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().set_global_data(&[4, 5, 6]).reply().build()),
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_update(&content, identity);
    let wrong_signature = sign_update(&content, &wrong_identity);

    // Add the correct public key but the wrong public key
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_sig: Some(Blob(signature.signature.unwrap())),
        sender_pubkey: Some(Blob(wrong_signature.public_key.clone().unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/call",
            malicious_node.url,
            canister_id.to_text()
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    // Even though the request is invalid, the malicious node accepts it.
    assert_eq!(res.status(), 202);
}

async fn test_request_with_incorrect_signature_and_correct_pubkey<T: Identity + 'static>(
    identity: &T,
    malicious_node: &IcEndpoint,
    canister_id: Principal,
) {
    let wrong_identity = random_ed25519_identity();

    // An update call to set the global data to [4, 5, 6].
    let content = HttpSubmitContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().set_global_data(&[4, 5, 6]).reply().build()),
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_update(&content, identity);
    let wrong_signature = sign_update(&content, &wrong_identity);

    // Add the wrong signature but the right public key.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_sig: Some(Blob(wrong_signature.signature.unwrap())),
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/call",
            malicious_node.url,
            canister_id.to_text()
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    // Even though the request is invalid, the malicious node accepts it.
    assert_eq!(res.status(), 202);
}

async fn test_request_with_incorrect_sender<T: Identity + 'static>(
    identity: &T,
    malicious_node: &IcEndpoint,
    canister_id: Principal,
) {
    let wrong_identity = random_ed25519_identity();

    // An update call to set the global data to [4, 5, 6].
    let content = HttpSubmitContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().set_global_data(&[4, 5, 6]).reply().build()),
            sender: Blob(wrong_identity.sender().unwrap().as_slice().to_vec()), // wrong sender
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_update(&content, identity);

    // Create an envelope with a correct signature.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_sig: Some(Blob(signature.signature.unwrap())),
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/call",
            malicious_node.url,
            canister_id.to_text()
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    // Even though the request is invalid, the malicious node accepts it.
    assert_eq!(res.status(), 202);
}

async fn test_request_with_expired_ingress<T: Identity + 'static>(
    identity: &T,
    malicious_node: &IcEndpoint,
    canister_id: Principal,
) {
    // An update call to set the global data to [4, 5, 6].
    let content = HttpSubmitContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().set_global_data(&[4, 5, 6]).reply().build()),
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: 0,
            nonce: None,
        },
    };

    let signature = sign_update(&content, identity);

    // Add the correct public key but the wrong public key
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_sig: Some(Blob(signature.signature.unwrap())),
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/call",
            malicious_node.url,
            canister_id.to_text()
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    // Even though the request is invalid, the malicious node accepts it.
    assert_eq!(res.status(), 202);
}

async fn test_request_with_delegation<T: Identity + 'static>(
    identity: &T,
    node_url: &Url,
    canister_id: Principal,
    delegation_expiry: u64,
    delegation_targets: Option<Vec<Principal>>,
) {
    let identity2 = random_ed25519_identity();

    // An update call to set the global data to [4, 5, 6].
    let content = HttpSubmitContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().set_global_data(&[4, 5, 6]).reply().build()),
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_update(&content, &identity2);

    // A delegation from identity to identity2 for the specific canister ID.
    let delegation = match delegation_targets {
        Some(targets) => {
            Delegation::new_with_targets(
                signature.public_key.clone().unwrap(), // public key of identity2
                Time::from_nanos_since_unix_epoch(delegation_expiry),
                targets
                    .into_iter()
                    .map(|principal| CanisterId::try_from(principal.as_slice()).unwrap())
                    .collect(),
            )
        }
        None => {
            Delegation::new(
                signature.public_key.clone().unwrap(), // public key of identity2
                Time::from_nanos_since_unix_epoch(delegation_expiry),
            )
        }
    };

    let signed_delegation = sign_delegation(delegation, identity);

    let public_key_identity = { identity.sign(&[]).unwrap().public_key.unwrap() };

    // Add the correct public key but the wrong public key
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: Some(vec![signed_delegation]),
        sender_sig: Some(Blob(signature.signature.unwrap())),
        sender_pubkey: Some(Blob(public_key_identity)),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!(
            "{}api/v2/canister/{}/call",
            node_url,
            canister_id.to_text()
        ))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    // Even though the request can be invalid, the node should accepts it, since we
    // only send invalid requests to malicious nodes, which accept all requests.
    assert_eq!(res.status(), 202);
}

fn sign_delegation(delegation: Delegation, identity: &impl Identity) -> SignedDelegation {
    let mut msg = b"\x1Aic-request-auth-delegation".to_vec();
    msg.extend(&delegation.as_signed_bytes_without_domain_separator());
    let signature = identity.sign(&msg).unwrap();

    SignedDelegation::new(delegation, signature.signature.unwrap())
}
