/* tag::catalog[]
end::catalog[] */
use ic_agent::export::Principal;
use ic_agent::{
    identity::{AnonymousIdentity, Secp256k1Identity},
    Identity,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::util::{
    agent_with_identity, block_on, expiry_time, random_ed25519_identity, sign_query, sign_update,
    UniversalCanister,
};
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpRequestEnvelope, HttpUserQuery,
};
use ic_universal_canister::wasm;
use rand::{CryptoRng, Rng};
use slog::{debug, info};

pub fn request_signature_test(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    let rng = &mut reproducible_rng();
    block_on({
        async move {
            let node_url = node.get_public_url();
            debug!(logger, "Selected replica"; "url" => format!("{}", node_url));

            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            debug!(
                logger,
                "Installed Universal Canister";
                "canister_id" => format!("{:?}", canister.canister_id())
            );

            info!(
                logger,
                "Testing valid requests from the anonymous user. Should succeed."
            );
            test_valid_request_succeeds(
                node_url.as_str(),
                AnonymousIdentity,
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing valid requests from an ECDSA identity. Should succeed."
            );
            test_valid_request_succeeds(
                node_url.as_str(),
                random_ecdsa_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing valid requests from an Ed25519 identity. Should succeed."
            );
            test_valid_request_succeeds(
                node_url.as_str(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity but with missing signature. Should fail."
            );
            test_request_with_empty_signature_fails(
                node_url.as_str(),
                random_ecdsa_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with missing signature. Should fail."
            );
            test_request_with_empty_signature_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity signed by an ed25519 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ecdsa_identity(rng),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity signed by an ECDSA identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                random_ecdsa_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity signed by another ed25519 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity signed by another ECDSA identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ecdsa_identity(rng),
                random_ecdsa_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity but with an ed25519 sender. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ecdsa_identity(rng),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with wrong (ECDSA) identity. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                random_ecdsa_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with wrong (ed25519) identity. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity but with wrong (ECDSA) identity. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ecdsa_identity(rng),
                random_ecdsa_identity(rng),
                canister.canister_id(),
            )
            .await;
        }
    });
}

pub fn random_ecdsa_identity<R: Rng + CryptoRng>(rng: &mut R) -> Secp256k1Identity {
    Secp256k1Identity::from_private_key(k256::SecretKey::random(rng))
}

// Test sending a query/update from the anonymous user that returns
// the caller back. Should succeed.
async fn test_valid_request_succeeds<T: Identity + 'static>(
    url: &str,
    identity: T,
    canister_id: Principal,
) {
    let identity_principal = identity.sender().unwrap();
    let agent = agent_with_identity(url, identity).await.unwrap();

    let res = agent
        .query(&canister_id, "query")
        .with_arg(wasm().caller().reply_data_append().reply().build())
        .call()
        .await
        .unwrap();

    assert_eq!(res, identity_principal.as_slice());

    let res = agent
        .update(&canister_id, "update")
        .with_arg(wasm().caller().reply_data_append().reply().build())
        .call_and_wait()
        .await
        .unwrap();

    assert_eq!(res, identity_principal.as_slice());
}

async fn test_request_with_empty_signature_fails<T: Identity + 'static>(
    url: &str,
    identity: T,
    canister_id: Principal,
) {
    // Try a query.
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_query(&content, &identity);

    // Add the public key but not the signature to the envelope. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
        sender_sig: None,
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!("{}api/v2/canister/{}/query", url, canister_id))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);

    // Now try an update.
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature = sign_update(&content, &identity);

    // Add the public key but not the signature to the envelope. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
        sender_sig: None,
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!("{}api/v2/canister/{}/call", url, canister_id))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

async fn test_request_signed_by_another_identity_fails<
    I1: Identity + 'static,
    I2: Identity + 'static,
>(
    url: &str,
    identity1: I1,
    identity2: I2,
    canister_id: Principal,
) {
    // Test a query
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(identity1.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature1 = sign_query(&content, &identity1);
    let signature2 = sign_query(&content, &identity2);

    // Use the public key of identity1 but the signature of identity2. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature1.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature2.signature.unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!("{}api/v2/canister/{}/query", url, canister_id))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);

    // Test an update.
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(identity1.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature1 = sign_update(&content, &identity1);
    let signature2 = sign_update(&content, &identity2);

    // Use the public key of identity1 but the signature of identity2. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature1.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature2.signature.unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!("{}api/v2/canister/{}/call", url, canister_id))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);
}

async fn test_request_with_valid_signature_but_wrong_sender_fails<
    I1: Identity + 'static,
    I2: Identity + 'static,
>(
    url: &str,
    identity1: I1,
    identity2: I2,
    canister_id: Principal,
) {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(identity1.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature2 = sign_query(&content, &identity2);

    // Envelope with signature from `identity2` but sender is `identity1`. Should
    // fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature2.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature2.signature.unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!("{}api/v2/canister/{}/query", url, canister_id))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);

    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm().caller().reply_data_append().reply().build()),
            sender: Blob(identity1.sender().unwrap().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };

    let signature2 = sign_update(&content, &identity2);

    // Envelope with signature from `identity2` but sender is `identity1`. Should
    // fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature2.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature2.signature.unwrap())),
    };
    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(&format!("{}api/v2/canister/{}/call", url, canister_id))
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);
}
