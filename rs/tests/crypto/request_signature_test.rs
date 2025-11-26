/* tag::catalog[]
end::catalog[] */
use anyhow::Result;
use ic_agent::export::Principal;
use ic_agent::{
    Identity,
    identity::{AnonymousIdentity, Prime256v1Identity, Secp256k1Identity},
};
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    UniversalCanister, agent_with_identity, block_on, expiry_time, random_ed25519_identity,
    sign_query, sign_read_state, sign_update,
};
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
    HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery,
};
use ic_universal_canister::wasm;
use rand::{CryptoRng, Rng};
use slog::{debug, info};

const ALL_QUERY_API_VERSIONS: &[u8] = &[2, 3];
const ALL_UPDATE_API_VERSIONS: &[u8] = &[2, 3, 4];
const ALL_READ_STATE_API_VERSIONS: &[u8] = &[2, 3];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(request_signature_test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

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
                "Testing valid requests from an ECDSA secp256k1 identity. Should succeed."
            );
            test_valid_request_succeeds(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing valid requests from an ECDSA secp256r1 identity. Should succeed."
            );
            test_valid_request_succeeds(
                node_url.as_str(),
                random_ecdsa_secp256r1_identity(rng),
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
                "Testing request from an ECDSA secp256k1 identity but with missing signature. Should fail."
            );
            test_request_with_empty_signature_fails(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA secp256r1 identity but with missing signature. Should fail."
            );
            test_request_with_empty_signature_fails(
                node_url.as_str(),
                random_ecdsa_secp256r1_identity(rng),
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
                "Testing request from an ECDSA secp256k1 identity signed by an ed25519 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA secp256r1 identity signed by an ed25519 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ecdsa_secp256r1_identity(rng),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity signed by an ECDSA secp256k1 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                random_ecdsa_secp256k1_identity(rng),
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
                "Testing request from an ECDSA secp256k1 identity signed by another ECDSA secp256k1 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                random_ecdsa_secp256k1_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA secp256k1 identity but with an ed25519 sender. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA secp256r1 identity but with an ed25519 sender. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ecdsa_secp256r1_identity(rng),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with wrong (ECDSA secp256k1) identity. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                random_ecdsa_secp256k1_identity(rng),
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
                "Testing request from an ECDSA secp256k1 identity but with wrong (ECDSA secp256k1) identity. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                random_ecdsa_secp256k1_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA secp256k1 identity but with empty domain separator. Should fail."
            );
            test_request_with_empty_domain_separator_fails(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA secp256r1 identity but with empty domain separator. Should fail."
            );
            test_request_with_empty_domain_separator_fails(
                node_url.as_str(),
                random_ecdsa_secp256r1_identity(rng),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with empty domain separator. Should fail."
            );
            test_request_with_empty_domain_separator_fails(
                node_url.as_str(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request with invalid signature. Should fail."
            );
            test_request_with_invalid_signature_fails(
                node_url.as_str(),
                random_ecdsa_secp256k1_identity(rng),
                canister.canister_id(),
                rng,
            )
            .await;
        }
    });
}

pub fn random_ecdsa_secp256k1_identity<R: Rng + CryptoRng>(rng: &mut R) -> Secp256k1Identity {
    Secp256k1Identity::from_private_key(k256::SecretKey::random(rng))
}

pub fn random_ecdsa_secp256r1_identity<R: Rng + CryptoRng>(rng: &mut R) -> Prime256v1Identity {
    Prime256v1Identity::from_private_key(p256::SecretKey::random(rng))
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
    let client = reqwest::Client::new();

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
    for api_version in ALL_QUERY_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/query"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

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
    for api_version in ALL_UPDATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/call"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

    // Now try a read_state request.
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            paths: vec![],
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };
    let signature = sign_read_state(&content, &identity);
    // Add the public key but not the signature to the envelope. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
        sender_sig: None,
    };
    for api_version in ALL_READ_STATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/read_state"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }
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
    let client = reqwest::Client::new();

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
    for api_version in ALL_QUERY_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/query"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

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
    for api_version in ALL_UPDATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/call"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

    // Now try a read_state request.
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(identity1.sender().unwrap().as_slice().to_vec()),
            paths: vec![],
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };
    let signature1 = sign_read_state(&content, &identity1);
    let signature2 = sign_read_state(&content, &identity2);
    // Use the public key of identity1 but the signature of identity2. Should fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature1.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature2.signature.unwrap())),
    };
    for api_version in ALL_READ_STATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/read_state"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }
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
    let client = reqwest::Client::new();

    // Test a query.
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
    for api_version in ALL_QUERY_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/query"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

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
    let signature2 = sign_update(&content, &identity2);
    // Envelope with signature from `identity2` but sender is `identity1`. Should
    // fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature2.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature2.signature.unwrap())),
    };
    for api_version in ALL_UPDATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/call"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

    // Test a read_state request.
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(identity1.sender().unwrap().as_slice().to_vec()),
            paths: vec![],
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };
    let signature2 = sign_read_state(&content, &identity2);
    // Envelope with signature from `identity2` but sender is `identity1`. Should
    // fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature2.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature2.signature.unwrap())),
    };
    for api_version in ALL_READ_STATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/read_state"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }
}

async fn test_request_with_empty_domain_separator_fails<T: Identity + 'static>(
    url: &str,
    identity: T,
    canister_id: Principal,
) {
    let client = reqwest::Client::new();

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
    let signature = sign_query_with_empty_domain_separator(&content, &identity);
    // Envelope with signature from `identity` but empty domain separator. Should
    // fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature.signature.unwrap())),
    };
    for api_version in ALL_QUERY_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/query"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

    // Try an update.
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
    let signature = sign_update_with_empty_domain_separator(&content, &identity);
    // Envelope with signature from `identity` but empty domain separator. Should
    // fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature.signature.unwrap())),
    };
    for api_version in ALL_UPDATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/call"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }

    // Try a read_state request.
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            paths: vec![],
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };
    let signature = sign_read_state_with_empty_domain_separator(&content, &identity);
    // Envelope with signature from `identity` but empty domain separator. Should
    // fail.
    let envelope = HttpRequestEnvelope {
        content: content.clone(),
        sender_delegation: None,
        sender_pubkey: Some(Blob(signature.public_key.clone().unwrap())),
        sender_sig: Some(Blob(signature.signature.unwrap())),
    };
    for api_version in ALL_READ_STATE_API_VERSIONS {
        let res = client
            .post(format!(
                "{url}api/v{api_version}/canister/{canister_id}/read_state"
            ))
            .header("Content-Type", "application/cbor")
            .body(serde_cbor::ser::to_vec(&envelope).unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 400);
    }
}

async fn test_request_with_invalid_signature_fails<T: Identity + 'static>(
    url: &str,
    identity: T,
    canister_id: Principal,
    rng: &mut ReproducibleRng,
) {
    let client = reqwest::Client::new();

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
    for invalid_signature in [
        clong_signature_with_random_bit_flipped(&signature, rng),
        clone_signature_with_all_bytes_replaced(&signature, 42),
        clone_signature_with_all_bytes_replaced(&signature, 0),
    ] {
        // Add the public key with an invalid. Should fail.
        let envelope = HttpRequestEnvelope {
            content: content.clone(),
            sender_delegation: None,
            sender_pubkey: Some(Blob(invalid_signature.public_key.clone().unwrap())),
            sender_sig: Some(Blob(invalid_signature.signature.unwrap())),
        };
        for api_version in ALL_QUERY_API_VERSIONS {
            let res = client
                .post(format!(
                    "{url}api/v{api_version}/canister/{canister_id}/query"
                ))
                .header("Content-Type", "application/cbor")
                .body(serde_cbor::ser::to_vec(&envelope).unwrap())
                .send()
                .await
                .unwrap();

            assert_eq!(res.status(), 400);
        }
    }

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
    for invalid_signature in [
        clong_signature_with_random_bit_flipped(&signature, rng),
        clone_signature_with_all_bytes_replaced(&signature, 42),
        clone_signature_with_all_bytes_replaced(&signature, 0),
    ] {
        let envelope = HttpRequestEnvelope {
            content: content.clone(),
            sender_delegation: None,
            sender_pubkey: Some(Blob(invalid_signature.public_key.clone().unwrap())),
            sender_sig: Some(Blob(invalid_signature.signature.unwrap())),
        };
        for api_version in ALL_UPDATE_API_VERSIONS {
            let res = client
                .post(format!(
                    "{url}api/v{api_version}/canister/{canister_id}/call"
                ))
                .header("Content-Type", "application/cbor")
                .body(serde_cbor::ser::to_vec(&envelope).unwrap())
                .send()
                .await
                .unwrap();

            assert_eq!(res.status(), 400);
        }
    }

    // Try a read_state request. This should fail.
    let content = HttpReadStateContent::ReadState {
        read_state: HttpReadState {
            sender: Blob(identity.sender().unwrap().as_slice().to_vec()),
            paths: vec![],
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        },
    };
    let signature = sign_read_state(&content, &identity);
    for invalid_signature in [
        clong_signature_with_random_bit_flipped(&signature, rng),
        clone_signature_with_all_bytes_replaced(&signature, 42),
        clone_signature_with_all_bytes_replaced(&signature, 0),
    ] {
        let envelope = HttpRequestEnvelope {
            content: content.clone(),
            sender_delegation: None,
            sender_pubkey: Some(Blob(invalid_signature.public_key.clone().unwrap())),
            sender_sig: Some(Blob(invalid_signature.signature.unwrap())),
        };
        for api_version in ALL_READ_STATE_API_VERSIONS {
            let res = client
                .post(format!(
                    "{url}api/v{api_version}/canister/{canister_id}/read_state"
                ))
                .header("Content-Type", "application/cbor")
                .body(serde_cbor::ser::to_vec(&envelope).unwrap())
                .send()
                .await
                .unwrap();

            assert_eq!(res.status(), 400);
        }
    }
}

pub fn sign_query_with_empty_domain_separator(
    content: &HttpQueryContent,
    identity: &impl Identity,
) -> ic_agent::identity::Signature {
    let HttpQueryContent::Query { query: content } = content;
    let msg = ic_agent::agent::EnvelopeContent::Query {
        ingress_expiry: content.ingress_expiry,
        sender: Principal::from_slice(&content.sender),
        canister_id: Principal::from_slice(&content.canister_id),
        method_name: content.method_name.clone(),
        arg: content.arg.0.clone(),
        nonce: None,
    };
    let signable = msg.to_request_id().signable();
    identity
        .sign_arbitrary(truncate_domain_separator(&signable))
        .unwrap()
}

pub fn sign_update_with_empty_domain_separator(
    content: &HttpCallContent,
    identity: &impl Identity,
) -> ic_agent::identity::Signature {
    let HttpCallContent::Call { update: content } = content;
    let msg = ic_agent::agent::EnvelopeContent::Call {
        ingress_expiry: content.ingress_expiry,
        sender: Principal::from_slice(&content.sender),
        canister_id: Principal::from_slice(&content.canister_id),
        method_name: content.method_name.clone(),
        arg: content.arg.0.clone(),
        nonce: content.nonce.clone().map(|blob| blob.0),
    };
    let signable = msg.to_request_id().signable();
    identity
        .sign_arbitrary(truncate_domain_separator(&signable))
        .unwrap()
}

pub fn sign_read_state_with_empty_domain_separator(
    content: &HttpReadStateContent,
    identity: &impl Identity,
) -> ic_agent::identity::Signature {
    use ic_agent::hash_tree::Label;
    use std::ops::Deref;

    let HttpReadStateContent::ReadState {
        read_state: content,
    } = content;
    let msg = ic_agent::agent::EnvelopeContent::ReadState {
        paths: content
            .paths
            .iter()
            .map(|path| {
                path.deref()
                    .iter()
                    .map(|label| Label::from_bytes(label.as_bytes()))
                    .collect::<Vec<_>>()
            })
            .collect(),
        sender: Principal::from_slice(&content.sender),
        ingress_expiry: content.ingress_expiry,
    };
    let signable = msg.to_request_id().signable();
    identity
        .sign_arbitrary(truncate_domain_separator(&signable))
        .unwrap()
}

fn truncate_domain_separator(signable: &[u8]) -> &[u8] {
    const IC_REQUEST_DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";
    const DOMAIN_SEPARATOR_LENGTH: usize = 11;
    assert_eq!(
        signable[..DOMAIN_SEPARATOR_LENGTH],
        *IC_REQUEST_DOMAIN_SEPARATOR
    );
    &signable[DOMAIN_SEPARATOR_LENGTH..]
}

fn clone_signature_with_all_bytes_replaced(
    signature: &ic_agent::identity::Signature,
    byte: u8,
) -> ic_agent::identity::Signature {
    let mut clone = signature.clone();
    clone
        .signature
        .as_mut()
        .unwrap()
        .iter_mut()
        .for_each(|b| *b = byte);
    clone
}

fn clong_signature_with_random_bit_flipped(
    signature: &ic_agent::identity::Signature,
    rng: &mut ReproducibleRng,
) -> ic_agent::identity::Signature {
    let mut clone = signature.clone();
    if let Some(sig) = clone.signature.as_mut() {
        let idx = rng.random_range(0..sig.len());
        sig[idx] ^= 1 << (rng.random_range(0..8));
        clone
    } else {
        panic!("cannot flip bit: missing signature");
    }
}
