/* tag::catalog[]
end::catalog[] */
use crate::util::{
    agent_with_identity, assert_create_agent, delay, get_random_node_endpoint,
    random_ed25519_identity, UniversalCanister,
};
use ic_agent::export::Principal;
use ic_agent::{identity::AnonymousIdentity, Identity, Signature};
use ic_fondue::{ic_instance::InternetComputer, ic_manager::IcHandle};
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpRequestEnvelope, HttpUserQuery,
};
use ic_universal_canister::wasm;
use slog::{debug, info};
use std::time::{Duration, SystemTime};

pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on({
        let logger = ctx.logger.clone();
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            debug!(ctx.logger, "Selected replica"; "url" => format!("{}", endpoint.url));

            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;

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
                endpoint.url.as_str(),
                AnonymousIdentity,
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing valid requests from an ECDSA identity. Should succeed."
            );
            test_valid_request_succeeds(
                endpoint.url.as_str(),
                random_ecdsa_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing valid requests from an Ed25519 identity. Should succeed."
            );
            test_valid_request_succeeds(
                endpoint.url.as_str(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity but with missing signature. Should fail."
            );
            test_request_with_empty_signature_fails(
                endpoint.url.as_str(),
                random_ecdsa_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with missing signature. Should fail."
            );
            test_request_with_empty_signature_fails(
                endpoint.url.as_str(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity signed by an ed25519 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                endpoint.url.as_str(),
                random_ecdsa_identity(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity signed by an ECDSA identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                endpoint.url.as_str(),
                random_ed25519_identity(),
                random_ecdsa_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity signed by another ed25519 identity. Should fail."
            );
            test_request_signed_by_another_identity_fails(
                endpoint.url.as_str(),
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
                endpoint.url.as_str(),
                random_ecdsa_identity(),
                random_ecdsa_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ECDSA identity but with an ed25519 sender. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                endpoint.url.as_str(),
                random_ecdsa_identity(),
                random_ed25519_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with wrong (ECDSA) identity. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                endpoint.url.as_str(),
                random_ed25519_identity(),
                random_ecdsa_identity(),
                canister.canister_id(),
            )
            .await;

            info!(
                logger,
                "Testing request from an ed25519 identity but with wrong (ed25519) identity. Should fail."
            );
            test_request_with_valid_signature_but_wrong_sender_fails(
                endpoint.url.as_str(),
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
                endpoint.url.as_str(),
                random_ecdsa_identity(),
                random_ecdsa_identity(),
                canister.canister_id(),
            )
            .await;
        }
    });
}

pub fn random_ecdsa_identity() -> EcdsaIdentity {
    EcdsaIdentity::new_random()
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
        .call_and_wait(delay())
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

fn sign_query(content: &HttpQueryContent, identity: &impl Identity) -> Signature {
    let mut msg = b"\x0Aic-request".to_vec();
    msg.extend(&content.representation_independent_hash());
    identity.sign(&msg).unwrap()
}

pub fn sign_update(content: &HttpCallContent, identity: &impl Identity) -> Signature {
    let mut msg = b"\x0Aic-request".to_vec();
    msg.extend(&content.representation_independent_hash());
    identity.sign(&msg).unwrap()
}

pub fn expiry_time() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::from_secs(4 * 60)
}

// TODO(VER-507): Move the ECDSA implementation below to `agent-rs`.
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;

// NOTE: prime256v1 is a yet another name for secp256r1 (aka. NIST P-256),
// cf. https://tools.ietf.org/html/rfc5480
const CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;

pub struct EcdsaIdentity {
    key: EcKey<Private>,
}

impl EcdsaIdentity {
    pub fn new_random() -> Self {
        let group = EcGroup::from_curve_name(CURVE_NAME).expect("unable to create EC group");
        let ec_key = EcKey::generate(&group).expect("unable to generate EC key");
        Self { key: ec_key }
    }

    fn ecdsa_sig_to_bytes(ecdsa_sig: EcdsaSig) -> [u8; 64] {
        let r = ecdsa_sig.r().to_vec();
        let s = ecdsa_sig.s().to_vec();
        if r.len() > 32 || s.len() > 32 {
            panic!("ECDSA signature too long");
        }

        let mut bytes = [0; 64];
        // Account for leading zeros.
        bytes[(32 - r.len())..32].clone_from_slice(&r);
        bytes[(64 - s.len())..64].clone_from_slice(&s);
        bytes
    }

    fn public_key_der(&self) -> Vec<u8> {
        self.key.public_key_to_der().unwrap()
    }
}

impl Identity for EcdsaIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key_der()))
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        use ic_crypto_sha::Sha256;
        let msg = Sha256::hash(msg).to_vec();
        Ok(Signature {
            signature: Some(
                Self::ecdsa_sig_to_bytes(EcdsaSig::sign(&msg, &self.key).expect("unable to sign"))
                    .to_vec(),
            ),
            public_key: Some(self.public_key_der()),
        })
    }
}
