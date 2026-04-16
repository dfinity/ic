/* tag::catalog[]
end::catalog[] */

//! System test for the sender_info feature.
//!
//! Tests that canisters can read `msg_caller_info_data` and `msg_caller_info_signer`
//! when the caller provides valid `sender_info` in an ingress message authenticated
//! via canister signatures.

use anyhow::Result;
use ic_agent::Identity;
use ic_agent::export::Principal;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, block_on, expiry_time};
use ic_types::crypto::Signable;
use ic_types::messages::{
    Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpRequestEnvelope,
    HttpUserQuery, MessageId, RawSignedSenderInfo, SenderInfoContent, SignedDelegation,
};
use ic_types::{CanisterId, PrincipalId};
use ic_universal_canister::{call_args, wasm};
use reqwest::{StatusCode, Url};
use slog::debug;

// ---------------------------------------------------------------------------
// Infrastructure (simplified from rs/tests/crypto/ingress_verification_test.rs)
// ---------------------------------------------------------------------------

struct TestInformation {
    url: Url,
    canister_id: CanisterId,
}

fn canister_id_from_principal(p: &Principal) -> CanisterId {
    if *p == Principal::management_canister() {
        CanisterId::ic_00()
    } else {
        CanisterId::try_from_principal_id(PrincipalId::from(*p)).expect("invalid canister ID")
    }
}

/// Creates valid canister signatures backed by a Universal Canister that sets
/// certified data.
#[derive(Clone)]
struct CanisterSigner<'a> {
    canister: &'a UniversalCanister<'a>,
    seed: Vec<u8>,
}

impl<'a> CanisterSigner<'a> {
    pub fn new(canister: &'a UniversalCanister<'a>, seed: Vec<u8>) -> Self {
        Self { canister, seed }
    }

    pub fn canister_id(&self) -> CanisterId {
        canister_id_from_principal(&self.canister.canister_id())
    }

    pub fn public_key_raw(&self) -> Vec<u8> {
        use ic_crypto_test_utils::canister_signatures::canister_sig_pub_key_to_bytes;
        canister_sig_pub_key_to_bytes(self.canister_id(), &self.seed)
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        use ic_crypto_internal_basic_sig_der_utils::subject_public_key_info_der;
        use simple_asn1::oid;
        // OID 1.3.6.1.4.1.56387.1.2 (canister-signature)
        let oid_canister_signature = oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2);
        subject_public_key_info_der(oid_canister_signature, &self.public_key_raw()).unwrap()
    }

    pub async fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ic_certification::{labeled, leaf};
        use ic_crypto_sha2::Sha256;
        use serde::Serialize;
        use serde_bytes::ByteBuf;

        let seed_hash = Sha256::hash(&self.seed);
        let msg_hash = Sha256::hash(message);
        let sig_tree = labeled(b"sig", labeled(seed_hash, labeled(msg_hash, leaf(b""))));

        let certificate_cbor = self.certify_variable(&sig_tree.digest()).await;

        #[derive(serde::Serialize)]
        struct CanisterSignature {
            certificate: ByteBuf,
            tree: ic_certification::HashTree,
        }
        let canister_sig = CanisterSignature {
            certificate: ByteBuf::from(certificate_cbor),
            tree: sig_tree,
        };
        let mut serializer = serde_cbor::Serializer::new(Vec::new());
        serializer.self_describe().unwrap();
        canister_sig.serialize(&mut serializer).unwrap();
        serializer.into_inner()
    }

    async fn certify_variable(&self, variable_data: &[u8]) -> Vec<u8> {
        let _ = self
            .canister
            .update(wasm().certified_data_set(variable_data).reply().build())
            .await
            .expect("failed to set certified data on universal canister");

        self.canister
            .query(wasm().data_certificate().append_and_reply().build())
            .await
            .expect("failed to get data certificate from universal canister")
    }
}

/// Minimal identity wrapper for canister-signature authentication.
#[derive(Clone)]
struct CanisterSignerIdentity<'a> {
    signer: CanisterSigner<'a>,
    public_key_der: Vec<u8>,
    principal: Principal,
}

impl<'a> CanisterSignerIdentity<'a> {
    fn new(signer: CanisterSigner<'a>) -> Self {
        let pk = signer.public_key_der();
        let principal = Principal::self_authenticating(&pk);
        Self {
            signer,
            public_key_der: pk,
            principal,
        }
    }

    fn principal(&self) -> &Principal {
        &self.principal
    }

    fn public_key_der(&self) -> Vec<u8> {
        self.public_key_der.clone()
    }

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let sign_future = self.signer.sign(bytes);
        #[allow(clippy::disallowed_methods)]
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(sign_future))
    }
}

impl Identity for CanisterSignerIdentity<'_> {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.principal)
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.public_key_der.clone())
    }

    fn sign(
        &self,
        content: &ic_agent::agent::EnvelopeContent,
    ) -> Result<ic_agent::Signature, String> {
        self.sign_arbitrary(&content.to_request_id().signable())
    }

    fn sign_delegation(
        &self,
        content: &ic_agent::identity::Delegation,
    ) -> Result<ic_agent::Signature, String> {
        self.sign_arbitrary(&content.signable())
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<ic_agent::Signature, String> {
        let signature = self.sign_bytes(content);
        Ok(ic_agent::Signature {
            public_key: Some(self.public_key_der()),
            signature: Some(signature),
            delegations: None,
        })
    }
}

// -- Response helpers --

#[derive(Clone, Debug)]
enum ResponseBody {
    Empty,
    Text(String),
    Cbor(serde_cbor::Value),
}

#[derive(Clone, Debug)]
struct ReplicaResponse {
    status: StatusCode,
    body: ResponseBody,
}

impl ReplicaResponse {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn expect_query_ok(&self) {
        assert_eq!(self.status(), 200);
        match &self.body {
            ResponseBody::Cbor(serde_cbor::Value::Map(m)) => {
                assert!(
                    m.contains_key(&serde_cbor::Value::Text("reply".to_owned())),
                    "Missing 'reply' field in CBOR response: {:?}",
                    m
                );
            }
            other => panic!("Expected CBOR map with 'reply', got {:?}", other),
        }
    }

    fn expect_update_ok(&self) {
        // Use v3 API: expect 200 with a certificate
        assert_eq!(
            self.status(),
            200,
            "Expected 200 for v3 update, got {}",
            self.status()
        );
        match &self.body {
            ResponseBody::Cbor(serde_cbor::Value::Map(m)) => {
                assert!(
                    m.contains_key(&serde_cbor::Value::Text("certificate".to_owned())),
                    "Missing 'certificate' field in CBOR response: {:?}",
                    m
                );
            }
            other => panic!("Expected CBOR map with 'certificate', got {:?}", other),
        }
    }

    fn expect_query_reply_arg(&self, expected_arg: &[u8]) {
        match &self.body {
            ResponseBody::Cbor(serde_cbor::Value::Map(m)) => {
                let reply = m
                    .get(&serde_cbor::Value::Text("reply".to_owned()))
                    .expect("Missing 'reply' field in CBOR response");
                if let serde_cbor::Value::Map(reply_map) = reply {
                    let arg = reply_map
                        .get(&serde_cbor::Value::Text("arg".to_owned()))
                        .expect("Missing 'arg' field in reply");
                    if let serde_cbor::Value::Bytes(bytes) = arg {
                        assert_eq!(bytes, expected_arg, "Query reply arg mismatch");
                    } else {
                        panic!("Expected bytes for 'arg', got {:?}", arg);
                    }
                } else {
                    panic!("Expected map for 'reply', got {:?}", reply);
                }
            }
            other => panic!("Expected CBOR map response, got {:?}", other),
        }
    }
}

async fn send_request<C: serde::ser::Serialize>(
    api_ver: usize,
    test: &TestInformation,
    req_type: &'static str,
    content: C,
    sender_pubkey: Vec<u8>,
    sender_delegation: Option<Vec<SignedDelegation>>,
    sender_sig: Vec<u8>,
) -> ReplicaResponse {
    let envelope = HttpRequestEnvelope {
        content,
        sender_delegation,
        sender_pubkey: Some(Blob(sender_pubkey)),
        sender_sig: Some(Blob(sender_sig)),
    };

    let body = serde_cbor::ser::to_vec(&envelope).unwrap();
    let client = reqwest::Client::new();

    let url = format!(
        "{}api/v{}/canister/{}/{}",
        test.url, api_ver, test.canister_id, req_type
    );

    let response = client
        .post(url)
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    let status = response.status();

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|s| s.to_str().expect("Invalid Content-Type").to_owned());

    let bytes = response
        .bytes()
        .await
        .expect("Failed to get response body")
        .to_vec();

    let body = match content_type.as_deref() {
        None => {
            assert_eq!(bytes.len(), 0);
            ResponseBody::Empty
        }
        Some("application/cbor") => ResponseBody::Cbor(
            serde_cbor::from_slice(&bytes).expect("Failed to parse CBOR response"),
        ),
        Some("text/plain; charset=utf-8") => ResponseBody::Text(
            String::from_utf8(bytes).expect("Replica sent invalid text response"),
        ),
        Some(other) => {
            panic!("Unknown content type {}", other);
        }
    };

    ReplicaResponse { status, body }
}

// -- Test helper: create a SenderInfo context for a canister --

struct SenderInfoContext<'a> {
    identity: CanisterSignerIdentity<'a>,
    info_bytes: Vec<u8>,
    sender_info: RawSignedSenderInfo,
    signer_principal_bytes: Vec<u8>,
}

async fn create_sender_info_context<'a>(
    canister: &'a UniversalCanister<'a>,
) -> SenderInfoContext<'a> {
    let seed = b"sender_info_test_seed".to_vec();
    let signer = CanisterSigner::new(canister, seed);
    let identity = CanisterSignerIdentity::new(signer.clone());

    let info_bytes = b"some user attributes".to_vec();
    let sender_info_content = SenderInfoContent(info_bytes.clone());
    let sender_info_sig = signer.sign(&sender_info_content.as_signed_bytes()).await;

    let signer_principal_bytes = signer.canister_id().get().as_slice().to_vec();
    let sender_info = RawSignedSenderInfo {
        info: Blob(info_bytes.clone()),
        signer: Blob(signer_principal_bytes.clone()),
        sig: Blob(sender_info_sig),
    };

    SenderInfoContext {
        identity,
        info_bytes,
        sender_info,
        signer_principal_bytes,
    }
}

fn send_query_with_sender_info<'a>(
    test: &'a TestInformation,
    ctx: &'a SenderInfoContext<'_>,
    wasm_payload: Vec<u8>,
) -> impl std::future::Future<Output = ReplicaResponse> + 'a {
    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "query".to_string(),
            arg: Blob(wasm_payload),
            sender: Blob(ctx.identity.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
            sender_info: Some(ctx.sender_info.clone()),
        },
    };
    let message_id = MessageId::from(content.representation_independent_hash());
    let signature = ctx.identity.sign_bytes(&message_id.as_signed_bytes());
    send_request(
        3,
        test,
        "query",
        content,
        ctx.identity.public_key_der(),
        None,
        signature,
    )
}

fn send_update_with_sender_info<'a>(
    test: &'a TestInformation,
    ctx: &'a SenderInfoContext<'_>,
    wasm_payload: Vec<u8>,
) -> impl std::future::Future<Output = ReplicaResponse> + 'a {
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(test.canister_id.get().as_slice().to_vec()),
            method_name: "update".to_string(),
            arg: Blob(wasm_payload),
            sender: Blob(ctx.identity.principal().as_slice().to_vec()),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
            sender_info: Some(ctx.sender_info.clone()),
        },
    };
    let message_id = MessageId::from(content.representation_independent_hash());
    let signature = ctx.identity.sign_bytes(&message_id.as_signed_bytes());
    send_request(
        3,
        test,
        "call",
        content,
        ctx.identity.public_key_der(),
        None,
        signature,
    )
}

// ---------------------------------------------------------------------------
// Setup and main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(query_reads_sender_info_data_and_signer))
                .add_test(systest!(update_reads_sender_info_data_and_signer))
                .add_test(systest!(no_sender_info_returns_empty))
                .add_test(systest!(inter_canister_call_does_not_propagate_sender_info))
                .add_test(systest!(reply_callback_can_access_sender_info)),
        )
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

// ---------------------------------------------------------------------------
// Test functions
// ---------------------------------------------------------------------------

/// Verify that a canister can read both caller_info_data and caller_info_signer
/// from a query call carrying valid sender_info.
pub fn query_reads_sender_info_data_and_signer(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_application_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let test_info = TestInformation {
                url: node.get_public_url(),
                canister_id: canister_id_from_principal(&canister.canister_id()),
            };
            let ctx = create_sender_info_context(&canister).await;

            // Query: read msg_caller_info_data
            debug!(logger, "Querying msg_caller_info_data");
            let response = send_query_with_sender_info(
                &test_info,
                &ctx,
                wasm().msg_caller_info_data().append_and_reply().build(),
            )
            .await;
            response.expect_query_ok();
            response.expect_query_reply_arg(&ctx.info_bytes);

            // Query: read msg_caller_info_signer
            debug!(logger, "Querying msg_caller_info_signer");
            let response = send_query_with_sender_info(
                &test_info,
                &ctx,
                wasm().msg_caller_info_signer().append_and_reply().build(),
            )
            .await;
            response.expect_query_ok();
            response.expect_query_reply_arg(&ctx.signer_principal_bytes);
        }
    });
}

/// Verify that a canister can read sender_info from an update call by storing
/// it in stable memory and reading it back via a follow-up query.
pub fn update_reads_sender_info_data_and_signer(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_application_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let test_info = TestInformation {
                url: node.get_public_url(),
                canister_id: canister_id_from_principal(&canister.canister_id()),
            };
            let ctx = create_sender_info_context(&canister).await;

            // Update: store caller_info_data at stable[0..] and
            //         caller_info_signer at stable[100..]
            debug!(
                logger,
                "Sending update to store sender_info in stable memory"
            );
            let payload = wasm()
                .stable_grow(1)
                .push_int(0)
                .msg_caller_info_data()
                .stable_write_offset_blob()
                .push_int(100)
                .msg_caller_info_signer()
                .stable_write_offset_blob()
                .reply()
                .build();

            let response = send_update_with_sender_info(&test_info, &ctx, payload).await;
            response.expect_update_ok();

            // Read back caller_info_data from stable memory
            debug!(logger, "Reading back caller_info_data from stable memory");
            let result = canister
                .query(
                    wasm()
                        .stable_read(0, ctx.info_bytes.len() as u32)
                        .append_and_reply()
                        .build(),
                )
                .await
                .expect("failed to query stable memory for info data");
            assert_eq!(
                result, ctx.info_bytes,
                "caller_info_data mismatch in update call"
            );

            // Read back caller_info_signer from stable memory
            debug!(logger, "Reading back caller_info_signer from stable memory");
            let result = canister
                .query(
                    wasm()
                        .stable_read(100, ctx.signer_principal_bytes.len() as u32)
                        .append_and_reply()
                        .build(),
                )
                .await
                .expect("failed to query stable memory for signer");
            assert_eq!(
                result, ctx.signer_principal_bytes,
                "caller_info_signer mismatch in update call"
            );
        }
    });
}

/// Verify that msg_caller_info_data and msg_caller_info_signer return empty
/// when no sender_info is provided in the ingress message.
pub fn no_sender_info_returns_empty(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_application_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            // Query: msg_caller_info_data should be empty
            debug!(logger, "Querying msg_caller_info_data without sender_info");
            let result = canister
                .query(wasm().msg_caller_info_data().append_and_reply().build())
                .await
                .expect("failed to query msg_caller_info_data");
            assert!(
                result.is_empty(),
                "Expected empty caller_info_data, got {} bytes",
                result.len()
            );

            // Query: msg_caller_info_signer should be empty
            debug!(
                logger,
                "Querying msg_caller_info_signer without sender_info"
            );
            let result = canister
                .query(wasm().msg_caller_info_signer().append_and_reply().build())
                .await
                .expect("failed to query msg_caller_info_signer");
            assert!(
                result.is_empty(),
                "Expected empty caller_info_signer, got {} bytes",
                result.len()
            );
        }
    });
}

/// Verify that sender_info does NOT propagate to inter-canister calls. When
/// UC A (called with sender_info) calls UC B, UC B should see empty
/// caller_info_data.
pub fn inter_canister_call_does_not_propagate_sender_info(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_application_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let canister_b =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let test_info = TestInformation {
                url: node.get_public_url(),
                canister_id: canister_id_from_principal(&canister_a.canister_id()),
            };
            let ctx = create_sender_info_context(&canister_a).await;

            // UC A calls UC B. UC B writes msg_caller_info_data to stable memory.
            debug!(
                logger,
                "Sending update to UC A with sender_info, which calls UC B"
            );
            let canister_b_id = canister_b.canister_id();
            let payload = wasm()
                .inter_update(
                    canister_b_id,
                    call_args().other_side(
                        wasm()
                            .stable_grow(1)
                            .push_int(0)
                            .msg_caller_info_data()
                            .stable_write_offset_blob()
                            .reply()
                            .build(),
                    ),
                )
                .build();

            let response = send_update_with_sender_info(&test_info, &ctx, payload).await;
            response.expect_update_ok();

            // Read UC B's stable memory. If sender_info propagated, we'd see
            // the info bytes; otherwise it should be all zeros.
            debug!(
                logger,
                "Reading UC B's stable memory to verify sender_info isolation"
            );
            let result = canister_b
                .query(
                    wasm()
                        .stable_read(0, ctx.info_bytes.len() as u32)
                        .append_and_reply()
                        .build(),
                )
                .await
                .expect("failed to query UC B's stable memory");
            assert_eq!(
                result,
                vec![0u8; ctx.info_bytes.len()],
                "sender_info should NOT propagate to inter-canister calls"
            );
        }
    });
}

/// Verify that sender_info is accessible in reply callbacks. UC A receives an
/// ingress with sender_info, calls UC B (which just replies), and in the reply
/// callback reads and stores sender_info to stable memory.
pub fn reply_callback_can_access_sender_info(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_application_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let canister_b =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let test_info = TestInformation {
                url: node.get_public_url(),
                canister_id: canister_id_from_principal(&canister_a.canister_id()),
            };
            let ctx = create_sender_info_context(&canister_a).await;

            // UC A calls UC B (which just replies). In the reply callback,
            // UC A stores sender_info in stable memory.
            debug!(
                logger,
                "Sending update: UC A calls UC B, reply callback stores sender_info"
            );
            let payload = wasm()
                .inter_update(
                    canister_b.canister_id(),
                    call_args().other_side(wasm().reply().build()).on_reply(
                        wasm()
                            .stable_grow(1)
                            .push_int(0)
                            .msg_caller_info_data()
                            .stable_write_offset_blob()
                            .push_int(100)
                            .msg_caller_info_signer()
                            .stable_write_offset_blob()
                            .reply()
                            .build(),
                    ),
                )
                .build();

            let response = send_update_with_sender_info(&test_info, &ctx, payload).await;
            response.expect_update_ok();

            // Read back from UC A's stable memory
            debug!(
                logger,
                "Reading UC A's stable memory to verify sender_info in reply callback"
            );
            let result = canister_a
                .query(
                    wasm()
                        .stable_read(0, ctx.info_bytes.len() as u32)
                        .append_and_reply()
                        .build(),
                )
                .await
                .expect("failed to query UC A's stable memory for info data");
            assert_eq!(
                result, ctx.info_bytes,
                "caller_info_data mismatch in reply callback"
            );

            let result = canister_a
                .query(
                    wasm()
                        .stable_read(100, ctx.signer_principal_bytes.len() as u32)
                        .append_and_reply()
                        .build(),
                )
                .await
                .expect("failed to query UC A's stable memory for signer");
            assert_eq!(
                result, ctx.signer_principal_bytes,
                "caller_info_signer mismatch in reply callback"
            );
        }
    });
}
