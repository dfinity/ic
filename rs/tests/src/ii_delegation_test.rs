use std::time::{Duration, Instant};

use crate::driver::ic::InternetComputer;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot,
    IcNodeContainer,
};
use crate::execution::request_signature_test::{expiry_time, sign_query, sign_update};
use crate::util::{
    agent_with_identity, assert_canister_counter_with_retries, block_on, delay,
    random_ed25519_identity,
};
use candid::{CandidType, Deserialize, Principal};
use canister_test::PrincipalId;
use ic_agent::{Agent, Identity};
use ic_crypto_tree_hash::Path;
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{
    Blob, Certificate, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpQueryResponse,
    HttpReadState, HttpReadStateContent, HttpReadStateResponse, HttpRequestEnvelope, HttpUserQuery,
    MessageId,
};
use ic_types::Time;
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use ic_utils::interfaces::ManagementCanister;
use reqwest::{Client, Response};
use serde_bytes::ByteBuf;
use slog::info;

const INTERNET_IDENTITY_WASM: &str = "external/ii_test_canister/file/internet_identity_test.wasm";
const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const UPDATE_POLLING_TIMEOUT: Duration = Duration::from_secs(10);

pub type AnchorNumber = u64;

pub struct Base64(pub String);

pub type CredentialId = ByteBuf;
pub type PublicKey = ByteBuf;
pub type DeviceKey = PublicKey;
pub type UserKey = PublicKey;
pub type SessionKey = PublicKey;
pub type FrontendHostname = String;
pub type Timestamp = u64;
// in nanos since epoch
pub type Signature = ByteBuf;

#[derive(Eq, PartialEq, Clone, Debug, CandidType, Deserialize)]
pub struct DeviceData {
    pub pubkey: DeviceKey,
    pub alias: String,
    pub credential_id: Option<CredentialId>,
    pub purpose: Purpose,
    pub key_type: KeyType,
    pub protection: DeviceProtection,
}

#[derive(Eq, PartialEq, Clone, Debug, CandidType, Deserialize)]
pub enum Purpose {
    #[serde(rename = "recovery")]
    Recovery,
    #[serde(rename = "authentication")]
    Authentication,
}

#[derive(Eq, PartialEq, Clone, Debug, CandidType, Deserialize)]
pub enum RegisterResponse {
    #[serde(rename = "registered")]
    Registered { user_number: AnchorNumber },
    #[serde(rename = "canister_full")]
    CanisterFull,
    #[serde(rename = "bad_challenge")]
    BadChallenge,
}

#[derive(Eq, PartialEq, Clone, Debug, CandidType, Deserialize)]
pub enum KeyType {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross_platform")]
    CrossPlatform,
    #[serde(rename = "seed_phrase")]
    SeedPhrase,
}

#[derive(Eq, PartialEq, Clone, Debug, CandidType, Deserialize)]
pub enum DeviceProtection {
    #[serde(rename = "protected")]
    Protected,
    #[serde(rename = "unprotected")]
    Unprotected,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Challenge {
    pub png_base64: String,
    pub challenge_key: ChallengeKey,
}

pub type ChallengeKey = String;

// The user's attempt
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ChallengeAttempt {
    pub chars: String,
    pub key: ChallengeKey,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Delegation {
    pub pubkey: PublicKey,
    pub expiration: Timestamp,
    pub targets: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: Signature,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum GetDelegationResponse {
    #[serde(rename = "signed_delegation")]
    SignedDelegation(SignedDelegation),
    #[serde(rename = "no_such_delegation")]
    NoSuchDelegation,
}

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let non_nns_node = env.get_first_healthy_system_but_not_nns_node_snapshot();
    let ii_canister_id =
        non_nns_node.create_and_install_canister_with_arg(INTERNET_IDENTITY_WASM, None);
    info!(
        log,
        "II canister with id={ii_canister_id} installed on subnet with id={}",
        non_nns_node.subnet_id().unwrap()
    );
    let app_node = env.get_first_healthy_application_node_snapshot();
    let counter_canister_id =
        app_node.create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(
        log,
        "Counter canister with id={counter_canister_id} installed on subnet with id={}",
        app_node.subnet_id().unwrap()
    );
    let app_agent = app_node.build_default_agent();
    let ucan_id = block_on(install_universal_canister(
        &app_agent,
        app_node.effective_canister_id(),
    ));
    // We use universal canister to verify the identity of the caller for query and update calls performed with delegation.
    info!(
        log,
        "Universal canister with id={ucan_id} installed on subnet with id={}",
        app_node.subnet_id().unwrap()
    );
    let user_identity = random_ed25519_identity();
    let pubkey = user_identity.sign(&[]).unwrap().public_key.unwrap();
    let non_nns_agent = block_on(agent_with_identity(
        non_nns_node.get_public_url().as_str(),
        user_identity,
    ))
    .unwrap();
    block_on(register_user(&non_nns_agent, pubkey, ii_canister_id));
    info!(log, "User registered");
    let delegation_identity = random_ed25519_identity();
    let delegation_pubkey = delegation_identity.sign(&[]).unwrap().public_key.unwrap();
    let frontend_hostname = format!("https://{}.ic0.app", counter_canister_id.to_text());
    let (signed_delegation, ii_derived_public_key) = block_on(create_delegation(
        &non_nns_agent,
        delegation_pubkey,
        ii_canister_id,
        frontend_hostname,
    ));
    info!(log, "Delegation received");
    let app_agent_with_delegation = AgentWithDelegation {
        node_url: app_node.get_public_url(),
        pubkey: ii_derived_public_key.clone(),
        signed_delegation,
        delegation_identity,
        polling_timeout: UPDATE_POLLING_TIMEOUT,
    };
    info!(
        log,
        "Making an update call on counter canister with delegation (increment counter)"
    );
    let _ = block_on(app_agent_with_delegation.update(&counter_canister_id, "write", Blob(vec![])));
    info!(
        log,
        "Making a query call on counter canister with delegation (read counter)"
    );
    let query_response =
        block_on(app_agent_with_delegation.query(&counter_canister_id, "read", Blob(vec![])));
    match query_response {
        HttpQueryResponse::Replied { .. } => (),
        HttpQueryResponse::Rejected {
            error_code,
            reject_message,
            ..
        } => panic!("Query call was rejected: code={error_code}, message={reject_message}"),
    }
    info!(log, "Asserting canister counter has value=1");
    let app_agent = app_node.build_default_agent();
    block_on(assert_canister_counter_with_retries(
        &log,
        &app_agent,
        &counter_canister_id,
        vec![],
        1,
        10,
        Duration::from_secs(1),
    ));
    let expected_principal = Principal::self_authenticating(&ii_derived_public_key);
    info!(
        log,
        "Expected principal {} of the caller", expected_principal
    );
    info!(log, "Asserting caller identity of the query call");
    let observed_principal = {
        let response: HttpQueryResponse = block_on(app_agent_with_delegation.query(
            &ucan_id,
            "query",
            Blob(wasm().caller().append_and_reply().build()),
        ));
        let principal = match response {
            HttpQueryResponse::Replied { reply } => Principal::from_slice(reply.arg.as_ref()),
            HttpQueryResponse::Rejected { reject_message, .. } => {
                panic!("Query call was rejected: {reject_message}")
            }
        };
        principal
    };
    assert_eq!(expected_principal, observed_principal);
    info!(log, "Asserting caller identity of the update call");
    let observed_principal = {
        let response = block_on(app_agent_with_delegation.update_and_wait(
            &ucan_id,
            "update",
            Blob(wasm().caller().append_and_reply().build()),
        ))
        .unwrap();
        Principal::from_slice(response.as_ref())
    };
    assert_eq!(expected_principal, observed_principal);
}

struct AgentWithDelegation<T> {
    node_url: url::Url,
    pubkey: UserKey,
    signed_delegation: SignedDelegation,
    delegation_identity: T,
    polling_timeout: Duration,
}

impl<T: Identity> AgentWithDelegation<T> {
    async fn send_http_request(
        &self,
        method: &str,
        canister_id: &Principal,
        body: Vec<u8>,
    ) -> Response {
        let client = Client::new();
        client
            .post(&format!(
                "{}api/v2/canister/{}/{}",
                self.node_url.as_str(),
                canister_id,
                method
            ))
            .header("Content-Type", "application/cbor")
            .body(body)
            .send()
            .await
            .unwrap()
    }

    fn sender(&self) -> Blob {
        Blob(
            Principal::self_authenticating(self.pubkey.clone().into_vec())
                .as_slice()
                .to_vec(),
        )
    }

    pub async fn update_and_wait(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: Blob,
    ) -> Result<Vec<u8>, String> {
        let request_id = self.update(canister_id, method_name, arg.clone()).await;
        let content = HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                sender: self.sender(),
                paths: vec![Path::new(vec![
                    b"request_status".into(),
                    request_id.as_bytes().into(),
                ])],
                nonce: None,
                ingress_expiry: expiry_time().as_nanos() as u64,
            },
        };
        let sig_blob = sign_read_state(&content, &self.delegation_identity);
        let read_state_envelope: HttpRequestEnvelope<HttpReadStateContent> = HttpRequestEnvelope {
            content,
            sender_pubkey: Some(Blob(self.pubkey.clone().into_vec())),
            sender_sig: Some(sig_blob),
            sender_delegation: Some(vec![ic_types::messages::SignedDelegation::new(
                ic_types::messages::Delegation::new(
                    self.signed_delegation.delegation.pubkey.clone().into_vec(),
                    Time::from_nanos_since_unix_epoch(self.signed_delegation.delegation.expiration),
                ),
                self.signed_delegation.signature.clone().into_vec(),
            )]),
        };
        let body = serde_cbor::ser::to_vec(&read_state_envelope).unwrap();
        let path = {
            let p1: &[u8] = b"request_status";
            let p2: &[u8] = request_id.as_bytes();
            let p3: &[u8] = b"reply";
            vec![p1, p2, p3]
        };
        let start = Instant::now();
        let read_state: Vec<u8> = loop {
            if start.elapsed() > self.polling_timeout {
                return Err(format!(
                    "Polling timeout of {} ms was reached",
                    self.polling_timeout.as_millis()
                ));
            }
            let response = self
                .send_http_request("read_state", canister_id, body.clone())
                .await;
            let read_state_body = response.bytes().await.unwrap();
            let response_bytes: HttpReadStateResponse =
                serde_cbor::from_slice(&read_state_body).unwrap();
            let certificate: Certificate =
                serde_cbor::from_slice(&response_bytes.certificate).unwrap();
            let lookup_status = certificate.tree.lookup(&path);
            match lookup_status {
                ic_crypto_tree_hash::LookupStatus::Found(x) => match x {
                    ic_crypto_tree_hash::MixedHashTree::Leaf(y) => break y.clone(),
                    _ => panic!("Unexpected result from the read_state tree hash structure"),
                },
                ic_crypto_tree_hash::LookupStatus::Absent => {
                    // If request is absent, keep polling
                    continue;
                }
                ic_crypto_tree_hash::LookupStatus::Unknown => {
                    // If request is unknown, keep polling
                    continue;
                }
            };
        };
        Ok(read_state)
    }

    pub async fn update(&self, canister_id: &Principal, method_name: &str, arg: Blob) -> MessageId {
        let update = HttpCanisterUpdate {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: method_name.to_string(),
            arg,
            sender: self.sender(),
            ingress_expiry: expiry_time().as_nanos() as u64,
            nonce: None,
        };
        let request_id = update.id();
        let content = HttpCallContent::Call { update };
        let signature = sign_update(&content, &self.delegation_identity);
        let envelope = HttpRequestEnvelope {
            content: content.clone(),
            sender_delegation: Some(vec![ic_types::messages::SignedDelegation::new(
                ic_types::messages::Delegation::new(
                    self.signed_delegation.delegation.pubkey.clone().into_vec(),
                    Time::from_nanos_since_unix_epoch(self.signed_delegation.delegation.expiration),
                ),
                self.signed_delegation.signature.clone().into_vec(),
            )]),
            sender_pubkey: Some(Blob(self.pubkey.clone().into_vec())),
            sender_sig: Some(Blob(signature.signature.unwrap())),
        };
        let body = serde_cbor::ser::to_vec(&envelope).unwrap();
        let _ = self.send_http_request("call", canister_id, body).await;
        request_id
    }

    pub async fn query(
        &self,
        canister_id: &Principal,
        method_name: &str,
        arg: Blob,
    ) -> HttpQueryResponse {
        let content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(canister_id.as_slice().to_vec()),
                method_name: method_name.to_string(),
                arg,
                sender: self.sender(),
                ingress_expiry: expiry_time().as_nanos() as u64,
                nonce: None,
            },
        };
        let signature = sign_query(&content, &self.delegation_identity);
        let envelope = HttpRequestEnvelope {
            content: content.clone(),
            sender_delegation: Some(vec![ic_types::messages::SignedDelegation::new(
                ic_types::messages::Delegation::new(
                    self.signed_delegation.delegation.pubkey.clone().into_vec(),
                    Time::from_nanos_since_unix_epoch(self.signed_delegation.delegation.expiration),
                ),
                self.signed_delegation.signature.clone().into_vec(),
            )]),
            sender_pubkey: Some(Blob(self.pubkey.clone().into_vec())),
            sender_sig: Some(Blob(signature.signature.unwrap())),
        };
        let body = serde_cbor::ser::to_vec(&envelope).unwrap();
        let response = self.send_http_request("query", canister_id, body).await;
        let response_bytes = response.bytes().await.unwrap();
        serde_cbor::from_slice(&response_bytes).unwrap()
    }
}

pub fn sign_read_state(content: &HttpReadStateContent, identity: &impl Identity) -> Blob {
    let mut msg = b"\x0Aic-request".to_vec();
    msg.extend(content.representation_independent_hash());
    let sig = identity.sign(&msg).unwrap();
    Blob(sig.signature.unwrap())
}

async fn register_user(agent: &Agent, public_key: Vec<u8>, ii_canister_id: Principal) {
    let data = agent
        .update(&ii_canister_id, "create_challenge")
        .with_arg(candid::encode_one(()).unwrap())
        .call_and_wait(delay())
        .await
        .unwrap();
    let challenge: Challenge = candid::decode_one(&data).unwrap();
    let device = DeviceData {
        pubkey: ByteBuf::from(public_key),
        alias: "test key".to_string(),
        credential_id: None,
        purpose: Purpose::Authentication,
        key_type: KeyType::Unknown,
        protection: DeviceProtection::Unprotected,
    };
    let data: Vec<u8> = agent
        .update(&ii_canister_id, "register")
        .with_arg(
            candid::encode_args((
                device,
                ChallengeAttempt {
                    chars: "a".to_string(),
                    key: challenge.challenge_key,
                },
            ))
            .unwrap(),
        )
        .call_and_wait(delay())
        .await
        .unwrap();
    let register_response: RegisterResponse = candid::decode_one(&data).unwrap();
    assert_eq!(
        register_response,
        RegisterResponse::Registered {
            user_number: 10_000
        }
    );
}

async fn create_delegation(
    agent: &Agent,
    delegation_pubkey: Vec<u8>,
    ii_canister_id: Principal,
    canister_url: String,
) -> (SignedDelegation, UserKey) {
    let data: Vec<u8> = agent
        .update(&ii_canister_id, "prepare_delegation")
        .with_arg(
            candid::encode_args((
                10_000u64,
                canister_url.clone(),
                ByteBuf::from(delegation_pubkey.clone()),
                None::<u64>,
            ))
            .unwrap(),
        )
        .call_and_wait(delay())
        .await
        .unwrap();
    let (ii_derived_public_key, timestamp): (UserKey, Timestamp) =
        candid::decode_args(&data).unwrap();
    let data: Vec<u8> = agent
        .query(&ii_canister_id, "get_delegation")
        .with_arg(
            candid::encode_args((
                10_000u64,
                canister_url,
                ByteBuf::from(delegation_pubkey.clone()),
                timestamp,
            ))
            .unwrap(),
        )
        .call()
        .await
        .unwrap();
    let delegation_response: GetDelegationResponse = candid::decode_one(&data).unwrap();
    let signed_delegation = match delegation_response {
        GetDelegationResponse::SignedDelegation(delegation) => delegation,
        GetDelegationResponse::NoSuchDelegation => {
            panic!("unexpected get_delegation result: NoSuchDelegation")
        }
    };
    (signed_delegation, ii_derived_public_key)
}

async fn install_universal_canister(
    agent: &Agent,
    effective_canister_id: PrincipalId,
) -> Principal {
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait(delay())
        .await
        .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))
        .unwrap()
        .0;
    mgr.install_code(&canister_id, UNIVERSAL_CANISTER_WASM)
        .with_raw_arg(wasm().build())
        .call_and_wait(delay())
        .await
        .map_err(|err| format!("Couldn't install universal canister: {}", err))
        .unwrap();
    canister_id
}
