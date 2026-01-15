use crate::util::{expiry_time, sign_query, sign_update};

use super::sign_read_state;
use candid::{CandidType, Deserialize, Principal};
use canister_test::PrincipalId;
use ic_agent::Agent;
use ic_agent::identity::BasicIdentity;
use ic_crypto_tree_hash::Path;
use ic_types::Time;
use ic_types::messages::{
    Blob, Certificate, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpQueryResponse,
    HttpReadState, HttpReadStateContent, HttpReadStateResponse, HttpRequestEnvelope, HttpUserQuery,
    MessageId,
};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_utils::interfaces::ManagementCanister;
use reqwest::{Client, Response};
use serde_bytes::ByteBuf;
use std::time::{Duration, Instant};

pub const COUNTER_CANISTER_WAT: &str = "rs/tests/counter.wat";
pub const UPDATE_POLLING_TIMEOUT: Duration = Duration::from_secs(10);
/// user ids start with 10000 and increase by 1 for each new user
pub const USER_NUMBER_OFFSET: u64 = 10_000;

pub type AnchorNumber = u64;

pub type CredentialId = ByteBuf;
pub type PublicKey = ByteBuf;
pub type DeviceKey = PublicKey;
pub type UserKey = PublicKey;
// in nanos since epoch
pub type Timestamp = u64;
type Signature = ByteBuf;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
struct DeviceData {
    pub pubkey: DeviceKey,
    pub alias: String,
    pub credential_id: Option<CredentialId>,
    pub purpose: Purpose,
    pub key_type: KeyType,
    pub protection: DeviceProtection,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum Purpose {
    #[serde(rename = "recovery")]
    Recovery,
    #[serde(rename = "authentication")]
    Authentication,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
enum RegisterResponse {
    #[serde(rename = "registered")]
    Registered { user_number: AnchorNumber },
    #[serde(rename = "canister_full")]
    CanisterFull,
    #[serde(rename = "bad_challenge")]
    BadChallenge,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
enum KeyType {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross_platform")]
    CrossPlatform,
    #[serde(rename = "seed_phrase")]
    SeedPhrase,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum DeviceProtection {
    #[serde(rename = "protected")]
    Protected,
    #[serde(rename = "unprotected")]
    Unprotected,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Challenge {
    pub png_base64: String,
    pub challenge_key: ChallengeKey,
}

type ChallengeKey = String;

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
enum GetDelegationResponse {
    #[serde(rename = "signed_delegation")]
    SignedDelegation(SignedDelegation),
    #[serde(rename = "no_such_delegation")]
    NoSuchDelegation,
}

pub struct AgentWithDelegation<'a> {
    pub node_url: url::Url,
    pub pubkey: UserKey,
    pub signed_delegation: SignedDelegation,
    pub delegation_identity: &'a BasicIdentity,
    pub polling_timeout: Duration,
}

impl AgentWithDelegation<'_> {
    async fn send_http_request(
        &self,
        method: &str,
        canister_id: &Principal,
        body: Vec<u8>,
    ) -> Response {
        let client = Client::new();
        client
            .post(format!(
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
        let signature = sign_update(&content, self.delegation_identity);
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
        let signature = sign_query(&content, self.delegation_identity);
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
        let sig = sign_read_state(&content, self.delegation_identity);
        let read_state_envelope: HttpRequestEnvelope<HttpReadStateContent> = HttpRequestEnvelope {
            content,
            sender_pubkey: Some(Blob(self.pubkey.clone().into_vec())),
            sender_sig: Some(Blob(sig.signature.unwrap())),
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
}

pub async fn register_user(
    agent: &Agent,
    public_key: Vec<u8>,
    ii_canister_id: Principal,
    expected_user_id: u64,
) {
    let data = agent
        .update(&ii_canister_id, "create_challenge")
        .with_arg(candid::encode_one(()).unwrap())
        .call_and_wait()
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
        .call_and_wait()
        .await
        .unwrap();
    let register_response: RegisterResponse = candid::decode_one(&data).unwrap();
    assert_eq!(
        register_response,
        RegisterResponse::Registered {
            user_number: expected_user_id
        }
    );
}

pub async fn create_delegation(
    agent: &Agent,
    delegation_pubkey: Vec<u8>,
    ii_canister_id: Principal,
    canister_url: String,
    user_id: u64,
) -> (SignedDelegation, UserKey) {
    let data: Vec<u8> = agent
        .update(&ii_canister_id, "prepare_delegation")
        .with_arg(
            candid::encode_args((
                user_id,
                canister_url.clone(),
                ByteBuf::from(delegation_pubkey.clone()),
                None::<u64>,
            ))
            .unwrap(),
        )
        .call_and_wait()
        .await
        .unwrap();
    let (ii_derived_public_key, timestamp): (UserKey, Timestamp) =
        candid::decode_args(&data).unwrap();
    let data: Vec<u8> = agent
        .query(&ii_canister_id, "get_delegation")
        .with_arg(
            candid::encode_args((
                user_id,
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

pub async fn install_universal_canister(
    agent: &Agent,
    effective_canister_id: PrincipalId,
) -> Principal {
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't create canister with provisional API: {err}"))
        .unwrap()
        .0;
    mgr.install_code(&canister_id, &UNIVERSAL_CANISTER_WASM)
        .with_raw_arg(wasm().build())
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't install universal canister: {err}"))
        .unwrap();
    canister_id
}
