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
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::time::{Duration, Instant};

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
pub enum Purpose {
    #[serde(rename = "recovery")]
    Recovery,
    #[serde(rename = "authentication")]
    Authentication,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum DeviceProtection {
    #[serde(rename = "protected")]
    Protected,
    #[serde(rename = "unprotected")]
    Unprotected,
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
            sender_info: None,
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
                sender_info: None,
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

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum RegistrationFlowNextStep {
    /// Supply the captcha solution using check_captcha
    CheckCaptcha { captcha_png_base64: String },
    /// Finish the registration using identity_registration_finish
    Finish,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum IdRegStartError {
    RateLimitExceeded,
    InvalidCaller,
    AlreadyInProgress,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct IdRegNextStepResult {
    pub next_step: RegistrationFlowNextStep,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct PublicKeyAuthn {
    pub pubkey: PublicKey,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct WebAuthn {
    pub pubkey: PublicKey,
    pub credential_id: CredentialId,
    pub aaguid: Option<Vec<u8>>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum AuthnMethod {
    WebAuthn(WebAuthn),
    PubKey(PublicKeyAuthn),
}

#[derive(Eq, PartialEq, Clone, Debug, CandidType, Deserialize)]
pub enum MetadataEntryV2 {
    String(String),
    Bytes(ByteBuf),
    Map(HashMap<String, MetadataEntryV2>),
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum AuthnMethodProtection {
    Protected,
    Unprotected,
}

#[derive(Eq, PartialEq, Clone, Debug, CandidType, Deserialize)]
pub enum AuthnMethodPurpose {
    Recovery,
    Authentication,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct AuthnMethodSecuritySettings {
    pub protection: AuthnMethodProtection,
    pub purpose: AuthnMethodPurpose,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct AuthnMethodData {
    pub authn_method: AuthnMethod,
    pub security_settings: AuthnMethodSecuritySettings,
    pub metadata: HashMap<String, MetadataEntryV2>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct IdRegFinishArg {
    pub authn_method: AuthnMethodData,
    pub name: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct IdRegFinishResult {
    pub identity_number: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum IdRegFinishError {
    UnexpectedCall { next_step: RegistrationFlowNextStep },
    NoRegistrationFlow,
    InvalidAuthnMethod(String),
    StorageError(String),
}

#[derive(CandidType, Serialize)]
enum StaticCaptchaTrigger {
    #[allow(dead_code)]
    CaptchaEnabled,
    CaptchaDisabled,
}

#[derive(CandidType, Serialize)]
enum CaptchaTrigger {
    #[allow(dead_code)]
    Dynamic,
    Static(StaticCaptchaTrigger),
}

#[derive(CandidType, Serialize)]
struct CaptchaConfig {
    pub max_unsolved_captchas: u64,
    pub captcha_trigger: CaptchaTrigger,
}

#[derive(CandidType, Serialize)]
struct InternetIdentityInit {
    pub captcha_config: Option<CaptchaConfig>,
}

pub fn build_internet_identity_backend_install_arg() -> Vec<u8> {
    candid::encode_one(&InternetIdentityInit {
        captcha_config: Some(CaptchaConfig {
            max_unsolved_captchas: 50,
            captcha_trigger: CaptchaTrigger::Static(StaticCaptchaTrigger::CaptchaDisabled),
        }),
    })
    .unwrap()
}

pub async fn register_user(
    agent: &Agent,
    public_key: Vec<u8>,
    ii_canister_id: Principal,
    expected_user_id: u64,
) {
    let data = agent
        .update(&ii_canister_id, "identity_registration_start")
        .with_arg(candid::encode_one(()).unwrap())
        .call_and_wait()
        .await
        .unwrap();

    let result: Result<IdRegNextStepResult, IdRegStartError> = candid::decode_one(&data).unwrap();

    let IdRegNextStepResult {
        next_step: RegistrationFlowNextStep::Finish,
    } = result.expect("identity_registration_start failed")
    else {
        panic!(
            "Expected the next step to be Finish, but got CheckCaptcha with captcha. \
             Make sure to initialize internet_identity_backend with CaptchaDisabled for tests.",
        );
    };

    let authn_method = AuthnMethodData {
        authn_method: AuthnMethod::WebAuthn(WebAuthn {
            pubkey: ByteBuf::from(public_key),
            // Not used for this device type
            credential_id: ByteBuf::from([0xde, 0xad, 0xbe, 0xef]),
            aaguid: None,
        }),
        // Does not matter for the test, but unfortunately not optional.
        security_settings: AuthnMethodSecuritySettings {
            protection: AuthnMethodProtection::Unprotected,
            purpose: AuthnMethodPurpose::Authentication,
        },
        // This passkey isn't going to be used from a web browser, so mocking out its
        // origin is fine for the test.
        metadata: [(
            "origin".to_string(),
            MetadataEntryV2::String("https://id.ai".to_string()),
        )]
        .into_iter()
        .collect(),
    };
    let data: Vec<u8> = agent
        .update(&ii_canister_id, "identity_registration_finish")
        .with_arg(
            candid::encode_one(IdRegFinishArg {
                authn_method,
                name: Some("test user".to_string()),
            })
            .unwrap(),
        )
        .call_and_wait()
        .await
        .unwrap();

    let register_response: Result<IdRegFinishResult, IdRegFinishError> =
        candid::decode_one(&data).unwrap();

    let IdRegFinishResult { identity_number } = register_response.unwrap();

    assert_eq!(identity_number, expected_user_id);
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
