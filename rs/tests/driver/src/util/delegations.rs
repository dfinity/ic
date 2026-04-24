use crate::util::agent_with_identity;

use candid::{CandidType, Deserialize, Principal};
use canister_test::PrincipalId;
use ic_agent::Agent;
use ic_agent::identity::{BasicIdentity, DelegatedIdentity};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_utils::interfaces::ManagementCanister;
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::collections::HashMap;

/// user ids start with 10000 and increase by 1 for each new user
pub const USER_NUMBER_OFFSET: u64 = 10_000;

pub type AnchorNumber = u64;

pub type CredentialId = ByteBuf;
pub type PublicKey = ByteBuf;
pub type UserKey = PublicKey;
// in nanos since epoch
type Timestamp = u64;
type Signature = ByteBuf;

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CandidDelegation {
    pubkey: PublicKey,
    expiration: Timestamp,
    targets: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CandidSignedDelegation {
    delegation: CandidDelegation,
    signature: Signature,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
enum GetDelegationResponse {
    #[serde(rename = "signed_delegation")]
    SignedDelegation(CandidSignedDelegation),
    #[serde(rename = "no_such_delegation")]
    NoSuchDelegation,
}

fn to_agent_signed_delegation(d: CandidSignedDelegation) -> ic_agent::identity::SignedDelegation {
    ic_agent::identity::SignedDelegation {
        delegation: ic_agent::identity::Delegation {
            pubkey: d.delegation.pubkey.into_vec(),
            expiration: d.delegation.expiration,
            targets: d.delegation.targets,
        },
        signature: d.signature.into_vec(),
    }
}

pub async fn agent_with_delegation(
    url: &str,
    ii_derived_public_key: Vec<u8>,
    signed_delegation: ic_agent::identity::SignedDelegation,
    delegation_identity: BasicIdentity,
) -> Agent {
    let delegated_identity = DelegatedIdentity::new_unchecked(
        ii_derived_public_key,
        Box::new(delegation_identity),
        vec![signed_delegation],
    );
    agent_with_identity(url, delegated_identity).await.unwrap()
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
) -> (ic_agent::identity::SignedDelegation, UserKey) {
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
    let candid_signed_delegation = match delegation_response {
        GetDelegationResponse::SignedDelegation(delegation) => delegation,
        GetDelegationResponse::NoSuchDelegation => {
            panic!("unexpected get_delegation result: NoSuchDelegation")
        }
    };
    (
        to_agent_signed_delegation(candid_signed_delegation),
        ii_derived_public_key,
    )
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
