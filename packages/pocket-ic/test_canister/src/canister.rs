use candid::{CandidType, Nat, Principal, define_function};
use ic_cdk::api::{
    accept_message, canister_self, debug_print, instruction_counter, msg_arg_data, msg_reject,
};
use ic_cdk::call::{Call, Error as CallError, RejectCode};
use ic_cdk::stable::{stable_grow, stable_size as raw_stable_size, stable_write};
use ic_cdk::{inspect_message, query, trap, update};
use ic_cdk_management_canister::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, EcdsaPublicKeyResult, HttpMethod, HttpRequestArgs,
    HttpRequestResult, SignWithEcdsaArgs, SignWithEcdsaResult, TransformArgs, TransformContext,
    TransformFunc, ecdsa_public_key as ic_cdk_ecdsa_public_key,
    http_request as canister_http_outcall,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// The reject code that `canister_http` reports back to its callers.
///
/// The variants and their ordering define the `RejectionCode` variant declared in
/// `canister.did`, so the numbering must stay in sync with the reject codes of the
/// [IC interface specification](https://docs.internetcomputer.org/references/ic-interface-spec/https-interface/#reject-codes).
#[derive(Copy, Clone, Debug, CandidType, Deserialize)]
pub enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    SysUnknown,
    /// The reject code reported by the system is not one the interface
    /// specification defines.
    Unknown,
}

impl RejectionCode {
    /// Translates a raw reject code, as reported by the system, into the variant
    /// this canister exposes over Candid.
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::NoError,
            1 => Self::SysFatal,
            2 => Self::SysTransient,
            3 => Self::DestinationInvalid,
            4 => Self::CanisterReject,
            5 => Self::CanisterError,
            6 => Self::SysUnknown,
            _ => Self::Unknown,
        }
    }
}

/// Translates a failed call into the reject code and message the endpoints below
/// report back over Candid.
///
/// The match is deliberately exhaustive (rather than using a catch-all arm) so
/// that a new [`CallError`] variant forces us to revisit this mapping.
fn map_call_error(err: impl Into<CallError>) -> (RejectionCode, String) {
    match err.into() {
        // The call was rejected and the system assigned a reject code; report it.
        CallError::CallRejected(rejected) => (
            RejectionCode::from_raw(rejected.raw_reject_code()),
            rejected.reject_message().to_string(),
        ),
        // None of these carry a system-assigned reject code, so there is no
        // faithful code to report; surface them as `Unknown`.
        err @ (CallError::CandidDecodeFailed(_)
        | CallError::InsufficientLiquidCycleBalance(_)
        | CallError::CallPerformFailed(_)) => (RejectionCode::Unknown, err.to_string()),
    }
}

// HTTP gateway interface

pub type HeaderField = (String, String);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Token {}

define_function!(pub StreamingCallbackFunction : (Token) -> (StreamingCallbackHttpResponse) query);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum StreamingStrategy {
    Callback {
        callback: StreamingCallbackFunction,
        token: Token,
    },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StreamingCallbackHttpResponse {
    pub body: ByteBuf,
    pub token: Option<Token>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpGatewayRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    pub body: ByteBuf,
    pub certificate_version: Option<u16>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpGatewayResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: ByteBuf,
    pub upgrade: Option<bool>,
    pub streaming_strategy: Option<StreamingStrategy>,
}

#[query]
fn http_request(request: HttpGatewayRequest) -> HttpGatewayResponse {
    if request.method == "GET" && request.url == "/asset.txt" {
        HttpGatewayResponse {
            status_code: 200,
            headers: vec![],
            body: ByteBuf::from(b"My sample asset."),
            upgrade: None,
            streaming_strategy: None,
        }
    } else {
        HttpGatewayResponse {
            status_code: 400,
            headers: vec![],
            body: ByteBuf::from(b"The request is not supported by the test canister."),
            upgrade: None,
            streaming_strategy: None,
        }
    }
}

// Schnorr interface

#[derive(CandidType, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "bip340secp256k1")]
    Bip340Secp256k1,
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
struct SchnorrKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SchnorrPublicKeyArgument {
    pub canister_id: Option<Principal>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SchnorrPublicKeyResponse {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithSchnorrArgument {
    pub message: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
    pub aux: Option<SignWithSchnorrAux>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum SignWithSchnorrAux {
    #[serde(rename = "bip341")]
    Bip341(SignWithBip341Aux),
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct SignWithBip341Aux {
    pub merkle_root_hash: ByteBuf,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithSchnorrResponse {
    pub signature: Vec<u8>,
}

#[update]
async fn schnorr_public_key(
    canister_id: Option<Principal>,
    derivation_path: Vec<Vec<u8>>,
    key_id: SchnorrKeyId,
) -> Result<SchnorrPublicKeyResponse, String> {
    let request = SchnorrPublicKeyArgument {
        canister_id,
        derivation_path,
        key_id,
    };

    let res: SchnorrPublicKeyResponse =
        Call::unbounded_wait(Principal::management_canister(), "schnorr_public_key")
            .with_arg(&request)
            .await
            .map_err(|err| format!("schnorr_public_key failed: {err}"))?
            .candid()
            .map_err(|err| format!("could not decode the schnorr_public_key reply: {err}"))?;

    Ok(res)
}

#[update]
async fn sign_with_schnorr(
    message: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    key_id: SchnorrKeyId,
    aux: Option<SignWithSchnorrAux>,
) -> Result<Vec<u8>, String> {
    let fee = if key_id.name == "key_1" {
        26_153_846_153
    } else {
        10_000_000_000
    };
    let request = SignWithSchnorrArgument {
        message,
        derivation_path,
        key_id,
        aux,
    };

    let reply: SignWithSchnorrResponse =
        Call::unbounded_wait(Principal::management_canister(), "sign_with_schnorr")
            .with_arg(&request)
            .with_cycles(fee)
            .await
            .map_err(|err| format!("sign_with_schnorr failed: {err}"))?
            .candid()
            .map_err(|err| format!("could not decode the sign_with_schnorr reply: {err}"))?;

    Ok(reply.signature)
}

// ECDSA interface

#[update]
async fn ecdsa_public_key(
    canister_id: Option<Principal>,
    derivation_path: Vec<Vec<u8>>,
    name: String,
) -> Result<EcdsaPublicKeyResult, String> {
    let arg = EcdsaPublicKeyArgs {
        canister_id,
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name,
        },
    };
    ic_cdk_ecdsa_public_key(&arg)
        .await
        .map_err(|err| format!("ecdsa_public_key failed: {err}"))
}

#[update]
async fn sign_with_ecdsa(
    message_hash: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    name: String,
) -> Result<Vec<u8>, String> {
    let fee: u128 = if name == "key_1" {
        26_153_846_153
    } else {
        10_000_000_000
    };
    let arg = SignWithEcdsaArgs {
        message_hash,
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name,
        },
    };
    let res: SignWithEcdsaResult =
        Call::unbounded_wait(Principal::management_canister(), "sign_with_ecdsa")
            .with_arg(&arg)
            .with_cycles(fee)
            .await
            .map_err(|err| format!("sign_with_ecdsa failed: {err}"))?
            .candid()
            .map_err(|err| format!("could not decode the sign_with_ecdsa reply: {err}"))?;

    Ok(res.signature)
}

// vetKd interface

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum VetKdCurve {
    #[serde(rename = "bls12_381_g2")]
    #[allow(non_camel_case_types)]
    Bls12_381_G2,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct VetKdKeyId {
    pub curve: VetKdCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct VetKdPublicKeyArgument {
    pub canister_id: Option<Principal>,
    pub context: Vec<u8>,
    pub key_id: VetKdKeyId,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct VetKdPublicKeyResponse {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct VetKdDeriveKeyArgument {
    pub context: Vec<u8>,
    pub input: Vec<u8>,
    pub key_id: VetKdKeyId,
    pub transport_public_key: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct VetKdDeriveKeyResponse {
    pub encrypted_key: Vec<u8>,
}

#[update]
async fn vetkd_public_key(
    canister_id: Option<Principal>,
    context: Vec<u8>,
    name: String,
) -> Result<Vec<u8>, String> {
    let request = VetKdPublicKeyArgument {
        canister_id,
        context,
        key_id: VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name,
        },
    };

    let res: VetKdPublicKeyResponse =
        Call::unbounded_wait(Principal::management_canister(), "vetkd_public_key")
            .with_arg(&request)
            .await
            .map_err(|err| format!("vetkd_public_key failed: {err}"))?
            .candid()
            .map_err(|err| format!("could not decode the vetkd_public_key reply: {err}"))?;

    Ok(res.public_key)
}

#[update]
async fn vetkd_derive_key(
    context: Vec<u8>,
    input: Vec<u8>,
    name: String,
    transport_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let fee = if name == "key_1" {
        26_153_846_153
    } else {
        10_000_000_000
    };
    let request = VetKdDeriveKeyArgument {
        context,
        input,
        key_id: VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name,
        },
        transport_public_key,
    };

    let reply: VetKdDeriveKeyResponse =
        Call::unbounded_wait(Principal::management_canister(), "vetkd_derive_key")
            .with_arg(&request)
            .with_cycles(fee)
            .await
            .map_err(|err| format!("vetkd_derive_key failed: {err}"))?
            .candid()
            .map_err(|err| format!("could not decode the vetkd_derive_key reply: {err}"))?;

    Ok(reply.encrypted_key)
}

// canister HTTP outcalls

#[update]
async fn canister_http(
    http_server_addr: String,
) -> Result<HttpRequestResult, (RejectionCode, String)> {
    let arg = HttpRequestArgs {
        url: http_server_addr,
        max_response_bytes: None,
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        transform: None,
        is_replicated: None,
    };
    canister_http_outcall(&arg).await.map_err(map_call_error)
}

#[query]
async fn transform(transform_args: TransformArgs) -> HttpRequestResult {
    let mut resp = transform_args.response;
    resp.headers = vec![];
    resp.body = transform_args.context;
    resp
}

#[update]
async fn canister_http_with_transform(http_server_addr: String) -> HttpRequestResult {
    let context = b"this is my transform context".to_vec();
    let arg = HttpRequestArgs {
        url: http_server_addr,
        max_response_bytes: None,
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                method: "transform".to_string(),
                principal: canister_self(),
            }),
            context,
        }),
        is_replicated: None,
    };
    canister_http_outcall(&arg).await.unwrap()
}

// inter-canister calls

/// Proxies a call to `method` of `callee`, passing the already Candid-encoded
/// `args` verbatim and attaching `cycles` cycles.
///
/// Both the argument and the reply are passed through undecoded, so a test can use
/// the callee's authoritative Candid types instead of copies maintained here. That
/// is what makes it possible to call a management canister endpoint
/// `ic-cdk-management-canister` does not expose (`flexible_http_request`) or to set
/// a field it does not expose (`http_request`'s `pricing_version`).
#[update]
async fn proxy_call(
    callee: Principal,
    method: String,
    args: ByteBuf,
    cycles: u128,
) -> Result<ByteBuf, (RejectionCode, String)> {
    Call::unbounded_wait(callee, &method)
        .with_raw_args(&args)
        .with_cycles(cycles)
        .await
        .map(|response| ByteBuf::from(response.into_bytes()))
        .map_err(map_call_error)
}

#[update]
async fn whoami() -> String {
    canister_self().to_string()
}

#[update]
async fn whois(canister: Principal) -> String {
    Call::unbounded_wait(canister, "whoami")
        .with_arg(())
        .await
        .unwrap()
        .candid()
        .unwrap()
}

#[update]
async fn call_and_get_rejection_code(canister: Principal) -> u32 {
    let result = Call::unbounded_wait(canister, "whoami")
        .with_arg(())
        .await
        .map_err(CallError::from)
        .and_then(|response| response.candid::<String>().map_err(CallError::from));

    match result {
        Ok(_) => 0,
        Err(CallError::CallRejected(rejected)) => rejected.raw_reject_code(),
        Err(CallError::CandidDecodeFailed(_)) => RejectCode::CanisterError as u32,
        // The call never left this canister, so it may well succeed if retried.
        Err(_) => RejectCode::SysTransient as u32,
    }
}

#[update]
async fn blob_len(blob: Vec<u8>) -> usize {
    blob.len()
}

#[update]
async fn call_with_large_blob(canister: Principal, blob_len: usize) -> usize {
    Call::unbounded_wait(canister, "blob_len")
        .with_arg(vec![42_u8; blob_len])
        .await
        .unwrap()
        .candid()
        .unwrap()
}

#[derive(CandidType, Deserialize)]
pub struct NodeMetrics {
    pub node_id: Principal,
    pub num_blocks_proposed_total: u64,
    pub num_block_failures_total: u64,
}

#[derive(CandidType, Deserialize)]
pub struct NodeMetricsHistoryResponse {
    pub timestamp_nanos: u64,
    pub node_metrics: Vec<NodeMetrics>,
}

#[derive(CandidType, Deserialize)]
pub struct NodeMetricsHistoryArgs {
    pub start_at_timestamp_nanos: u64,
    pub subnet_id: Principal,
}

#[update]
async fn node_metrics_history_proxy(
    args: NodeMetricsHistoryArgs,
) -> Vec<NodeMetricsHistoryResponse> {
    Call::unbounded_wait(
        candid::Principal::management_canister(),
        "node_metrics_history",
    )
    .with_arg(&args)
    .await
    .unwrap()
    .candid()
    .unwrap()
}

// executing many instructions

#[update]
async fn execute_many_instructions(n: u64) {
    while instruction_counter() < n {}
}

// canister logs

#[update]
async fn canister_log(msg: String) {
    debug_print(msg);
}

// time

#[query]
fn time() -> u64 {
    ic_cdk::api::time()
}

// reject responses

#[inspect_message]
fn inspect_message() {
    let arg_data = msg_arg_data();
    if arg_data == b"trap" {
        trap("trap in inspect message");
    } else if arg_data == b"skip" {
    } else {
        accept_message();
    }
}

#[query(manual_reply = true)]
fn reject_query() {
    msg_reject("reject in query method");
}

#[update(manual_reply = true)]
fn reject_update() {
    msg_reject("reject in update method");
}

#[query]
fn trap_query() {
    trap("trap in query method");
}

#[update]
fn trap_update() {
    trap("trap in update method");
}

// deposit cycles to the cycles ledger
#[update]
async fn deposit_cycles_to_cycles_ledger(beneficiary: Principal, cycles: u128) {
    #[derive(CandidType)]
    struct DepositArg {
        to: Account,
        memo: Option<Memo>,
    }

    #[derive(CandidType, Deserialize)]
    struct DepositResult {
        block_index: Nat,
        balance: Nat,
    }

    let cycles_ledger_id = Principal::from_text("um5iw-rqaaa-aaaaq-qaaba-cai").unwrap();
    let deposit_arg = DepositArg {
        to: Account {
            owner: beneficiary,
            subaccount: None,
        },
        memo: None,
    };
    let _deposit_result: DepositResult = Call::unbounded_wait(cycles_ledger_id, "deposit")
        .with_arg(&deposit_arg)
        .with_cycles(cycles)
        .await
        .unwrap()
        .candid()
        .unwrap();
}

#[query]
fn stable_size() -> u64 {
    raw_stable_size()
}

#[update]
fn stable_grow_and_fill(pages: u64) {
    let offset = stable_size();
    stable_grow(pages).unwrap();
    let mut content = vec![0_u8; 1 << 16];
    for (i, elem) in content.iter_mut().enumerate() {
        *elem = (i % 256) as u8;
    }
    for i in 0..pages {
        stable_write((offset + i) << 16, &content);
    }
}

fn main() {}
