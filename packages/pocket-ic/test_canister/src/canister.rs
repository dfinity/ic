use candid::{define_function, CandidType, Principal};
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key as ic_cdk_ecdsa_public_key, sign_with_ecdsa as ic_cdk_sign_with_ecdsa,
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument, EcdsaPublicKeyResponse, SignWithEcdsaArgument,
};
use ic_cdk::api::management_canister::http_request::{
    http_request as canister_http_outcall, CanisterHttpRequestArgument, HttpMethod, HttpResponse,
    TransformArgs, TransformContext, TransformFunc,
};
use ic_cdk::{query, update};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

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
            status_code: 404,
            headers: vec![],
            body: ByteBuf::from(b"Not Found."),
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

    let (res,): (SchnorrPublicKeyResponse,) = ic_cdk::call(
        Principal::management_canister(),
        "schnorr_public_key",
        (request,),
    )
    .await
    .map_err(|e| format!("schnorr_public_key failed {}", e.1))?;

    Ok(res)
}

#[update]
async fn sign_with_schnorr(
    message: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    key_id: SchnorrKeyId,
) -> Result<Vec<u8>, String> {
    let internal_request = SignWithSchnorrArgument {
        message,
        derivation_path,
        key_id,
    };

    let (internal_reply,): (SignWithSchnorrResponse,) = ic_cdk::api::call::call_with_payment(
        Principal::management_canister(),
        "sign_with_schnorr",
        (internal_request,),
        25_000_000_000,
    )
    .await
    .map_err(|e| format!("sign_with_schnorr failed {e:?}"))?;

    Ok(internal_reply.signature)
}

// ECDSA interface

#[update]
async fn ecdsa_public_key(
    canister_id: Option<Principal>,
    derivation_path: Vec<Vec<u8>>,
    name: String,
) -> Result<EcdsaPublicKeyResponse, String> {
    let arg = EcdsaPublicKeyArgument {
        canister_id,
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name,
        },
    };
    Ok(ic_cdk_ecdsa_public_key(arg)
        .await
        .map_err(|(code, msg)| format!("Reject code: {:?}; Reject message: {}", code, msg))?
        .0)
}

#[update]
async fn sign_with_ecdsa(
    message_hash: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    name: String,
) -> Result<Vec<u8>, String> {
    let arg = SignWithEcdsaArgument {
        message_hash,
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name,
        },
    };
    Ok(ic_cdk_sign_with_ecdsa(arg)
        .await
        .map_err(|(code, msg)| format!("Reject code: {:?}; Reject message: {}", code, msg))?
        .0
        .signature)
}

// canister HTTP outcalls

#[update]
async fn canister_http() -> Result<HttpResponse, (RejectionCode, String)> {
    let arg: CanisterHttpRequestArgument = CanisterHttpRequestArgument {
        url: "https://example.com".to_string(),
        max_response_bytes: None,
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        transform: None,
    };
    let cycles = 20_849_238_800; // magic number derived from the error message when setting this to zero
    canister_http_outcall(arg, cycles).await.map(|resp| resp.0)
}

#[query]
async fn transform(transform_args: TransformArgs) -> HttpResponse {
    let mut resp = transform_args.response;
    resp.headers = vec![];
    resp.body = transform_args.context;
    resp
}

#[update]
async fn canister_http_with_transform() -> HttpResponse {
    let context = b"this is my transform context".to_vec();
    let arg: CanisterHttpRequestArgument = CanisterHttpRequestArgument {
        url: "https://example.com".to_string(),
        max_response_bytes: None,
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                method: "transform".to_string(),
                principal: ic_cdk::id(),
            }),
            context,
        }),
    };
    let cycles = 20_849_431_200; // magic number derived from the error message when setting this to zero
    canister_http_outcall(arg, cycles).await.unwrap().0
}

// inter-canister calls

#[update]
async fn whoami() -> String {
    ic_cdk::id().to_string()
}

#[update]
async fn whois(canister: Principal) -> String {
    ic_cdk::call::<_, (String,)>(canister, "whoami", ((),))
        .await
        .unwrap()
        .0
}

#[update]
async fn blob_len(blob: Vec<u8>) -> usize {
    blob.len()
}

#[update]
async fn call_with_large_blob(canister: Principal, blob_len: usize) -> usize {
    ic_cdk::call::<_, (usize,)>(canister, "blob_len", (vec![42_u8; blob_len],))
        .await
        .unwrap()
        .0
}

fn main() {}
