#![allow(deprecated)]
use candid::{CandidType, Principal};
use futures::future::join_all;
use ic_cdk::api::management_canister::ecdsa::{
    EcdsaKeyId, EcdsaPublicKeyArgument, SignWithEcdsaArgument,
    ecdsa_public_key as ic_cdk_ecdsa_public_key, sign_with_ecdsa as ic_cdk_sign_with_ecdsa,
};
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader as IcCdkHttpHeader, HttpMethod,
    http_request as ic_cdk_http_request,
};
use ic_cdk::api::management_canister::main::{
    CanisterInstallMode, CanisterSettings, CreateCanisterArgument, InstallCodeArgument,
    UpdateSettingsArgument, create_canister as ic_cdk_create_canister,
    install_code as ic_cdk_install_code, update_settings as ic_cdk_update_settings,
};
use ic_cdk::update;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct CreateCanistersArgs {
    pub canisters_number: u64,
    pub canisters_per_batch: u64,
    pub initial_cycles: u128,
}

#[update]
async fn create_canisters(args: CreateCanistersArgs) -> Vec<Principal> {
    let mut result = vec![];
    let mut remaining_canisters = args.canisters_number;
    while remaining_canisters > 0 {
        let batch_size = args.canisters_per_batch.min(remaining_canisters);
        let futures: Vec<_> = (0..batch_size)
            .map(|_| {
                ic_cdk_create_canister(
                    CreateCanisterArgument {
                        settings: Some(CanisterSettings {
                            controllers: Some(vec![ic_cdk::api::id()]),
                            ..CanisterSettings::default()
                        }),
                    },
                    args.initial_cycles,
                )
            })
            .collect();

        let batch_results = join_all(futures).await;

        let mut batch_ids: Vec<_> = batch_results
            .into_iter()
            .map(|r| {
                let (canister_id_record,) = r.unwrap(); // Reject if there is an error.
                canister_id_record.canister_id
            })
            .collect();
        result.append(&mut batch_ids);
        remaining_canisters -= batch_size;
    }
    result
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct InstallCodeArgs {
    pub canister_ids: Vec<Principal>,
    pub wasm_module_size: u64,
    pub arg_size: u64,
}

#[update]
async fn install_code(args: InstallCodeArgs) {
    if args.wasm_module_size == 0 {
        return;
    }
    let wasm_module = vec![42; args.wasm_module_size as usize];
    let arg = vec![27; args.arg_size as usize];
    let futures: Vec<_> = args
        .canister_ids
        .into_iter()
        .map(|canister_id| {
            ic_cdk_install_code(InstallCodeArgument {
                mode: CanisterInstallMode::Install,
                canister_id,
                wasm_module: wasm_module.clone(),
                arg: arg.clone(),
            })
        })
        .collect();

    let results = join_all(futures).await;

    results.into_iter().for_each(|r| {
        r.unwrap(); // Reject if there is an error.
    });
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateSettingsArgs {
    pub canister_ids: Vec<Principal>,
    pub controllers_number: u64,
}

#[update]
async fn update_settings(args: UpdateSettingsArgs) {
    let controllers = vec![ic_cdk::api::id(); args.controllers_number as usize];
    let futures: Vec<_> = args
        .canister_ids
        .into_iter()
        .map(|canister_id| {
            ic_cdk_update_settings(UpdateSettingsArgument {
                canister_id,
                settings: CanisterSettings {
                    controllers: Some(controllers.clone()),
                    ..CanisterSettings::default()
                },
            })
        })
        .collect();

    let results = join_all(futures).await;

    results.into_iter().for_each(|r| {
        r.unwrap(); // Reject if there is an error.
    });
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct ECDSAArgs {
    pub ecdsa_key: EcdsaKeyId,
    pub calls: u64,
    pub derivation_paths: u64,
    pub buf_size: u64,
}

#[update]
async fn ecdsa_public_key(args: ECDSAArgs) {
    let futures: Vec<_> = (0..args.calls)
        .map(|_| {
            ic_cdk_ecdsa_public_key(EcdsaPublicKeyArgument {
                canister_id: None,
                derivation_path: vec![
                    vec![0_u8; args.buf_size as usize];
                    args.derivation_paths as usize
                ],
                key_id: args.ecdsa_key.clone(),
            })
        })
        .collect();

    let results = join_all(futures).await;

    results.into_iter().for_each(|r| {
        r.unwrap(); // Reject if there is an error.
    });
}

#[update]
async fn sign_with_ecdsa(args: ECDSAArgs) {
    let futures: Vec<_> = (0..args.calls)
        .map(|_| {
            ic_cdk_sign_with_ecdsa(SignWithEcdsaArgument {
                message_hash: vec![0; 32],
                derivation_path: vec![
                    vec![0_u8; args.buf_size as usize];
                    args.derivation_paths as usize
                ],
                key_id: args.ecdsa_key.clone(),
            })
        })
        .collect();

    let results = join_all(futures).await;

    results.into_iter().for_each(|r| {
        r.unwrap(); // Reject if there is an error.
    });
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct HttpRequestArgs {
    pub calls: u64,
    pub headers_number: u64,
    pub header: HttpHeader,
    pub cycles: u128,
}

#[update]
async fn http_request(args: HttpRequestArgs) {
    let futures: Vec<_> = (0..args.calls)
        .map(|_| {
            ic_cdk_http_request(
                CanisterHttpRequestArgument {
                    url: String::from("www.example.com"),
                    max_response_bytes: None,
                    method: HttpMethod::GET,
                    headers: vec![
                        IcCdkHttpHeader {
                            name: args.header.name.clone(),
                            value: args.header.value.clone(),
                        };
                        args.headers_number as usize
                    ],
                    body: None,
                    transform: None,
                },
                args.cycles,
            )
        })
        .collect();

    let results = join_all(futures).await;

    results.into_iter().for_each(|r| {
        r.unwrap(); // Reject if there is an error.
    });
}

fn main() {}
