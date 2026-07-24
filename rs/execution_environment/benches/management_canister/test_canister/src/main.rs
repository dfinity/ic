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
    CanisterIdRecord, CanisterInstallMode, CanisterSettings, CreateCanisterArgument,
    InstallCodeArgument, UpdateSettingsArgument, create_canister as ic_cdk_create_canister,
    delete_canister as ic_cdk_delete_canister, install_code as ic_cdk_install_code,
    stop_canister as ic_cdk_stop_canister, update_settings as ic_cdk_update_settings,
};
use ic_cdk::call::Call;
use ic_cdk::{api::canister_self, update};
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
                            controllers: Some(vec![canister_self()]),
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

/// Creates `2 * args.canisters_number` canisters and then deletes every other
/// one (in canister ID order), leaving `args.canisters_number` canisters
/// separated by gaps. As a result, the management canister's `list_canisters`
/// method reports (roughly) one ID range per remaining canister. Returns the
/// number of remaining canisters.
#[update]
async fn create_canisters_with_gaps(args: CreateCanistersArgs) -> u64 {
    let mut canister_ids = create_canisters(CreateCanistersArgs {
        canisters_number: args.canisters_number * 2,
        canisters_per_batch: args.canisters_per_batch,
        initial_cycles: args.initial_cycles,
    })
    .await;

    // Canister ID principals encode the canister index in big-endian order, so
    // sorting by the principal's bytes yields the numeric canister ID order.
    canister_ids.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));

    // Delete every other canister so that the remaining ones are separated by
    // gaps (i.e. each remaining canister forms its own ID range).
    let to_delete: Vec<Principal> = canister_ids.iter().skip(1).step_by(2).copied().collect();
    let mut remaining = to_delete.as_slice();
    while !remaining.is_empty() {
        let batch_size = (args.canisters_per_batch as usize).min(remaining.len());
        let (batch, rest) = remaining.split_at(batch_size);
        remaining = rest;

        // A canister must be stopped before it can be deleted.
        let stop_futures: Vec<_> = batch
            .iter()
            .map(|canister_id| {
                ic_cdk_stop_canister(CanisterIdRecord {
                    canister_id: *canister_id,
                })
            })
            .collect();
        join_all(stop_futures).await.into_iter().for_each(|r| {
            r.unwrap(); // Reject if there is an error.
        });

        let delete_futures: Vec<_> = batch
            .iter()
            .map(|canister_id| {
                ic_cdk_delete_canister(CanisterIdRecord {
                    canister_id: *canister_id,
                })
            })
            .collect();
        join_all(delete_futures).await.into_iter().for_each(|r| {
            r.unwrap(); // Reject if there is an error.
        });
    }

    (canister_ids.len() - to_delete.len()) as u64
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
    let controllers = vec![canister_self(); args.controllers_number as usize];
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

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct CanisterIdRange {
    pub start: Principal,
    pub end: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct ListCanistersResult {
    pub canisters: Vec<CanisterIdRange>,
}

/// Calls the management canister's `list_canisters` method (which takes no
/// arguments) and returns the number of canister ID ranges reported for the
/// subnet. This canister must be a subnet admin for the call to succeed.
#[update]
async fn list_canisters() -> u64 {
    let result: ListCanistersResult =
        Call::unbounded_wait(Principal::management_canister(), "list_canisters")
            .await
            .expect("list_canisters call failed")
            .candid()
            .expect("failed to decode list_canisters response");
    result.canisters.len() as u64
}

fn main() {}
