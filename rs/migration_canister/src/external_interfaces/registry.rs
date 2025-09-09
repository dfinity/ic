use std::convert::Infallible;

use candid::{CandidType, Principal};
use ic_cdk::{call::Call, println};
use serde::Deserialize;

use crate::{processing::ProcessingResult, ValidationError};

const REGISTRY_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";

#[derive(Clone, Debug, CandidType, Deserialize)]
struct GetSubnetForCanisterArgs {
    principal: Option<Principal>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct GetSubnetForCanisterResponse {
    subnet_id: Option<Principal>,
}

pub async fn get_subnet_for_canister(
    canister_id: Principal,
) -> ProcessingResult<Principal, ValidationError> {
    let args = GetSubnetForCanisterArgs {
        principal: Some(canister_id),
    };

    match Call::bounded_wait(
        Principal::from_text(REGISTRY_CANISTER_ID).unwrap(),
        "get_subnet_for_canister",
    )
    .with_arg(args)
    .await
    {
        Err(e) => {
            println!(
                "Call `get_subnet_for_canister` for {:?} failed: {:?}",
                canister_id, e
            );
            ProcessingResult::NoProgress
        }
        Ok(response) => match response.candid::<Result<GetSubnetForCanisterResponse, String>>() {
            Ok(Ok(GetSubnetForCanisterResponse { subnet_id })) => match subnet_id {
                None => ProcessingResult::FatalFailure(ValidationError::CanisterNotFound {
                    canister: canister_id,
                }),
                Some(subnet_id) => ProcessingResult::Success(subnet_id),
            },
            Ok(Err(e)) => {
                println!(
                    "Decoding `GetSubnetForCanisterResponse` for {:?} failed: {:?}",
                    canister_id, e
                );
                ProcessingResult::NoProgress
            }
            Err(e) => {
                println!(
                    "Decoding `GetSubnetForCanisterResponse` for {:?} failed: {:?}",
                    canister_id, e
                );
                ProcessingResult::NoProgress
            }
        },
    }
}

// ========================================================================= //
// `migrate_canisters`

#[derive(Clone, Debug, CandidType, Deserialize)]
struct MigrateCanistersArgs {
    canister_ids: Vec<Principal>,
    target_subnet_id: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct MigrateCanisterResponse {
    registry_version: u64,
}

pub async fn migrate_canister(
    source: Principal,
    target_subnet: Principal,
) -> ProcessingResult<u64, Infallible> {
    let args = MigrateCanistersArgs {
        canister_ids: vec![source],
        target_subnet_id: target_subnet,
    };

    match Call::bounded_wait(
        Principal::from_text(REGISTRY_CANISTER_ID).unwrap(),
        "migrate_canisters",
    )
    .with_arg(args)
    .await
    {
        Err(e) => {
            println!("Call `migrate_canisters` for {:?} failed: {:?}", source, e);
            ProcessingResult::NoProgress
        }
        Ok(_) => ProcessingResult::Success(42 /* TODO */),
    }
}
