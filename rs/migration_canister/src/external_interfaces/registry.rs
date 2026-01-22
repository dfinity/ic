use std::convert::Infallible;

use candid::{CandidType, Principal};
use ic_cdk::{call::Call, println};
use serde::Deserialize;

use crate::{ValidationError, processing::ProcessingResult};

const REGISTRY_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";

#[derive(Clone, Debug, CandidType, Deserialize)]
struct GetSubnetForCanisterArgs {
    principal: Option<Principal>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct GetSubnetForCanisterResponse {
    subnet_id: Option<Principal>,
}

pub async fn get_subnet_for_canister(canister_id: Principal) -> Result<Principal, ValidationError> {
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
            let msg = format!(
                "Call `get_subnet_for_canister` for {} failed: {:?}",
                canister_id, e
            );
            println!("{}", msg);
            Err(ValidationError::CallFailed { reason: msg })
        }
        Ok(response) => match response.candid::<Result<GetSubnetForCanisterResponse, String>>() {
            Ok(Ok(GetSubnetForCanisterResponse { subnet_id })) => match subnet_id {
                None => Err(ValidationError::CanisterNotFound {
                    canister: canister_id,
                }),
                Some(subnet_id) => Ok(subnet_id),
            },
            Ok(Err(e)) => {
                let msg = format!(
                    "Call `GetSubnetForCanisterResponse` for {} failed: {}",
                    canister_id, e
                );
                println!("{}", msg);
                Err(ValidationError::CallFailed { reason: msg })
            }
            Err(e) => {
                let msg = format!(
                    "Decoding `get_subnet_for_canister` for {} failed: {:?}",
                    canister_id, e
                );
                println!("{}", msg);
                Err(ValidationError::CallFailed { reason: msg })
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
    migrated_canister: Principal,
    replaced_canister_subnet: Principal,
) -> ProcessingResult<u64, Infallible> {
    let args = MigrateCanistersArgs {
        canister_ids: vec![migrated_canister],
        target_subnet_id: replaced_canister_subnet,
    };

    match Call::bounded_wait(
        Principal::from_text(REGISTRY_CANISTER_ID).unwrap(),
        "migrate_canisters",
    )
    .with_arg(args)
    .await
    {
        Err(e) => {
            println!(
                "Call `migrate_canisters` for {} failed: {:?}",
                migrated_canister, e
            );
            ProcessingResult::NoProgress
        }
        Ok(response) => match response.candid::<MigrateCanisterResponse>() {
            Ok(MigrateCanisterResponse { registry_version }) => {
                ProcessingResult::Success(registry_version)
            }
            Err(e) => {
                println!(
                    "Decoding `migrate_canisters` for {} failed: {:?}",
                    migrated_canister, e
                );
                ProcessingResult::NoProgress
            }
        },
    }
}
