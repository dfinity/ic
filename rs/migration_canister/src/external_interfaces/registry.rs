use candid::{CandidType, Principal};
use ic_cdk::{call::Call, println};
use serde::Deserialize;

use crate::{processing::ProcessingResult, ValidationError};

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

    match Call::bounded_wait(Principal::management_canister(), "update_settings")
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
        Ok(response) => match response.candid::<GetSubnetForCanisterResponse>() {
            Ok(GetSubnetForCanisterResponse { subnet_id }) => match subnet_id {
                None => ProcessingResult::FatalFailure(ValidationError::CanisterNotFound {
                    canister: canister_id,
                }),
                Some(subnet_id) => ProcessingResult::Success(subnet_id),
            },
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
