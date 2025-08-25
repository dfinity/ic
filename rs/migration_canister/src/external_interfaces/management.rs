use candid::{CandidType, Principal};
use ic_cdk::{api::canister_self, call::Call, println};
use serde::Deserialize;

use crate::processing::ProcessingResult;

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CanisterSettings {
    pub controllers: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct UpdateSettingsArgs {
    pub canister_id: Principal,
    pub settings: CanisterSettings,
}

pub async fn set_exclusive_controller(canister_id: Principal) -> ProcessingResult<(), String> {
    let args = UpdateSettingsArgs {
        canister_id,
        settings: CanisterSettings {
            controllers: Some(vec![canister_self()]),
        },
    };
    match Call::bounded_wait(Principal::management_canister(), "update_settings")
        .with_arg(args)
        .await
    {
        Ok(_) => ProcessingResult::Success(()),
        // if we fail due to not being controller, this is a fatal failure
        Err(e) => {
            println!(
                "Call `update_settings` for {:?} failed {:?}",
                canister_id, e
            );
            match e {
                ic_cdk::call::CallFailed::InsufficientLiquidCycleBalance(_)
                | ic_cdk::call::CallFailed::CallPerformFailed(_) => ProcessingResult::NoProgress,
                ic_cdk::call::CallFailed::CallRejected(call_rejected) => {
                    if call_rejected
                        .reject_message()
                        .contains("Only the controllers of the canister")
                    {
                        ProcessingResult::FatalFailure(format!(
                            "Failed to set controller of canister {:?}",
                            canister_id
                        ))
                    } else {
                        ProcessingResult::NoProgress
                    }
                }
            }
        }
    }
}
