use std::convert::Infallible;

use candid::{CandidType, Principal};
use ic_cdk::{
    api::{canister_self, canister_version},
    call::Call,
    management_canister::{CanisterInfoArgs, CanisterInfoResult, canister_info},
    println,
};
use serde::Deserialize;

use crate::{ValidationError, processing::ProcessingResult};

// ========================================================================= //
// `update_settings`

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

/// This is a success if the call is a success OR if it fails with "we are not controller"
pub async fn set_original_controllers(
    canister_id: Principal,
    controllers: Vec<Principal>,
    subnet_id: Principal,
) -> ProcessingResult<(), Infallible> {
    let args = UpdateSettingsArgs {
        canister_id,
        settings: CanisterSettings {
            controllers: Some(controllers),
        },
    };
    match Call::bounded_wait(subnet_id, "update_settings")
        .with_arg(args)
        .await
    {
        Ok(_) => ProcessingResult::Success(()),
        // If we fail due to not being controller, this is a success
        Err(ref e) => match e {
            ic_cdk::call::CallFailed::InsufficientLiquidCycleBalance(_)
            | ic_cdk::call::CallFailed::CallPerformFailed(_) => ProcessingResult::NoProgress,
            ic_cdk::call::CallFailed::CallRejected(call_rejected) => {
                if call_rejected
                    .reject_message()
                    .contains("Only the controllers of the canister")
                {
                    ProcessingResult::Success(())
                } else {
                    println!(
                        "Call `update_settings` for {:?} failed {:?}",
                        canister_id, e
                    );
                    ProcessingResult::NoProgress
                }
            }
        },
    }
}

// ========================================================================= //
// `canister_status`

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CanisterStatusArgs {
    pub canister_id: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CanisterStatusResponse {
    pub status: CanisterStatusType,
    pub ready_for_migration: bool,
    pub version: u64,
    pub settings: DefiniteCanisterSettingsArgs,
    pub cycles: candid::Nat,
    pub freezing_threshold: candid::Nat,
    pub reserved_cycles: candid::Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum CanisterStatusType {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    Stopped,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DefiniteCanisterSettingsArgs {
    pub controller: Principal,
    pub controllers: Vec<Principal>,
    pub freezing_threshold: candid::Nat,
    pub reserved_cycles_limit: candid::Nat,
}

pub async fn canister_status(
    canister_id: Principal,
    subnet_id: Principal,
) -> ProcessingResult<CanisterStatusResponse, ValidationError> {
    let args = CanisterStatusArgs { canister_id };

    // We have to provide the subnet_id explicitly because `aaaaa-aa` will not always work during migration.
    match Call::bounded_wait(subnet_id, "canister_status")
        .with_arg(args)
        .await
    {
        Ok(response) => match response.candid::<CanisterStatusResponse>() {
            Ok(canister_status) => ProcessingResult::Success(canister_status),
            Err(e) => {
                println!(
                    "Decoding `CanisterStatusResponse` for {:?}, {:?} failed: {:?}",
                    canister_id, subnet_id, e
                );
                ProcessingResult::NoProgress
            }
        },
        Err(e) => {
            println!(
                "Call `canister_status` for {:?}, {:?} failed {:?}",
                canister_id, subnet_id, e
            );
            match e {
                ic_cdk::call::CallFailed::InsufficientLiquidCycleBalance(_)
                | ic_cdk::call::CallFailed::CallPerformFailed(_) => ProcessingResult::NoProgress,
                ic_cdk::call::CallFailed::CallRejected(call_rejected) => {
                    if call_rejected
                        .reject_message()
                        .contains("Only the controllers of the canister")
                    {
                        ProcessingResult::FatalFailure(ValidationError::NotController {
                            canister: canister_id,
                        })
                    } else {
                        ProcessingResult::NoProgress
                    }
                }
            }
        }
    }
}

// ========================================================================= //
// `canister_info`

pub async fn get_canister_info(
    canister_id: Principal,
) -> ProcessingResult<CanisterInfoResult, Infallible> {
    let args = CanisterInfoArgs {
        canister_id,
        num_requested_changes: None,
    };

    match canister_info(&args).await {
        Ok(canister_info) => ProcessingResult::Success(canister_info),
        Err(e) => {
            println!("Call `canister_info` for {:?}, failed {:?}", canister_id, e);
            ProcessingResult::NoProgress
        }
    }
}

// ========================================================================= //
// `rename_canister`

#[derive(Clone, Debug, Deserialize, CandidType, PartialEq)]
pub struct RenameCanisterArgs {
    pub canister_id: Principal,
    pub rename_to: RenameToArgs,
    pub sender_canister_version: u64,
}

#[derive(Clone, Debug, Deserialize, CandidType, PartialEq)]
pub struct RenameToArgs {
    pub canister_id: Principal,
    pub version: u64,
    pub total_num_changes: u64,
}

pub async fn rename_canister(
    source: Principal,
    source_version: u64,
    target: Principal,
    total_num_changes: u64,
) -> ProcessingResult<(), Infallible> {
    let args = RenameCanisterArgs {
        canister_id: source,
        rename_to: RenameToArgs {
            canister_id: target,
            version: source_version,
            total_num_changes,
        },
        sender_canister_version: canister_version(),
    };

    match Call::bounded_wait(target, "rename_canister")
        .with_arg(args)
        .await
    {
        Ok(_) => ProcessingResult::Success(()),
        Err(e) => {
            println!("Call `rename_canister` for {:?} failed {:?}", target, e);
            // All fatal error conditions have been checked upfront and should not be possible now.
            // CanisterAlreadyExists, RenameCanisterNotStopped, RenameCanisterHasSnapshot.
            ProcessingResult::NoProgress
        }
    }
}
