use std::convert::Infallible;

use candid::{CandidType, Principal, Reserved};
use ic_cdk::{
    api::{canister_self, canister_version},
    call::{Call, CallFailed, Error as CallError, RejectCode},
    management_canister::{
        CanisterInfoArgs, CanisterInfoResult, canister_info, list_canister_snapshots,
    },
    println,
};
use ic_management_canister_types::ListCanisterSnapshotsArgs;
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

/// This is a success if the call is a success
/// and a fatal failure otherwise.
/// We never retry this due to potential data races.
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
        Err(e) => {
            println!("Call `update_settings` for {} failed: {:?}", canister_id, e);
            ProcessingResult::FatalFailure(format!(
                "Failed to set the migration canister as the exclusive controller of canister {canister_id}: {e}",
            ))
        }
    }
}

/// This is a success if the call is a success
/// and a fatal failure if the canister does not exist.
/// Otherwise, this function returns no progress.
/// If applicable, failures due to the caller not being a controller of the given canister
/// should be detected separately using `canister_info`.
pub async fn set_controllers(
    canister_id: Principal,
    controllers: Vec<Principal>,
    subnet_id: Principal,
) -> ProcessingResult<(), ()> {
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
        Err(ref e) => {
            println!("Call `update_settings` for {} failed: {:?}", canister_id, e);
            match e {
                CallFailed::CallRejected(e) => {
                    if e.reject_code() == Ok(RejectCode::DestinationInvalid) {
                        ProcessingResult::FatalFailure(())
                    } else {
                        ProcessingResult::NoProgress
                    }
                }
                _ => ProcessingResult::NoProgress,
            }
        }
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
) -> ProcessingResult<CanisterStatusResponse, ValidationError> {
    let args = CanisterStatusArgs { canister_id };

    match Call::bounded_wait(Principal::management_canister(), "canister_status")
        .with_arg(args)
        .await
    {
        Ok(response) => match response.candid::<CanisterStatusResponse>() {
            Ok(canister_status) => ProcessingResult::Success(canister_status),
            Err(e) => {
                println!(
                    "Decoding `CanisterStatusResponse` for canister: {} failed: {:?}",
                    canister_id, e
                );
                ProcessingResult::NoProgress
            }
        },
        Err(e) => {
            println!(
                "Call `canister_status` for canister: {} failed: {:?}",
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

/// This is a success if the call is a success
/// and a fatal failure if the canister does not exist.
pub async fn get_canister_info(canister_id: Principal) -> ProcessingResult<CanisterInfoResult, ()> {
    let args = CanisterInfoArgs {
        canister_id,
        num_requested_changes: None,
    };

    match canister_info(&args).await {
        Ok(canister_info) => ProcessingResult::Success(canister_info),
        Err(e) => {
            println!("Call `canister_info` for {} failed: {:?}", canister_id, e);
            match e {
                CallError::CallRejected(e) => {
                    if e.reject_code() == Ok(RejectCode::DestinationInvalid) {
                        ProcessingResult::FatalFailure(())
                    } else {
                        ProcessingResult::NoProgress
                    }
                }
                _ => ProcessingResult::NoProgress,
            }
        }
    }
}

// ========================================================================= //
// `rename_canister`

#[derive(Clone, Debug, Deserialize, CandidType, PartialEq)]
pub struct RenameCanisterArgs {
    pub canister_id: Principal,
    pub rename_to: RenameToArgs,
    pub requested_by: Principal,
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
    target_subnet: Principal,
    total_num_changes: u64,
    requested_by: Principal,
) -> ProcessingResult<(), Infallible> {
    let args = RenameCanisterArgs {
        canister_id: target,
        rename_to: RenameToArgs {
            canister_id: source,
            version: source_version,
            total_num_changes,
        },
        requested_by,
        sender_canister_version: canister_version(),
    };

    // We have to await this call no matter what. Bounded wait is not an option.
    match Call::unbounded_wait(target_subnet, "rename_canister")
        .with_arg(args)
        .await
    {
        Ok(_) => ProcessingResult::Success(()),
        Err(e) => {
            println!(
                "Call `rename_canister` for canister`: {}, subnet: {} failed: {:?}",
                target, target_subnet, e
            );
            // All fatal error conditions have been checked upfront and should not be possible now.
            // CanisterAlreadyExists, RenameCanisterNotStopped, RenameCanisterHasSnapshot.
            ProcessingResult::NoProgress
        }
    }
}

// ========================================================================= //
// `list_canister_snapshots`

pub async fn assert_no_snapshots(canister_id: Principal) -> ProcessingResult<(), ValidationError> {
    match list_canister_snapshots(&ListCanisterSnapshotsArgs { canister_id }).await {
        Ok(snapshots) => {
            if snapshots.is_empty() {
                ProcessingResult::Success(())
            } else {
                ProcessingResult::FatalFailure(ValidationError::TargetHasSnapshots(Reserved))
            }
        }
        Err(e) => {
            println!(
                "Call `list_canister_snapshots` for {} failed: {:?}",
                canister_id, e
            );
            ProcessingResult::NoProgress
        }
    }
}

// ========================================================================= //
// `subnet_info`
// Handrolling this until the CDK exposes the new field

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SubnetInfoArgs {
    pub subnet_id: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SubnetInfoResponse {
    pub replica_version: String,
    pub registry_version: u64,
}

pub async fn get_registry_version(subnet_id: Principal) -> ProcessingResult<u64, Infallible> {
    let args = SubnetInfoArgs { subnet_id };
    match Call::bounded_wait(subnet_id, "subnet_info")
        .with_arg(&args)
        .await
    {
        Ok(response) => match response.candid::<SubnetInfoResponse>() {
            Ok(SubnetInfoResponse {
                registry_version, ..
            }) => ProcessingResult::Success(registry_version),
            Err(e) => {
                println!(
                    "Decoding `SubnetInfoResponse` for subnet: {} failed: {:?}",
                    subnet_id, e
                );
                ProcessingResult::NoProgress
            }
        },
        Err(e) => {
            println!(
                "Call `subnet_info` for subnet: {} failed: {:?}",
                subnet_id, e
            );
            ProcessingResult::NoProgress
        }
    }
}

// ========================================================================= //
// `delete_canister`
// We can't use the CDK's implementation because we need to call the correct subnet.

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DeleteCanisterArgs {
    pub canister_id: Principal,
}

/// This is a success if the call is a success or the canister does not exist,
/// i.e., a previous call to delete the canister was a success.
pub async fn delete_canister(
    canister_id: Principal,
    subnet_id: Principal,
) -> ProcessingResult<(), Infallible> {
    let args = DeleteCanisterArgs { canister_id };
    match Call::bounded_wait(subnet_id, "delete_canister")
        .with_arg(&args)
        .await
    {
        Ok(_) => ProcessingResult::Success(()),
        Err(e) => {
            println!(
                "Call `delete_canister` for canister: {}, subnet: {}, failed: {:?}",
                canister_id, subnet_id, e
            );
            match e {
                CallFailed::CallRejected(e) => {
                    if e.reject_code() == Ok(RejectCode::DestinationInvalid) {
                        ProcessingResult::Success(())
                    } else {
                        ProcessingResult::NoProgress
                    }
                }
                _ => ProcessingResult::NoProgress,
            }
        }
    }
}
