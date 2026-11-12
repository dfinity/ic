use std::convert::Infallible;

use candid::{CandidType, Principal, Reserved};
use ic_cdk::{
    api::{canister_self, canister_version},
    call::{Call, CallFailed, Error as CallError, RejectCode},
    println,
};
use ic_cdk_management_canister::{
    CanisterInfoArgs, CanisterInfoResult, ListCanisterSnapshotsArgs, canister_info,
    list_canister_snapshots,
};
use serde::Deserialize;

use crate::{ValidationError, processing::ProcessingResult};

// ========================================================================= //
// `update_settings`

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CanisterSettings {
    pub controllers: Option<Vec<Principal>>,
    pub memory_allocation: Option<candid::Nat>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct UpdateSettingsArgs {
    pub canister_id: Principal,
    pub settings: CanisterSettings,
}

/// Makes the migration canister the only controller of the given canister and,
/// if `memory_allocation` is not `None`, sets its memory allocation in the same call.
///
/// This is a success if the call is a success and a fatal failure if the call definitely
/// had no effect. If the outcome of the call is unknown (its response might have been dropped),
/// then this function returns no progress so that the call is retried: this way, the caller
/// always knows whether the migration canister became the exclusive controller.
pub async fn set_exclusive_controller(
    canister_id: Principal,
    memory_allocation: Option<u64>,
) -> ProcessingResult<(), String> {
    let args = UpdateSettingsArgs {
        canister_id,
        settings: CanisterSettings {
            controllers: Some(vec![canister_self()]),
            memory_allocation: memory_allocation.map(candid::Nat::from),
        },
    };
    match Call::bounded_wait(Principal::management_canister(), "update_settings")
        .with_arg(args)
        .await
    {
        Ok(_) => ProcessingResult::Success(()),
        Err(ref e) => {
            println!("Call `update_settings` for {} failed: {:?}", canister_id, e);
            let no_effect = match e {
                // The call has not even been enqueued.
                CallFailed::InsufficientLiquidCycleBalance(_)
                | CallFailed::CallPerformFailed(_) => true,
                // A call rejected with a recognized reject code other than `SysUnknown`
                // has been rejected without taking effect. In particular, `SysUnknown`
                // (and an unrecognized reject code) means that the outcome of the call
                // is unknown, i.e., the call might have taken effect.
                CallFailed::CallRejected(e) => {
                    !matches!(e.reject_code(), Ok(RejectCode::SysUnknown) | Err(_))
                }
            };
            if no_effect {
                ProcessingResult::FatalFailure(format!(
                    "Failed to set the migration canister as the exclusive controller of canister {canister_id}: {e}",
                ))
            } else {
                ProcessingResult::NoProgress
            }
        }
    }
}

/// Sets the controllers of the given canister and, if `memory_allocation` is not `None`,
/// its memory allocation in the same call: the memory freed by lowering the memory allocation
/// covers the memory of the canister history entry recorded for the controllers change.
///
/// This is a success if the call is a success
/// and a fatal failure if the canister does not exist.
/// Otherwise, this function returns no progress.
/// If applicable, failures due to the caller not being a controller of the given canister
/// should be detected separately using `canister_info`.
pub async fn set_controllers(
    canister_id: Principal,
    controllers: Vec<Principal>,
    memory_allocation: Option<u64>,
    subnet_id: Principal,
) -> ProcessingResult<(), ()> {
    let args = UpdateSettingsArgs {
        canister_id,
        settings: CanisterSettings {
            controllers: Some(controllers),
            memory_allocation: memory_allocation.map(candid::Nat::from),
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
pub struct MemoryMetrics {
    pub canister_history_size: candid::Nat,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CanisterStatusResponse {
    pub status: CanisterStatusType,
    pub ready_for_migration: bool,
    pub version: u64,
    pub settings: DefiniteCanisterSettingsArgs,
    pub memory_size: candid::Nat,
    pub memory_metrics: MemoryMetrics,
    pub cycles: candid::Nat,
    pub freezing_threshold: candid::Nat,
    pub reserved_cycles: candid::Nat,
}

impl CanisterStatusResponse {
    /// The canister's memory usage in bytes (saturating at `u64::MAX`).
    pub fn memory_usage(&self) -> u64 {
        u64::try_from(&self.memory_size.0).unwrap_or(u64::MAX)
    }

    /// The canister's memory usage in bytes excluding its canister history
    /// (saturating at `u64::MAX`). Only the canister history of a canister under
    /// the exclusive control of the migration canister is expected to grow
    /// (see `MEMORY_RESERVED_FOR_CANISTER_HISTORY`).
    pub fn memory_usage_excluding_canister_history(&self) -> u64 {
        self.memory_usage().saturating_sub(
            u64::try_from(&self.memory_metrics.canister_history_size.0).unwrap_or(u64::MAX),
        )
    }

    /// The canister's memory allocation in bytes (saturating at `u64::MAX`);
    /// `0` means that the canister's memory growth is best-effort.
    pub fn memory_allocation(&self) -> u64 {
        u64::try_from(&self.settings.memory_allocation.0).unwrap_or(u64::MAX)
    }
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
    pub memory_allocation: candid::Nat,
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
                CallFailed::CallRejected(e) => {
                    if e.reject_code() == Ok(RejectCode::DestinationInvalid) {
                        ProcessingResult::FatalFailure(ValidationError::CanisterNotFound {
                            canister: canister_id,
                        })
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
// `canister_info`

/// This is a success if the call is a success
/// and a fatal failure if the canister does not exist.
/// Otherwise, this function returns no progress.
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

/// This is a success if the call is a success or the replaced canister does not exist,
/// i.e., a previous call to rename the replaced canister was a success.
pub async fn rename_canister(
    migrated_canister: Principal,
    migrated_canister_version: u64,
    replaced_canister: Principal,
    replaced_canister_subnet: Principal,
    total_num_changes: u64,
    requested_by: Principal,
) -> ProcessingResult<(), Infallible> {
    let args = RenameCanisterArgs {
        canister_id: replaced_canister,
        rename_to: RenameToArgs {
            canister_id: migrated_canister,
            version: migrated_canister_version,
            total_num_changes,
        },
        requested_by,
        sender_canister_version: canister_version(),
    };

    match Call::bounded_wait(replaced_canister_subnet, "rename_canister")
        .with_arg(args)
        .await
    {
        Ok(_) => ProcessingResult::Success(()),
        Err(e) => {
            println!(
                "Call `rename_canister` for canister`: {}, subnet: {} failed: {:?}",
                replaced_canister, replaced_canister_subnet, e
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

// ========================================================================= //
// `list_canister_snapshots`

pub async fn assert_no_snapshots(canister_id: Principal) -> ProcessingResult<(), ValidationError> {
    match list_canister_snapshots(&ListCanisterSnapshotsArgs { canister_id }).await {
        Ok(snapshots) if snapshots.is_empty() => ProcessingResult::Success(()),
        Ok(_) => {
            ProcessingResult::FatalFailure(ValidationError::ReplacedCanisterHasSnapshots(Reserved))
        }
        Err(CallError::CallRejected(e))
            if e.reject_code() == Ok(RejectCode::DestinationInvalid) =>
        {
            println!(
                "Call `list_canister_snapshots` for {} returned DestinationInvalid, treating as success",
                canister_id
            );
            ProcessingResult::Success(())
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

pub async fn get_registry_version(
    subnet_id: Principal,
) -> ProcessingResult<Option<u64>, Infallible> {
    let args = SubnetInfoArgs { subnet_id };
    match Call::bounded_wait(subnet_id, "subnet_info")
        .with_arg(&args)
        .await
    {
        Ok(response) => match response.candid::<SubnetInfoResponse>() {
            Ok(SubnetInfoResponse {
                registry_version, ..
            }) => ProcessingResult::Success(Some(registry_version)),
            Err(e) => {
                println!(
                    "Decoding `SubnetInfoResponse` for subnet: {} failed: {:?}",
                    subnet_id, e
                );
                ProcessingResult::NoProgress
            }
        },
        Err(CallFailed::CallRejected(e))
            if e.reject_code() == Ok(RejectCode::DestinationInvalid) =>
        {
            println!(
                "Call `subnet_info` for subnet: {} returned DestinationInvalid, treating as success",
                subnet_id
            );
            ProcessingResult::Success(None)
        }
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
