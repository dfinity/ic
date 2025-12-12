//! This module contains request validation code.
//!
//! Validate as much as possible upfront, so that the processing state machine does as little work
//! as possible.
//! Some checks will have to be repeated because of time of check/time of use issues. But it's better
//! to reject a request that has no chance early.
//! This method makes several calls and might take a while. But it will respond to the user's call
//! directly, which makes it worth the wait. The subsequent error conditions have to be polled by the
//! caller.

use candid::{Principal, Reserved};
use ic_cdk::api::canister_self;

use crate::{
    CYCLES_COST_PER_MIGRATION, Request, ValidationError,
    canister_state::CanisterGuard,
    canister_state::requests::list_by,
    external_interfaces::{
        management::{
            CanisterStatusResponse, CanisterStatusType, assert_no_snapshots, canister_status,
            get_canister_info,
        },
        registry::get_subnet_for_canister,
    },
    processing::ProcessingResult,
};

async fn check_controllers_and_get_status(
    canister_id: Principal,
    caller: Principal,
) -> Result<CanisterStatusResponse, ValidationError> {
    let canister_info = match get_canister_info(canister_id).await {
        ProcessingResult::Success(canister_info) => canister_info,
        ProcessingResult::NoProgress => {
            return Err(ValidationError::CallFailed {
                reason: "Call to management canister (`canister_info`) failed. Try again later."
                    .to_string(),
            });
        }
        ProcessingResult::FatalFailure(()) => {
            return Err(ValidationError::CanisterNotFound {
                canister: canister_id,
            });
        }
    };
    if !canister_info.controllers.contains(&canister_self()) {
        return Err(ValidationError::NotController {
            canister: canister_id,
        });
    }
    if !canister_info.controllers.contains(&caller) {
        return Err(ValidationError::CallerNotController {
            canister: canister_id,
        });
    }
    let ProcessingResult::Success(canister_status) = canister_status(canister_id).await else {
        return Err(ValidationError::CallFailed {
            reason: "Call to management canister (`canister_status`) failed. Try again later."
                .to_string(),
        });
    };
    Ok(canister_status)
}

/// Given caller-provided data, returns
/// - a `Request` that can very likely be processed and
///   locks that should only be dropped after inserting the `Request`
///   into canister state;
/// - or an informative error.
pub async fn validate_request(
    migrated: Principal,
    replaced: Principal,
    caller: Principal,
) -> Result<(Request, Vec<CanisterGuard>), ValidationError> {
    // We first check if the caller is authorized (i.e.,
    // if the caller is a controller of both the migrated and replaced canisters)
    // before acquiring locks for the migrated and replaced canisters
    // to prevent unauthorized callers from acquiring the lock
    // and blocking authorized callers from performing canister migration.

    // 1. The migrated canister must not be equal to the replaced canister.
    if migrated == replaced {
        return Err(ValidationError::SameSubnet(Reserved));
    }

    // 2. Is the caller controller of the migrated canister?
    let migrated_canister_status = check_controllers_and_get_status(migrated, caller).await?;
    // 3. Is the caller controller of the replaced canister?
    let replaced_canister_status = check_controllers_and_get_status(replaced, caller).await?;

    // Now we can acquire the locks
    // to prevent reentrancy bugs across asynchronous calls
    // while validating the migrated and replaced canisters.
    let Ok(migrated_canister_guard) = CanisterGuard::new(migrated) else {
        return Err(ValidationError::ValidationInProgress { canister: migrated });
    };
    let Ok(replaced_canister_guard) = CanisterGuard::new(replaced) else {
        return Err(ValidationError::ValidationInProgress { canister: replaced });
    };

    // 4. Is any of these canisters already in a migration process?
    for request in list_by(|_| true) {
        if let Some(id) = request.request().affects_canister(migrated, replaced) {
            return Err(ValidationError::MigrationInProgress { canister: id });
        }
    }
    // 5. Are the migrated and replaced canisters on the same subnet?
    let migrated_canister_subnet = get_subnet_for_canister(migrated).await?;
    let replaced_canister_subnet = get_subnet_for_canister(replaced).await?;
    if migrated_canister_subnet == replaced_canister_subnet {
        return Err(ValidationError::SameSubnet(Reserved));
    }
    // 6. Is the migrated canister stopped?
    if migrated_canister_status.status != CanisterStatusType::Stopped {
        return Err(ValidationError::MigratedNotStopped(Reserved));
    }
    // 7. Is the migrated canister ready for migration?
    if !migrated_canister_status.ready_for_migration {
        return Err(ValidationError::MigratedNotReady(Reserved));
    }
    // 8. Is the replaced canister stopped?
    if replaced_canister_status.status != CanisterStatusType::Stopped {
        return Err(ValidationError::ReplacedNotStopped(Reserved));
    }
    // 9. Does the replaced canister have snapshots?
    assert_no_snapshots(replaced).await.into_result(
        "Call to management canister `list_canister_snapshots` failed. Try again later.",
    )?;

    // 10. Does the migrated canister have sufficient cycles for the migration?
    if migrated_canister_status.cycles < CYCLES_COST_PER_MIGRATION {
        return Err(ValidationError::MigratedInsufficientCycles(Reserved));
    }

    let mut migrated_canister_original_controllers = migrated_canister_status.settings.controllers;
    migrated_canister_original_controllers.retain(|e| *e != canister_self());
    let mut replaced_canister_original_controllers = replaced_canister_status.settings.controllers;
    replaced_canister_original_controllers.retain(|e| *e != canister_self());
    let request = Request {
        migrated,
        migrated_canister_subnet,
        migrated_canister_original_controllers,
        replaced,
        replaced_canister_subnet,
        replaced_canister_original_controllers,
        caller,
    };

    Ok((
        request,
        vec![migrated_canister_guard, replaced_canister_guard],
    ))
}
