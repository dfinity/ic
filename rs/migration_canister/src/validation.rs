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
        management::{CanisterStatusType, assert_no_snapshots, canister_status},
        registry::get_subnet_for_canister,
    },
};

/// Given caller-provided data, returns a `Request` that can very likely be processed or an informative error.
pub async fn validate_request(
    source: Principal,
    target: Principal,
    caller: Principal,
) -> Result<Request, ValidationError> {
    // We first check if the caller is authorized (i.e.,
    // if the caller is a controller of both the source and target)
    // before acquiring locks for the source and target
    // to prevent unauthorized callers from acquiring the lock
    // and blocking authorized callers from performing canister migration.

    // 1. The source must not be equal to the target.
    if source == target {
        return Err(ValidationError::SameSubnet(Reserved));
    }

    // 2. Is the caller controller of the source? This call also fails if we are not controller.
    let source_status = canister_status(source)
        .await
        .into_result(&format!("Call to management canister (`canister_status`) failed. Ensure that the canister {} is the expected source and try again later.", source))?;
    if !source_status.settings.controllers.contains(&caller) {
        return Err(ValidationError::CallerNotController { canister: source });
    }
    // 3. Is the caller controller of the target? This call also fails if we are not controller.
    let target_status = canister_status(target)
        .await
        .into_result(&format!("Call to management canister (`canister_status`) failed. Ensure that the canister {} is the expected target and try again later.", target))?;
    if !target_status.settings.controllers.contains(&caller) {
        return Err(ValidationError::CallerNotController { canister: target });
    }

    // Now we can acquire the locks
    // to prevent reentrancy bugs across asynchronous calls
    // while validating the source and target.
    let Ok(_source_guard) = CanisterGuard::new(source) else {
        return Err(ValidationError::ValidationInProgress { canister: source });
    };
    let Ok(_target_guard) = CanisterGuard::new(target) else {
        return Err(ValidationError::ValidationInProgress { canister: target });
    };

    // 4. Is any of these canisters already in a migration process?
    for request in list_by(|_| true) {
        if let Some(id) = request.request().affects_canister(source, target) {
            return Err(ValidationError::MigrationInProgress { canister: id });
        }
    }
    // 5. Are the source and target on the same subnet?
    let source_subnet = get_subnet_for_canister(source).await?;
    let target_subnet = get_subnet_for_canister(target).await?;
    if source_subnet == target_subnet {
        return Err(ValidationError::SameSubnet(Reserved));
    }
    // 6. Is the source stopped?
    if source_status.status != CanisterStatusType::Stopped {
        return Err(ValidationError::SourceNotStopped(Reserved));
    }
    // 7. Is the source ready for migration?
    if !source_status.ready_for_migration {
        return Err(ValidationError::SourceNotReady(Reserved));
    }
    // 8. Is the target stopped?
    if target_status.status != CanisterStatusType::Stopped {
        return Err(ValidationError::TargetNotStopped(Reserved));
    }
    // 9. Does the target have snapshots?
    assert_no_snapshots(target).await.into_result(
        "Call to management canister `list_canister_snapshots` failed. Try again later.",
    )?;

    // 10. Does the source have sufficient cycles for the migration?
    if source_status.cycles < CYCLES_COST_PER_MIGRATION {
        return Err(ValidationError::SourceInsufficientCycles(Reserved));
    }

    let mut source_original_controllers = source_status.settings.controllers;
    source_original_controllers.retain(|e| *e != canister_self());
    let mut target_original_controllers = target_status.settings.controllers;
    target_original_controllers.retain(|e| *e != canister_self());
    Ok(Request {
        source,
        source_subnet,
        source_original_controllers,
        target,
        target_subnet,
        target_original_controllers,
        caller,
    })
}
