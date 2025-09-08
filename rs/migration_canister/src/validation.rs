//! This module contains request validation code.
//!
//! Validate as much as possible upfront, so that the processing state machine does as little work
//! as possible.
//! Some checks will have to be repeated because of time of check/time of use issues. But it's better
//! to reject a request that has no chance early.
//! This method makes several calls and might take a while. But it will respond to the user's call
//! directly, which makes it worth the wait. The subsequent error conditions have to be polled by the
//! caller.

use candid::Principal;
use ic_cdk::api::canister_self;

use crate::{
    Request, ValidationError,
    canister_state::requests::list_by,
    external_interfaces::{
        management::{CanisterStatusType, canister_status},
        registry::get_subnet_for_canister,
    },
};

/// Given caller-provided data, returns a `Request` that can very likely be processed or an informative error.
pub async fn validate_request(
    source: Principal,
    target: Principal,
    caller: Principal,
) -> Result<Request, ValidationError> {
    // 1. Is any of these canisters already in a migration process?
    for request in list_by(|_| true) {
        if let Some(id) = request.request().affects_canister(source, target) {
            return Err(ValidationError::MigrationInProgress { canister: id });
        }
    }
    // 2. Does the source canister exist?
    let source_subnet = get_subnet_for_canister(source)
        .await
        .into_result("Call to registry canister failed. Try again later.")?;
    // 3. Does the target canister exist?
    let target_subnet = get_subnet_for_canister(target)
        .await
        .into_result("Call to registry canister failed. Try again later.")?;
    // 4. Are they on the same subnet?
    if source_subnet == target_subnet {
        return Err(ValidationError::SameSubnet);
    }
    // 5. Is the caller controller of the source? This call also fails if we are not controller.
    let source_status = canister_status(source, source_subnet)
        .await
        .into_result("Call to management canister failed. Try again later.")?;
    if !source_status.settings.controllers.contains(&caller) {
        return Err(ValidationError::CallerNotController { canister: source });
    }
    // 6. Is the caller controller of the target? This call also fails if we are not controller.
    let target_status = canister_status(target, target_subnet)
        .await
        .into_result("Call to management canister failed. Try again later.")?;
    if !target_status.settings.controllers.contains(&caller) {
        return Err(ValidationError::CallerNotController { canister: target });
    }
    // 7. Is the source stopped?
    if source_status.status != CanisterStatusType::Stopped {
        return Err(ValidationError::SourceNotStopped);
    }
    // 8. Is the source ready for migration?
    if !source_status.ready_for_migration {
        return Err(ValidationError::SourceNotReady);
    }
    // 9. Is the target stopped?
    if target_status.status != CanisterStatusType::Stopped {
        return Err(ValidationError::TargetNotStopped);
    }
    // 10. Does the target have snapshots?
    // TODO: list snapshots

    // n. Does the target have sufficient cycles for the migration?
    // TODO

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
