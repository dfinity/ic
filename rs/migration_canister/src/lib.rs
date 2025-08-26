//! This module contains types and internal methods.  
//!
//! TODO: mention that new state is necessary as soon as effectful call is made. info gathering is irrelevant.

use candid::{CandidType, Principal};
use ic_cdk::{api::canister_self, futures::spawn};
use ic_cdk_timers::set_timer_interval;
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::{borrow::Cow, time::Duration};

use crate::{
    canister_state::{max_active_requests, num_active_requests, requests::list_by},
    external_interfaces::{
        management::{canister_status, CanisterStatusType},
        registry::get_subnet_for_canister,
    },
    processing::{process_accepted, process_all_failed, process_all_generic},
};

mod canister_state;
mod external_interfaces;
mod migration_canister;
mod privileged;
mod processing;

const DEFAULT_MAX_ACTIVE_REQUESTS: u64 = 50;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ValidationError {
    MigrationsDisabled,
    RateLimited,
    MigrationInProgress { canister: Principal },
    CanisterNotFound { canister: Principal },
    SameSubnet,
    CallerNotController { canister: Principal },
    NotController { canister: Principal },
    SourceNotStopped,
    SourceNotReady,
    TargetNotStopped,
    TargetHasSnapshots,
    TargetInsufficientCycles,
    CallFailed { reason: String },
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    source: Principal,
    source_subnet: Principal,
    source_original_controllers: Vec<Principal>,
    target: Principal,
    target_subnet: Principal,
    target_original_controllers: Vec<Principal>,
    caller: Principal,
}

impl Request {
    fn affects_canister(&self, src_id: Principal, tgt_id: Principal) -> Option<Principal> {
        if self.source == src_id || self.target == src_id {
            return Some(src_id);
        }
        if self.source == tgt_id || self.target == tgt_id {
            return Some(tgt_id);
        }
        None
    }
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestState {
    /// Request was validated successfully.
    /// * Called registry `get_subnet_for_canister` to determine:
    ///     * Existence of source and target.
    ///     * Subnet of source and target.
    /// * Called mgmt `canister_status` to determine:
    ///     * We are controller of source and target.
    ///     * The original controllers of source and target.
    ///     * If the target has sufficient cycles above the freezing threshold.
    Accepted { request: Request },

    /// Called mgmt `update_settings` to make us the only controller.
    ///
    /// Certain checks are not informative before this state because the original controller
    /// could still interfere until this state.
    ControllersChanged { request: Request },

    /// * Called mgmt `canister_status` to determine:
    ///     * Source and target are stopped.
    ///     * Source is ready for migration.
    ///     * Target has no snapshots.
    ///     * Target has sufficient cycles above the freezing threshold.
    ///     * Source canister version is not absurdly high.
    /// * Called mgmt `canister_info` to determine the history length of source.  
    ///
    /// Record the canister version and history length of source and the current time.
    StoppedAndReady {
        request: Request,
        stopped_since: u64,
        canister_version: u64,
        canister_history_total_num: u64,
    },

    /// Called mgmt `rename_canister`. Subsequent mgmt calls have to use the explicit subnet ID, not `aaaaa-aa`.
    RenamedTarget {
        request: Request,
        stopped_since: u64,
    },

    /// Called registry `migrate_canisters`.
    ///
    /// Record the new registry version.
    UpdatedRoutingTable {
        request: Request,
        stopped_since: u64,
        registry_version: u64,
    },

    /// Both subnets have learned about the new routing information.
    /// Called `subnet_info` on both subnets to determine their `registry_version`.
    RoutingTableChangeAccepted {
        request: Request,
        stopped_since: u64,
    },

    /// Called mgmt `delete_canister`.
    SourceDeleted {
        request: Request,
        stopped_since: u64,
    },

    /// Five minutes have passed since `stopped_since` such that any messages to the
    /// source subnet have expired by now.
    /// Restored the controllers of the target canister (now addressed with source's id).
    ///
    /// Called `update_settings` to restore controllers.
    RestoredControllers { request: Request },

    /// Some transition has failed fatally.
    /// We stay in this state until the controllers have been restored and then
    /// transition to a `Failed` state in the `HISTORY`.
    Failed { request: Request, reason: String },
}

impl RequestState {
    fn request(&self) -> &Request {
        match self {
            RequestState::Accepted { request }
            | RequestState::ControllersChanged { request }
            | RequestState::StoppedAndReady { request, .. }
            | RequestState::RenamedTarget { request, .. }
            | RequestState::UpdatedRoutingTable { request, .. }
            | RequestState::RoutingTableChangeAccepted { request, .. }
            | RequestState::SourceDeleted { request, .. }
            | RequestState::RestoredControllers { request }
            | RequestState::Failed { request, .. } => request,
        }
    }
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Succeeded { request: Request },
    Failed { request: Request, reason: String },
}

impl Storable for Request {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(to_vec(&self).expect("Request serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("Request deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for RequestState {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(to_vec(&self).expect("RequestState serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("RequestState deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for Event {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(to_vec(&self).expect("Event serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("Event deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

pub fn start_timers() {
    let interval = Duration::from_secs(1);
    set_timer_interval(interval, || {
        spawn(process_all_generic(
            "accepted",
            |r| matches!(r, RequestState::Accepted { .. }),
            process_accepted,
        ))
    });

    // This one has a different type from the generic ones above.
    set_timer_interval(interval, || spawn(process_all_failed()));
}

pub fn rate_limited() -> bool {
    num_active_requests() > max_active_requests()
}

/// Validate as much as possible upfront, so that the processing state machine does as little work
/// as possible.
/// Some checks will have to be repeated because of time of check/time of use issues. But it's better
/// to reject a request that has no chance upfront.
/// This method makes several calls and might take a while. But it will respond to the user's call
/// directly, which makes it worth the wait. The subsequent error conditions have to be polled by the
/// caller.
/// TODO: This comment should be a module-level overview.
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
    // 2. Does source canister exist?
    let source_subnet = get_subnet_for_canister(source)
        .await
        .into_result("Call to registry canister failed. Try again later.")?;
    // 3. Does target canister exist?
    let target_subnet = get_subnet_for_canister(target)
        .await
        .into_result("Call to registry canister failed. Try again later.")?;
    // 4. Are they on the same subnet?
    if source_subnet == target_subnet {
        return Err(ValidationError::SameSubnet);
    }
    // 5. Is the caller controller of the source? This fall fails if we are not controller.
    let source_status = canister_status(source, source_subnet)
        .await
        .into_result("Call to management canister failed. Try again later.")?;
    if !source_status.settings.controllers.contains(&caller) {
        return Err(ValidationError::CallerNotController { canister: source });
    }
    // 6. Is the caller controller of the target? This fall fails if we are not controller.
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
