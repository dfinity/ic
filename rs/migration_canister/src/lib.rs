//! This module contains types and internal methods.
//!
//!
use candid::{CandidType, Principal, Reserved};
use ic_cdk_timers::set_timer_interval;
use ic_stable_structures::{Storable, storable::Bound};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::{borrow::Cow, fmt::Display, time::Duration};
use strum_macros::Display;

use crate::{
    canister_state::{limiter::num_successes_in_past_24_h, requests::num_requests},
    controller_recovery::ControllerRecoveryState,
    processing::{
        process_accepted, process_all_by_predicate, process_all_failed, process_all_succeeded,
        process_controllers_changed, process_migrated_canister_deleted, process_renamed,
        process_routing_table, process_stopped, process_updated,
    },
};

pub use crate::migration_canister::{MigrateCanisterArgs, MigrationStatus};

mod canister_state;
mod controller_recovery;
mod external_interfaces;
mod migration_canister;
mod privileged;
mod processing;
#[cfg(test)]
mod tests;
mod validation;

/// The max number of requests in a 24 hour sliding window. Requests are either
/// - active (in REQUESTS)
/// - succeeded (in HISTORY) and not older than 24 hours.
///
/// Note that RATE_LIMIT + MAX_ONGOING_VALIDATIONS < 500, which is the
/// subnet queue capacity.
const RATE_LIMIT: u64 = 50;
/// Validations cause xnet calls, so we limit them.
const MAX_ONGOING_VALIDATIONS: u64 = 200;
/// 10 Trillion Cycles
const CYCLES_COST_PER_MIGRATION: u64 = 10_000_000_000_000;

#[derive(Clone, Display, Debug, CandidType, Deserialize)]
pub enum ValidationError {
    MigrationsDisabled(Reserved),
    RateLimited(Reserved),
    #[strum(to_string = "ValidationError::ValidationInProgress {{ canister: {canister} }}")]
    ValidationInProgress {
        canister: Principal,
    },
    #[strum(to_string = "ValidationError::MigrationInProgress {{ canister: {canister} }}")]
    MigrationInProgress {
        canister: Principal,
    },
    #[strum(to_string = "ValidationError::CanisterNotFound {{ canister: {canister} }}")]
    CanisterNotFound {
        canister: Principal,
    },
    SameSubnet(Reserved),
    #[strum(to_string = "ValidationError::CallerNotController {{ canister: {canister} }}")]
    CallerNotController {
        canister: Principal,
    },
    #[strum(to_string = "ValidationError::NotController {{ canister: {canister} }}")]
    NotController {
        canister: Principal,
    },
    MigratedCanisterNotStopped(Reserved),
    MigratedCanisterNotReady(Reserved),
    ReplacedCanisterNotStopped(Reserved),
    ReplacedCanisterHasSnapshots(Reserved),
    MigratedCanisterInsufficientCycles(Reserved),
    #[strum(to_string = "ValidationError::CallFailed {{ reason: {reason} }}")]
    CallFailed {
        reason: String,
    },
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
struct CanisterMigrationArgs {
    pub migrated: Principal,
    pub replaced: Principal,
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    migrated: Principal,
    migrated_canister_subnet: Principal,
    migrated_canister_original_controllers: Vec<Principal>,
    replaced: Principal,
    replaced_canister_subnet: Principal,
    replaced_canister_original_controllers: Vec<Principal>,
    caller: Principal,
}

impl Request {
    pub fn new(
        migrated: Principal,
        migrated_canister_subnet: Principal,
        migrated_canister_original_controllers: Vec<Principal>,
        replaced: Principal,
        replaced_canister_subnet: Principal,
        replaced_canister_original_controllers: Vec<Principal>,
        caller: Principal,
    ) -> Self {
        Self {
            migrated,
            migrated_canister_subnet,
            migrated_canister_original_controllers,
            replaced,
            replaced_canister_subnet,
            replaced_canister_original_controllers,
            caller,
        }
    }
    fn affects_canister(&self, src_id: Principal, tgt_id: Principal) -> Option<Principal> {
        if self.migrated == src_id || self.replaced == src_id {
            return Some(src_id);
        }
        if self.migrated == tgt_id || self.replaced == tgt_id {
            return Some(tgt_id);
        }
        None
    }
}

impl Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request {{ migrated: {}, migrated_canister_subnet: {}, replaced: {}, replaced_canister_subnet: {}, caller: {}, migrated_canister_original_controllers: [",
            self.migrated,
            self.migrated_canister_subnet,
            self.replaced,
            self.replaced_canister_subnet,
            self.caller
        )?;
        for x in self.migrated_canister_original_controllers.iter() {
            write!(f, "{}, ", x)?;
        }
        write!(f, "], replaced_canister_original_controllers: [",)?;
        for x in self.replaced_canister_original_controllers.iter() {
            write!(f, "{}, ", x)?;
        }
        write!(f, "] }}")
    }
}

impl From<&Request> for CanisterMigrationArgs {
    fn from(request: &Request) -> Self {
        Self {
            migrated: request.migrated,
            replaced: request.replaced,
        }
    }
}

/// Represents the recovery state of a `Request` in `RequestState::Failed`,
/// i.e., whether controllers of migrated and replaced canisters must still be restored.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryState {
    pub restore_migrated_canister_controllers: ControllerRecoveryState,
    pub restore_replaced_canister_controllers: ControllerRecoveryState,
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryState {
    pub fn new() -> Self {
        Self {
            restore_migrated_canister_controllers: ControllerRecoveryState::NoProgress,
            restore_replaced_canister_controllers: ControllerRecoveryState::NoProgress,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(
            self.restore_migrated_canister_controllers,
            ControllerRecoveryState::Done
        ) && matches!(
            self.restore_replaced_canister_controllers,
            ControllerRecoveryState::Done
        )
    }
}

/// Represents the state a `Request` is currently in and contains all data necessary
/// to transition to the next state (and sometimes data for a future state).
///
/// The variants are ordered according to the successful path.
/// Each variant has a corresponding `process_*` function which attempts to make progress.
/// Every such function may collect data via various xnet calls, but for every function (and
/// therefore state), only _one_ effectful call is allowed, and on success it has to transition
/// to the next state.
///
/// If a transition fails, it may either be retried (signalled by `ProcessingResult::NoProgress`)
/// or fails fatally and transitions into the Failed state. Failed states run a cleanup and end up
/// as a record in the event log `HISTORY`.
#[derive(Clone, Display, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestState {
    /// Request was validated successfully.
    /// * Called registry `get_subnet_for_canister` to determine:
    ///     * Existence of migrated and replaced canisters.
    ///     * Subnet of migrated and replaced canisters.
    /// * Called mgmt `canister_status` to determine:
    ///     * We are controller of migrated and replaced canisters.
    ///     * The original controllers of migrated and replaced canisters.
    ///     * If the replaced canister has sufficient cycles above the freezing threshold.
    #[strum(to_string = "RequestState::Accepted {{ request: {request} }}")]
    Accepted { request: Request },

    /// Called mgmt `update_settings` to make us the only controller.
    ///
    /// Certain checks are not informative before this state because the original controller
    /// could still interfere until this state.
    #[strum(to_string = "RequestState::ControllersChanged {{ request: {request} }}")]
    ControllersChanged { request: Request },

    /// * Called mgmt `canister_status` to determine:
    ///     * Migrated and replaced canisters are stopped.
    ///     * Migrated canister is ready for migration.
    ///     * Replaced canister has no snapshots.
    ///     * Replaced canister has sufficient cycles above the freezing threshold.
    ///     * Migrated canister version is not absurdly high.
    /// * Called mgmt `canister_info` to determine the history length of migrated canister.
    ///
    /// Record the canister version and history length of migrated canister and the current time.
    #[strum(
        to_string = "RequestState::StoppedAndReady {{ request: {request}, stopped_since: {stopped_since}, canister_version: {canister_version}, canister_history_total_num: {canister_history_total_num} }}"
    )]
    StoppedAndReady {
        request: Request,
        stopped_since: u64,
        canister_version: u64,
        canister_history_total_num: u64,
    },

    /// Called mgmt `rename_canister`. Subsequent mgmt calls have to use the explicit subnet ID, not `aaaaa-aa`.
    #[strum(
        to_string = "RequestState::RenamedReplaced {{ request: {request}, stopped_since: {stopped_since} }}"
    )]
    RenamedReplaced {
        request: Request,
        stopped_since: u64,
    },

    /// Called registry `migrate_canisters`.
    ///
    /// Record the new registry version.
    #[strum(
        to_string = "RequestState::UpdatedRoutingTable {{ request: {request}, stopped_since: {stopped_since}, registry_version: {registry_version} }}"
    )]
    UpdatedRoutingTable {
        request: Request,
        stopped_since: u64,
        registry_version: u64,
    },

    /// Both subnets have learned about the new routing information.
    /// Called `subnet_info` on both subnets to determine their `registry_version`.
    #[strum(
        to_string = "RequestState::RoutingTableChangeAccepted {{ request: {request}, stopped_since: {stopped_since} }}"
    )]
    RoutingTableChangeAccepted {
        request: Request,
        stopped_since: u64,
    },

    /// Called mgmt `delete_canister`.
    #[strum(
        to_string = "RequestState::MigratedDeleted {{ request: {request}, stopped_since: {stopped_since} }}"
    )]
    MigratedDeleted {
        request: Request,
        stopped_since: u64,
    },

    /// Six minutes have passed since `stopped_since` such that any messages to the
    /// migrated canister subnet have expired by now.
    /// Restored the controllers of the replaced canister (now addressed with migrated canister's id).
    ///
    /// This state transitions to a success event without any additional work.
    ///
    /// Called `update_settings` to restore controllers.
    #[strum(to_string = "RequestState::RestoredControllers {{ request: {request} }}")]
    RestoredControllers { request: Request },

    /// Some transition has failed fatally.
    /// We stay in this state until the controllers have been restored and then
    /// transition to a `Failed` state in the `HISTORY`.
    #[strum(to_string = "RequestState::Failed {{ request: {request}, reason: {reason} }}")]
    Failed {
        request: Request,
        recovery_state: RecoveryState,
        reason: String,
    },
}

impl RequestState {
    fn request(&self) -> &Request {
        match self {
            RequestState::Accepted { request }
            | RequestState::ControllersChanged { request }
            | RequestState::StoppedAndReady { request, .. }
            | RequestState::RenamedReplaced { request, .. }
            | RequestState::UpdatedRoutingTable { request, .. }
            | RequestState::RoutingTableChangeAccepted { request, .. }
            | RequestState::MigratedDeleted { request, .. }
            | RequestState::RestoredControllers { request }
            | RequestState::Failed { request, .. } => request,
        }
    }

    fn name(&self) -> &str {
        match self {
            RequestState::Accepted { .. } => "Accepted",
            RequestState::ControllersChanged { .. } => "ControllersChanged",
            RequestState::StoppedAndReady { .. } => "StoppedAndReady",
            RequestState::RenamedReplaced { .. } => "RenamedReplaced",
            RequestState::UpdatedRoutingTable { .. } => "UpdatedRoutingTable",
            RequestState::RoutingTableChangeAccepted { .. } => "RoutingTableChangeAccepted",
            RequestState::MigratedDeleted { .. } => "MigratedDeleted",
            RequestState::RestoredControllers { .. } => "RestoredControllers",
            RequestState::Failed { .. } => "Failed",
        }
    }
}

#[derive(Clone, Display, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    #[strum(to_string = "Event::Succeeded {{ request: {request} }}")]
    Succeeded { request: Request },
    #[strum(to_string = "Event::Failed {{ request: {request}, reason: {reason} }}")]
    Failed { request: Request, reason: String },
}

impl EventType {
    fn request(&self) -> &Request {
        match self {
            EventType::Succeeded { request } | EventType::Failed { request, .. } => request,
        }
    }
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
struct Event {
    // This field MUST be the first in the struct so that Ord works as intended.
    /// IC time in nanos since epoch.
    pub time: u64,
    pub event: EventType,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Event {{ time: {}, event: {} }}", self.time, self.event)
    }
}

impl From<&Event> for CanisterMigrationArgs {
    fn from(x: &Event) -> Self {
        x.event.request().into()
    }
}

impl Storable for CanisterMigrationArgs {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("Canister migration argument serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("Canister migration argument deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for Request {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
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
    fn to_bytes(&self) -> Cow<'_, [u8]> {
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

impl Storable for EventType {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("EventType serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("EventType deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for Event {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
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

// ========================================================================= //
// Internal methods

#[allow(clippy::disallowed_methods)]
pub fn start_timers() {
    let interval = Duration::from_secs(1);
    set_timer_interval(interval, async || {
        process_all_by_predicate(
            "accepted",
            |r| matches!(r, RequestState::Accepted { .. }),
            process_accepted,
        )
        .await
    });
    set_timer_interval(interval, async || {
        process_all_by_predicate(
            "controllers_changed",
            |r| matches!(r, RequestState::ControllersChanged { .. }),
            process_controllers_changed,
        )
        .await
    });
    set_timer_interval(interval, async || {
        process_all_by_predicate(
            "stopped",
            |r| matches!(r, RequestState::StoppedAndReady { .. }),
            process_stopped,
        )
        .await
    });
    set_timer_interval(interval, async || {
        process_all_by_predicate(
            "renamed_replaced",
            |r| matches!(r, RequestState::RenamedReplaced { .. }),
            process_renamed,
        )
        .await
    });
    set_timer_interval(interval, async || {
        process_all_by_predicate(
            "updated_routing_table",
            |r| matches!(r, RequestState::UpdatedRoutingTable { .. }),
            process_updated,
        )
        .await
    });
    set_timer_interval(interval, async || {
        process_all_by_predicate(
            "routing_table_change_accepted",
            |r| matches!(r, RequestState::RoutingTableChangeAccepted { .. }),
            process_routing_table,
        )
        .await
    });
    set_timer_interval(interval, async || {
        process_all_by_predicate(
            "migrated_canister_deleted",
            |r| matches!(r, RequestState::MigratedDeleted { .. }),
            process_migrated_canister_deleted,
        )
        .await
    });

    set_timer_interval(interval, async || process_all_succeeded().await);

    // This one has a different type from the generic ones above.
    set_timer_interval(interval, async || process_all_failed().await);
}

/// Rate limit active requests:
/// Within a sliding 24h window, we don't want to exceed some maximum of migrations.
/// Therefore, we add currently active requests and successes in the past 24 hours.
pub fn rate_limited() -> bool {
    num_requests() + num_successes_in_past_24_h() >= RATE_LIMIT
}

#[allow(dead_code)]
fn main() {
    // This block is intentionally left blank.
}
