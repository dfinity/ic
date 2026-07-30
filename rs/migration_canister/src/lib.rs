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
/// Changing the controllers of a canister (and renaming it) records a canister history entry and
/// thus increases the canister's memory usage. If the subnet of that canister cannot accommodate
/// that increase, then the corresponding management canister call fails: the call to
/// `rename_canister` in `RequestState::StoppedAndReady` and the call restoring the original
/// controllers of a failed request would keep failing forever.
///
/// To prevent this, the migration canister bumps the memory allocation of the migrated and
/// replaced canisters to their memory usage plus this amount when making itself their exclusive
/// controller (and restores the original memory allocation when restoring the original
/// controllers: the memory freed by lowering the memory allocation covers the canister history
/// entry recorded by that very call).
///
/// A canister history entry (of a canister with at most 10 controllers) takes way less than
/// 1KiB and hence this amount is a safe bound on the memory usage increase caused by the few
/// canister history entries recorded by the migration canister.
const MEMORY_RESERVED_FOR_CANISTER_HISTORY: u64 = 4 * 1024;

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
    #[strum(to_string = "ValidationError::CloudEngineSubnet {{ subnet: {subnet} }}")]
    CloudEngineSubnet {
        subnet: Principal,
    },
    #[strum(to_string = "ValidationError::CallFailed {{ reason: {reason} }}")]
    CallFailed {
        reason: String,
    },
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
struct CanisterMigrationArgs {
    pub migrated_canister: Principal,
    pub replaced_canister: Principal,
}

/// The memory allocation of a canister managed by the migration canister
/// while it is the exclusive controller of that canister.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedMemoryAllocation {
    /// The memory allocation of the canister at validation time. It is restored
    /// together with the original controllers of the canister.
    /// Note that `0` means that the canister's memory growth is best-effort.
    pub original: u64,
    /// The memory allocation to be set for the canister while the migration canister
    /// is its exclusive controller: the memory usage of the canister at validation time
    /// plus `MEMORY_RESERVED_FOR_CANISTER_HISTORY` (or `original` if that one is already higher,
    /// in which case setting it is a no-op).
    pub reserved: u64,
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    migrated_canister: Principal,
    migrated_canister_subnet: Principal,
    migrated_canister_original_controllers: Vec<Principal>,
    /// The memory allocation of the migrated canister at validation time and the one to be set
    /// while the migration canister is the exclusive controller of the migrated canister.
    ///
    /// This is `None` if and only if the request was validated by a version of the migration
    /// canister that did not manage the memory allocation of the migrated canister yet: in that
    /// case, the memory allocation of the migrated canister must be left untouched.
    #[serde(default)]
    migrated_canister_memory_allocation: Option<ManagedMemoryAllocation>,
    /// Whether the migration canister successfully made itself the exclusive controller
    /// of the migrated canister:
    /// - `Some(true)`: the corresponding call succeeded and thus the original controllers and
    ///   memory allocation of the migrated canister must be restored if the request fails;
    /// - `Some(false)`: no such call has been made and thus there is nothing to restore;
    /// - `None`: the outcome of the corresponding call is unknown (or the request was validated
    ///   by a version of the migration canister that did not track this yet) and thus the
    ///   canister history of the migrated canister must be inspected to determine whether
    ///   there is anything to restore.
    #[serde(default)]
    migrated_canister_exclusive_controller: Option<bool>,
    replaced_canister: Principal,
    replaced_canister_subnet: Principal,
    replaced_canister_original_controllers: Vec<Principal>,
    /// The memory allocation of the replaced canister at validation time and the one to be set
    /// while the migration canister is the exclusive controller of the replaced canister.
    ///
    /// This is `None` under the same condition as `migrated_canister_memory_allocation`.
    #[serde(default)]
    replaced_canister_memory_allocation: Option<ManagedMemoryAllocation>,
    /// Whether the migration canister successfully made itself the exclusive controller
    /// of the replaced canister (see `migrated_canister_exclusive_controller`).
    #[serde(default)]
    replaced_canister_exclusive_controller: Option<bool>,
    caller: Principal,
}

impl Request {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        migrated_canister: Principal,
        migrated_canister_subnet: Principal,
        migrated_canister_original_controllers: Vec<Principal>,
        migrated_canister_memory_allocation: Option<ManagedMemoryAllocation>,
        migrated_canister_exclusive_controller: Option<bool>,
        replaced_canister: Principal,
        replaced_canister_subnet: Principal,
        replaced_canister_original_controllers: Vec<Principal>,
        replaced_canister_memory_allocation: Option<ManagedMemoryAllocation>,
        replaced_canister_exclusive_controller: Option<bool>,
        caller: Principal,
    ) -> Self {
        Self {
            migrated_canister,
            migrated_canister_subnet,
            migrated_canister_original_controllers,
            migrated_canister_memory_allocation,
            migrated_canister_exclusive_controller,
            replaced_canister,
            replaced_canister_subnet,
            replaced_canister_original_controllers,
            replaced_canister_memory_allocation,
            replaced_canister_exclusive_controller,
            caller,
        }
    }
    fn affects_canister(&self, src_id: Principal, tgt_id: Principal) -> Option<Principal> {
        if self.migrated_canister == src_id || self.replaced_canister == src_id {
            return Some(src_id);
        }
        if self.migrated_canister == tgt_id || self.replaced_canister == tgt_id {
            return Some(tgt_id);
        }
        None
    }
}

impl Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request {{ migrated_canister: {}, migrated_canister_subnet: {}, replaced_canister: {}, replaced_canister_subnet: {}, migrated_canister_memory_allocation: {:?}, migrated_canister_exclusive_controller: {:?}, replaced_canister_memory_allocation: {:?}, replaced_canister_exclusive_controller: {:?}, caller: {}, migrated_canister_original_controllers: [",
            self.migrated_canister,
            self.migrated_canister_subnet,
            self.replaced_canister,
            self.replaced_canister_subnet,
            self.migrated_canister_memory_allocation,
            self.migrated_canister_exclusive_controller,
            self.replaced_canister_memory_allocation,
            self.replaced_canister_exclusive_controller,
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
            migrated_canister: request.migrated_canister,
            replaced_canister: request.replaced_canister,
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

    /// Called mgmt `update_settings` to make us the only controller and, in the same call,
    /// to bump the memory allocation of the migrated and replaced canisters so that recording
    /// canister history entries for them cannot fail
    /// (see `MEMORY_RESERVED_FOR_CANISTER_HISTORY`).
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
        to_string = "RequestState::RenamedReplacedCanister {{ request: {request}, stopped_since: {stopped_since} }}"
    )]
    RenamedReplacedCanister {
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
        to_string = "RequestState::MigratedCanisterDeleted {{ request: {request}, stopped_since: {stopped_since} }}"
    )]
    MigratedCanisterDeleted {
        request: Request,
        stopped_since: u64,
    },

    /// Six minutes have passed since `stopped_since` such that any messages to the
    /// migrated canister subnet have expired by now.
    /// Restored the controllers of the replaced canister (now addressed with migrated canister's id)
    /// and its original memory allocation.
    ///
    /// This state transitions to a success event without any additional work.
    ///
    /// Called `update_settings` to restore controllers and the original memory allocation.
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
            | RequestState::RenamedReplacedCanister { request, .. }
            | RequestState::UpdatedRoutingTable { request, .. }
            | RequestState::RoutingTableChangeAccepted { request, .. }
            | RequestState::MigratedCanisterDeleted { request, .. }
            | RequestState::RestoredControllers { request }
            | RequestState::Failed { request, .. } => request,
        }
    }

    fn name(&self) -> &str {
        match self {
            RequestState::Accepted { .. } => "Accepted",
            RequestState::ControllersChanged { .. } => "ControllersChanged",
            RequestState::StoppedAndReady { .. } => "StoppedAndReady",
            RequestState::RenamedReplacedCanister { .. } => "RenamedReplacedCanister",
            RequestState::UpdatedRoutingTable { .. } => "UpdatedRoutingTable",
            RequestState::RoutingTableChangeAccepted { .. } => "RoutingTableChangeAccepted",
            RequestState::MigratedCanisterDeleted { .. } => "MigratedCanisterDeleted",
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
            "renamed_replaced_canister",
            |r| matches!(r, RequestState::RenamedReplacedCanister { .. }),
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
            |r| matches!(r, RequestState::MigratedCanisterDeleted { .. }),
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
