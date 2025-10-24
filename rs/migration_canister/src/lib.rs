//! This module contains types and internal methods.
//!
//!
use candid::{CandidType, Principal};
use ic_cdk::futures::spawn;
use ic_cdk_timers::set_timer_interval;
use ic_stable_structures::{Storable, storable::Bound};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::{borrow::Cow, fmt::Display, time::Duration};
use strum_macros::Display;

use crate::{
    canister_state::{max_active_requests, num_active_requests},
    processing::{
        process_accepted, process_all_by_predicate, process_all_failed, process_all_succeeded,
        process_controllers_changed, process_renamed, process_routing_table,
        process_source_deleted, process_stopped, process_updated,
    },
};

pub use crate::migration_canister::{MigrateCanisterArgs, MigrationStatus};

mod canister_state;
mod external_interfaces;
mod migration_canister;
mod privileged;
mod processing;
#[cfg(test)]
mod tests;
mod validation;

const DEFAULT_MAX_ACTIVE_REQUESTS: u64 = 50;
/// 10 Trillion Cycles
const CYCLES_COST_PER_MIGRATION: u64 = 10_000_000_000_000;

#[derive(Clone, Display, Debug, CandidType, Deserialize)]
pub enum ValidationError {
    MigrationsDisabled,
    RateLimited,
    #[strum(to_string = "ValidationError::MigrationInProgress {{ canister: {canister} }}")]
    MigrationInProgress {
        canister: Principal,
    },
    #[strum(to_string = "ValidationError::CanisterNotFound {{ canister: {canister} }}")]
    CanisterNotFound {
        canister: Principal,
    },
    SameSubnet,
    #[strum(to_string = "ValidationError::CallerNotController {{ canister: {canister} }}")]
    CallerNotController {
        canister: Principal,
    },
    #[strum(to_string = "ValidationError::NotController {{ canister: {canister} }}")]
    NotController {
        canister: Principal,
    },
    SourceNotStopped,
    SourceNotReady,
    TargetNotStopped,
    TargetHasSnapshots,
    SourceInsufficientCycles,
    #[strum(to_string = "ValidationError::CallFailed {{ reason: {reason} }}")]
    CallFailed {
        reason: String,
    },
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn new(
        source: Principal,
        source_subnet: Principal,
        source_original_controllers: Vec<Principal>,
        target: Principal,
        target_subnet: Principal,
        target_original_controllers: Vec<Principal>,
        caller: Principal,
    ) -> Self {
        Self {
            source,
            source_subnet,
            source_original_controllers,
            target,
            target_subnet,
            target_original_controllers,
            caller,
        }
    }
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

impl Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request {{ source: {}, source_subnet: {}, target: {}, target_subnet: {}, caller: {}, source_original_controllers: [",
            self.source, self.source_subnet, self.target, self.target_subnet, self.caller
        )?;
        for x in self.source_original_controllers.iter() {
            write!(f, "{}, ", x)?;
        }
        write!(f, "], target_original_controllers: [",)?;
        for x in self.target_original_controllers.iter() {
            write!(f, "{}, ", x)?;
        }
        write!(f, "] }}")
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
    ///     * Existence of source and target.
    ///     * Subnet of source and target.
    /// * Called mgmt `canister_status` to determine:
    ///     * We are controller of source and target.
    ///     * The original controllers of source and target.
    ///     * If the target has sufficient cycles above the freezing threshold.
    #[strum(to_string = "RequestState::Accepted {{ request: {request} }}")]
    Accepted { request: Request },

    /// Called mgmt `update_settings` to make us the only controller.
    ///
    /// Certain checks are not informative before this state because the original controller
    /// could still interfere until this state.
    #[strum(to_string = "RequestState::ControllersChanged {{ request: {request} }}")]
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
        to_string = "RequestState::RenamedTarget {{ request: {request}, stopped_since: {stopped_since} }}"
    )]
    RenamedTarget {
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
        to_string = "RequestState::SourceDeleted {{ request: {request}, stopped_since: {stopped_since} }}"
    )]
    SourceDeleted {
        request: Request,
        stopped_since: u64,
    },

    /// Five minutes have passed since `stopped_since` such that any messages to the
    /// source subnet have expired by now.
    /// Restored the controllers of the target canister (now addressed with source's id).
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

    fn name(&self) -> &str {
        match self {
            RequestState::Accepted { .. } => "Accepted",
            RequestState::ControllersChanged { .. } => "ControllersChanged",
            RequestState::StoppedAndReady { .. } => "StoppedAndReady",
            RequestState::RenamedTarget { .. } => "RenamedTarget",
            RequestState::UpdatedRoutingTable { .. } => "UpdatedRoutingTable",
            RequestState::RoutingTableChangeAccepted { .. } => "RoutingTableChangeAccepted",
            RequestState::SourceDeleted { .. } => "SourceDeleted",
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
    /// IC time in nanos since epoch.
    pub time: u64,
    pub event: EventType,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Event {{ time: {}, event: {} }}", self.time, self.event)
    }
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
    set_timer_interval(interval, || {
        spawn(process_all_by_predicate(
            "accepted",
            |r| matches!(r, RequestState::Accepted { .. }),
            process_accepted,
        ))
    });
    set_timer_interval(interval, || {
        spawn(process_all_by_predicate(
            "controllers_changed",
            |r| matches!(r, RequestState::ControllersChanged { .. }),
            process_controllers_changed,
        ))
    });
    set_timer_interval(interval, || {
        spawn(process_all_by_predicate(
            "stopped",
            |r| matches!(r, RequestState::StoppedAndReady { .. }),
            process_stopped,
        ))
    });
    set_timer_interval(interval, || {
        spawn(process_all_by_predicate(
            "renamed_target",
            |r| matches!(r, RequestState::RenamedTarget { .. }),
            process_renamed,
        ))
    });
    set_timer_interval(interval, || {
        spawn(process_all_by_predicate(
            "updated_routing_table",
            |r| matches!(r, RequestState::UpdatedRoutingTable { .. }),
            process_updated,
        ))
    });
    set_timer_interval(interval, || {
        spawn(process_all_by_predicate(
            "routing_table_change_accepted",
            |r| matches!(r, RequestState::RoutingTableChangeAccepted { .. }),
            process_routing_table,
        ))
    });
    set_timer_interval(interval, || {
        spawn(process_all_by_predicate(
            "source_deleted",
            |r| matches!(r, RequestState::SourceDeleted { .. }),
            process_source_deleted,
        ))
    });

    set_timer_interval(interval, || spawn(process_all_succeeded()));

    // This one has a different type from the generic ones above.
    set_timer_interval(interval, || spawn(process_all_failed()));
}

pub fn rate_limited() -> bool {
    num_active_requests() >= max_active_requests()
}

#[allow(dead_code)]
fn main() {
    // This block is intentionally left blank.
}
