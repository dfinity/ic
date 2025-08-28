//! This module contains types and internal methods.  
//!
//!

use candid::{CandidType, Principal};
use ic_cdk::futures::spawn;
use ic_cdk_timers::set_timer_interval;
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::{borrow::Cow, time::Duration};

use crate::{
    canister_state::{max_active_requests, num_active_requests},
    processing::{
        process_accepted, process_all_failed, process_all_generic, process_controllers_changed,
    },
};

mod canister_state;
mod external_interfaces;
mod migration_canister;
mod privileged;
mod processing;
mod validation;

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

// ========================================================================= //
// Internal methods

#[allow(clippy::disallowed_methods)]
pub fn start_timers() {
    let interval = Duration::from_secs(1);
    set_timer_interval(interval, || {
        spawn(process_all_generic(
            "accepted",
            |r| matches!(r, RequestState::Accepted { .. }),
            process_accepted,
        ))
    });
    set_timer_interval(interval, || {
        spawn(process_all_generic(
            "controllers_changed",
            |r| matches!(r, RequestState::ControllersChanged { .. }),
            process_controllers_changed,
        ))
    });

    // This one has a different type from the generic ones above.
    set_timer_interval(interval, || spawn(process_all_failed()));
}

pub fn rate_limited() -> bool {
    num_active_requests() > max_active_requests()
}
