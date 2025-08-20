//! This module contains types and internal methods.  
//!
//!

use candid::Principal;

enum ValidatonError {
    MigrationsDisabled,
    MigrationInProgress { canisters: Vec<Principal> },
    RateLimited,
    CanisterNotFound { canisters: Vec<Principal> },
    SameSubnet,
    SenderNotController,
    NotController,
    TargetNotEnoughCycles,
    SourceNotStopped,
    SourceNotReady,
    TargetNotStopped,
    TargetHasSnapshots,
}

struct Request {
    source: Principal,
    source_subnet: Principal,
    source_original_controllers: Vec<Principal>,
    target: Principal,
    target_subnet: Principal,
    target_original_controllers: Vec<Principal>,
    sender: Principal,
}

enum RequestState {
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
    /// Record the original controllers of source.
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
        stopped_since: Time,
        canister_version: u64,
        canister_history_total_num: u64,
    },

    /// Called mgmt `rename_canister`. Subsequent mgmt calls have to use the explicit subnet ID, not `aaaaa-aa`.
    RenamedTarget {
        request: Request,
        stopped_since: Time,
    },

    /// Called registry `migrate_canisters`.
    ///
    /// Record the new registry version.
    UpdatedRoutingTable {
        request: Request,
        stopped_since: Time,
        registry_version: u64,
    },

    /// Both subnets have learned about the new routing information.
    /// Called `subnet_info` on both subnets to determine their `registry_version`.
    RoutingTableChangeAccepted {
        request: Request,
        stopped_since: Time,
    },

    /// Called mgmt `delete_canister`.
    SourceDeleted {
        request: Request,
        stopped_since: Time,
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
