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
    source_subnet: Principal, // from call to registry `get_subnet_for_canister`
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
    ///     * Subnet of source and target
    /// * Called mgmt `canister_status` to determine:
    ///     * We are controller of source and target
    ///     * The original controllers of source and target.
    ///     * If the target has enough cycles above the freezing threshold.
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
    ///     * Target has sufficient cycles
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

    /// Called mgmt `rename_canister`. Subsequent calls have to use the explicit subnet ID, not `aaaaa-aa`.
    ///
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
}
