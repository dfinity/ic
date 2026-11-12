//! Shared types for the engine controller canister.
//!
//! This crate exposes the Candid-encoded argument and response types used by
//! the engine controller canister so that clients (other canisters, agents,
//! tests) can depend on a single source of truth instead of redeclaring them.
use candid::{CandidType, Principal};
use serde::Deserialize;

// Re-export the response type returned by `create_engine` so clients don't
// have to depend on `registry-canister` directly just to decode it.
pub use registry_canister::mutations::do_create_subnet::NewSubnet;

// Re-export the payload types accepted by the proxy endpoints
// (`update_subnet` and `deploy_guestos_to_all_subnet_nodes`) so clients
// don't have to depend on `registry-canister` directly to construct them.
pub use registry_canister::mutations::do_change_subnet_membership::ChangeSubnetMembershipPayload;
pub use registry_canister::mutations::do_deploy_guestos_to_all_subnet_nodes::DeployGuestosToAllSubnetNodesPayload;
pub use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct EngineControllerInitArgs {
    /// If `Some`, replaces the default authorized caller; if `None`, the
    /// default is kept.
    pub authorized_caller: Option<Principal>,
    /// If `Some`, replaces the default `initial_dkg_subnet_id` used when
    /// forwarding `CreateSubnetPayload` to the registry; if `None`, the
    /// hard-coded default is kept.
    pub initial_dkg_subnet_id: Option<Principal>,
}

/// State limits for a new engine subnet, in bytes. `None` (or `0`) keeps the
/// protocol default. The query limits are deliberately absent: they stay
/// with governance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, CandidType, Deserialize)]
pub struct EngineResourceLimits {
    pub maximum_state_size: Option<u64>,
    pub maximum_state_delta: Option<u64>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateEngineArgs {
    pub node_ids: Vec<Principal>,
    pub subnet_admins: Vec<Principal>,
    /// Elected replica version that the new engine subnet should run.
    pub replica_version_id: String,
    /// State limits for the new subnet. `None` keeps the protocol defaults.
    pub resource_limits: Option<EngineResourceLimits>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DeleteEngineArgs {
    pub subnet_id: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateCanisterArgs {
    /// The cloud engine subnet to create the canister on.
    pub subnet_id: Principal,
    /// The new canister's controllers, 1 to 10 of them. The engine controller
    /// is not made a controller unless it is listed here.
    pub controllers: Vec<Principal>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct NewCanister {
    pub canister_id: Principal,
}
