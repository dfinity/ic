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

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateEngineArgs {
    pub node_ids: Vec<Principal>,
    pub subnet_admins: Vec<Principal>,
    /// Elected replica version that the new engine subnet should run.
    pub replica_version_id: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DeleteEngineArgs {
    pub subnet_id: Principal,
}
