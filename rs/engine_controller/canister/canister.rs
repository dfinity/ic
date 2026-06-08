//! The engine controller canister.
//!
//! This canister provides a thin user-facing API on top of the registry
//! canister's `create_subnet` / `delete_subnet` endpoints. Only a single,
//! hard-coded authorized principal may invoke its methods.
use candid::{CandidType, Principal};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_cdk::{api::msg_caller, call::Call, init, post_upgrade, println, update};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use registry_canister::mutations::do_create_subnet::{
    CanisterCyclesCostSchedule, CreateSubnetPayload, NewSubnet,
};
use registry_canister::mutations::do_delete_subnet::DeleteSubnetPayload;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashSet;

/// The principal that is allowed to call this canister's methods when the
/// init/post-upgrade argument does not specify one.
const DEFAULT_AUTHORIZED_CALLER: &str =
    "bct5z-vccu4-6q4t2-3lb6l-wm43p-ulppt-o5sqq-w6het-rthdz-qp4yn-fqe";

/// Subnet whose DKG transcript is used to bootstrap newly created engine
/// subnets when the init/post-upgrade argument does not override it.
///
/// While the mainnet registry still defaults `initial_dkg_subnet_id` to the
/// NNS subnet, leaving this `None` would cause new cloud engines to be
/// bootstrapped from the NNS — which we want to avoid. Pinning it to a
/// non-NNS subnet here is a deliberate workaround until the registry's
/// default is changed (see proposal in PR #10242). Once that lands on
/// mainnet, this default can be dropped and the field can be left
/// unconditionally `None`.
const DEFAULT_INITIAL_DKG_SUBNET_ID: &str =
    "fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae";

/// This many nodes are expected when creating a new engine as a minimum.
const REQUIRED_NODE_COUNT: usize = 4;

thread_local! {
    /// The principal currently allowed to call the canister's methods. Set on
    /// `init` and re-evaluated on every `post_upgrade`.
    static AUTHORIZED_CALLER: RefCell<Principal> = RefCell::new(default_authorized_caller());

    /// The subnet whose DKG is used to bootstrap newly created engines. Set
    /// on `init` and re-evaluated on every `post_upgrade`.
    static INITIAL_DKG_SUBNET_ID: RefCell<SubnetId> =
        RefCell::new(default_initial_dkg_subnet_id());
}

fn default_authorized_caller() -> Principal {
    Principal::from_text(DEFAULT_AUTHORIZED_CALLER)
        .expect("hardcoded DEFAULT_AUTHORIZED_CALLER must be a valid principal")
}

fn default_initial_dkg_subnet_id() -> SubnetId {
    let p = Principal::from_text(DEFAULT_INITIAL_DKG_SUBNET_ID)
        .expect("hardcoded DEFAULT_INITIAL_DKG_SUBNET_ID must be a valid principal");
    SubnetId::new(PrincipalId(p))
}

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

fn apply_init_args(args: Option<EngineControllerInitArgs>) {
    let args = args.unwrap_or_default();
    let authorized = args
        .authorized_caller
        .unwrap_or_else(default_authorized_caller);
    AUTHORIZED_CALLER.with(|c| *c.borrow_mut() = authorized);
    let initial_dkg_subnet_id = args
        .initial_dkg_subnet_id
        .map(|p| SubnetId::new(PrincipalId(p)))
        .unwrap_or_else(default_initial_dkg_subnet_id);
    INITIAL_DKG_SUBNET_ID.with(|c| *c.borrow_mut() = initial_dkg_subnet_id);
    println!(
        "engine_controller: authorized caller set to {authorized}, \
         initial_dkg_subnet_id set to {initial_dkg_subnet_id}"
    );
}

#[init]
fn init(args: Option<EngineControllerInitArgs>) {
    apply_init_args(args);
}

#[post_upgrade]
fn post_upgrade(args: Option<EngineControllerInitArgs>) {
    apply_init_args(args);
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateEngineArgs {
    pub node_ids: Vec<Principal>,
    pub subnet_admins: Vec<Principal>,
    /// Blessed replica version that the new engine subnet should run.
    pub replica_version_id: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DeleteEngineArgs {
    pub subnet_id: Principal,
}

fn ensure_authorized() -> Result<Principal, String> {
    let caller = msg_caller();
    let expected = AUTHORIZED_CALLER.with(|c| *c.borrow());
    if caller != expected {
        return Err(format!(
            "Caller {caller} is not authorized to call this canister"
        ));
    }
    Ok(caller)
}

#[update]
async fn create_engine(args: CreateEngineArgs) -> Result<NewSubnet, String> {
    let caller = ensure_authorized()?;

    // Validate node list.
    if args.node_ids.len() < REQUIRED_NODE_COUNT {
        return Err(format!(
            "Expected at least {REQUIRED_NODE_COUNT} node ids, got {}",
            args.node_ids.len()
        ));
    }
    let mut seen: HashSet<Principal> = HashSet::new();
    for n in &args.node_ids {
        if !seen.insert(*n) {
            return Err(format!("Duplicate node id supplied: {n}"));
        }
    }

    // Make sure the caller is part of the subnet admins.
    let mut subnet_admins: Vec<PrincipalId> =
        args.subnet_admins.into_iter().map(PrincipalId).collect();
    let caller_pid = PrincipalId(caller);
    if !subnet_admins.contains(&caller_pid) {
        subnet_admins.push(caller_pid);
    }

    let node_ids: Vec<NodeId> = args
        .node_ids
        .into_iter()
        .map(|p| NodeId::from(PrincipalId(p)))
        .collect();

    let initial_dkg_subnet_id = INITIAL_DKG_SUBNET_ID.with(|c| *c.borrow());

    let payload = CreateSubnetPayload {
        node_ids,
        subnet_admins: Some(subnet_admins),
        replica_version_id: args.replica_version_id,
        subnet_type: SubnetType::CloudEngine,
        initial_dkg_subnet_id: Some(initial_dkg_subnet_id),
        dkg_interval_length: 499,
        dkg_dealings_per_block: 1,
        initial_notary_delay_millis: 300,
        max_block_payload_size: 4 * 1024 * 1024, // 4 MiB
        max_ingress_bytes_per_message: 2 * 1024 * 1024, // 2 MiB
        max_ingress_messages_per_block: 1000,
        unit_delay_millis: 1000,
        canister_cycles_cost_schedule: Some(CanisterCyclesCostSchedule::Free),
        features: SubnetFeatures {
            http_requests: true,
            sev_enabled: Some(false),
        },
        ..Default::default()
    };

    let response: Result<NewSubnet, String> =
        Call::unbounded_wait(REGISTRY_CANISTER_ID.into(), "create_subnet")
            .with_arg(payload)
            .await
            .map_err(|e| format!("registry.create_subnet call failed: {e:?}"))?
            .candid()
            .map_err(|e| format!("Failed to decode registry response: {e}"))?;

    response
}

#[update]
async fn delete_engine(args: DeleteEngineArgs) -> Result<(), String> {
    ensure_authorized()?;

    let payload = DeleteSubnetPayload {
        subnet_id: args.subnet_id,
    };

    let response: Result<(), String> =
        Call::unbounded_wait(REGISTRY_CANISTER_ID.into(), "delete_subnet")
            .with_arg(payload)
            .await
            .map_err(|e| format!("registry.delete_subnet call failed: {e:?}"))?
            .candid()
            .map_err(|e| format!("Failed to decode registry response: {e}"))?;

    response
}

fn main() {
    // This block is intentionally left blank.
}

#[cfg(test)]
mod tests;
