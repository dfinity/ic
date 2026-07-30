//! The engine controller canister.
//!
//! This canister provides a thin user-facing API on top of the registry
//! canister's `create_subnet` / `delete_subnet` endpoints. Only a single,
//! hard-coded authorized principal may invoke its methods.
use candid::Principal;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_cdk::{api::msg_caller, call::Call, init, post_upgrade, println, update};
use ic_engine_controller::{
    ChangeSubnetMembershipPayload, CreateEngineArgs, DeleteEngineArgs,
    DeployGuestosToAllSubnetNodesPayload, EngineControllerInitArgs, NewSubnet, UpdateSubnetPayload,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use registry_canister::mutations::do_create_subnet::{
    CanisterCyclesCostSchedule, CreateSubnetPayload,
};
use registry_canister::mutations::do_delete_subnet::DeleteSubnetPayload;
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
    ensure_authorized()?;

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

    // Forward the supplied `subnet_admins` list to the registry as-is; the
    // engine controller does not manipulate it.
    let subnet_admins: Vec<PrincipalId> = args.subnet_admins.into_iter().map(PrincipalId).collect();

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
            canister_sandboxing: false,
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

/// Validates that the only fields set on the proxied `UpdateSubnetPayload`
/// are the ones the engine controller is allowed to manage: `subnet_admins`
/// and `is_halted` (subnet halting / unhalting). Every other `Option<_>`
/// field must be `None`, and the single non-optional knob
/// (`set_gossip_config_to_default`) must hold its default value (`false`).
/// The required `subnet_id` is exempt because it merely identifies the target.
///
/// This keeps the surface of `update_subnet` deliberately tiny: only the
/// fields the engine controller is intended to manage flow through. Adding a
/// new allowed field is a conscious, code-level decision.
fn ensure_only_allowed_fields_set(payload: &UpdateSubnetPayload) -> Result<(), String> {
    let UpdateSubnetPayload {
        subnet_id: _,
        // The fields we allow.
        subnet_admins: _,
        is_halted: _,

        max_ingress_bytes_per_message,
        max_ingress_bytes_per_block,
        max_ingress_messages_per_block,
        max_block_payload_size,
        unit_delay_millis,
        initial_notary_delay_millis,
        dkg_interval_length,
        dkg_dealings_per_block,
        start_as_nns,
        subnet_type,
        halt_at_cup_height,
        features,
        resource_limits,
        chain_key_config,
        chain_key_signing_enable,
        chain_key_signing_disable,
        max_number_of_canisters,
        ssh_readonly_access,
        ssh_backup_access,
        max_artifact_streams_per_peer,
        max_chunk_wait_ms,
        max_duplicity,
        max_chunk_size,
        receive_check_cache_size,
        pfn_evaluation_period_ms,
        registry_poll_period_ms,
        retransmission_request_ms,
        set_gossip_config_to_default,
    } = payload;

    // Build up a list of fields the caller is trying to set so the error is
    // actionable. The check is purely structural: any `Some(_)` (or a
    // non-default bool) is treated as "the caller tried to update this".
    let mut disallowed: Vec<&'static str> = vec![];
    macro_rules! check_none {
        ($field:expr, $name:literal) => {
            if $field.is_some() {
                disallowed.push($name);
            }
        };
    }
    check_none!(
        max_ingress_bytes_per_message,
        "max_ingress_bytes_per_message"
    );
    check_none!(max_ingress_bytes_per_block, "max_ingress_bytes_per_block");
    check_none!(
        max_ingress_messages_per_block,
        "max_ingress_messages_per_block"
    );
    check_none!(max_block_payload_size, "max_block_payload_size");
    check_none!(unit_delay_millis, "unit_delay_millis");
    check_none!(initial_notary_delay_millis, "initial_notary_delay_millis");
    check_none!(dkg_interval_length, "dkg_interval_length");
    check_none!(dkg_dealings_per_block, "dkg_dealings_per_block");
    check_none!(start_as_nns, "start_as_nns");
    check_none!(subnet_type, "subnet_type");
    check_none!(halt_at_cup_height, "halt_at_cup_height");
    check_none!(features, "features");
    check_none!(resource_limits, "resource_limits");
    check_none!(chain_key_config, "chain_key_config");
    check_none!(chain_key_signing_enable, "chain_key_signing_enable");
    check_none!(chain_key_signing_disable, "chain_key_signing_disable");
    check_none!(max_number_of_canisters, "max_number_of_canisters");
    check_none!(ssh_readonly_access, "ssh_readonly_access");
    check_none!(ssh_backup_access, "ssh_backup_access");
    check_none!(
        max_artifact_streams_per_peer,
        "max_artifact_streams_per_peer"
    );
    check_none!(max_chunk_wait_ms, "max_chunk_wait_ms");
    check_none!(max_duplicity, "max_duplicity");
    check_none!(max_chunk_size, "max_chunk_size");
    check_none!(receive_check_cache_size, "receive_check_cache_size");
    check_none!(pfn_evaluation_period_ms, "pfn_evaluation_period_ms");
    check_none!(registry_poll_period_ms, "registry_poll_period_ms");
    check_none!(retransmission_request_ms, "retransmission_request_ms");
    if *set_gossip_config_to_default {
        disallowed.push("set_gossip_config_to_default");
    }

    if disallowed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Updating these fields via the engine controller is not allowed: {}. \
             Only `subnet_admins` and `is_halted` may be updated.",
            disallowed.join(", ")
        ))
    }
}

/// Proxies to the registry's `update_subnet` endpoint. Only `subnet_admins`
/// and `is_halted` may be updated through this path; every other field must be
/// left at its default value (`None` / `false`) or the call is rejected.
#[update]
async fn update_subnet(payload: UpdateSubnetPayload) -> Result<(), String> {
    ensure_authorized()?;
    ensure_only_allowed_fields_set(&payload)?;

    Call::unbounded_wait(REGISTRY_CANISTER_ID.into(), "update_subnet")
        .with_arg(payload)
        .await
        .map_err(|e| format!("registry.update_subnet call failed: {e:?}"))?
        .candid::<()>()
        .map_err(|e| format!("Failed to decode registry response: {e}"))?;

    Ok(())
}

/// Proxies to the registry's `deploy_guestos_to_all_subnet_nodes` endpoint,
/// which is the registry path for updating a subnet's replica version.
#[update]
async fn deploy_guestos_to_all_subnet_nodes(
    payload: DeployGuestosToAllSubnetNodesPayload,
) -> Result<(), String> {
    ensure_authorized()?;

    Call::unbounded_wait(
        REGISTRY_CANISTER_ID.into(),
        "deploy_guestos_to_all_subnet_nodes",
    )
    .with_arg(payload)
    .await
    .map_err(|e| format!("registry.deploy_guestos_to_all_subnet_nodes call failed: {e:?}"))?
    .candid::<()>()
    .map_err(|e| format!("Failed to decode registry response: {e}"))?;

    Ok(())
}

/// Proxies to the registry's `change_subnet_membership` endpoint. The
/// registry enforces that, when invoked by the engine controller, the target
/// subnet must be of type `CloudEngine`.
#[update]
async fn change_subnet_membership(payload: ChangeSubnetMembershipPayload) -> Result<(), String> {
    ensure_authorized()?;

    Call::unbounded_wait(REGISTRY_CANISTER_ID.into(), "change_subnet_membership")
        .with_arg(payload)
        .await
        .map_err(|e| format!("registry.change_subnet_membership call failed: {e:?}"))?
        .candid::<()>()
        .map_err(|e| format!("Failed to decode registry response: {e}"))?;

    Ok(())
}

fn main() {
    // This block is intentionally left blank.
}

#[cfg(test)]
mod tests;
