use prost::Message;

use candid::{candid_method, Decode};
use dfn_candid::{candid, candid_one};
use dfn_core::{
    api::{arg_data, data_certificate, reply},
    over, over_async, over_may_reject, stable,
};
use ic_base_types::NodeId;
use ic_certified_map::{AsHashTree, HashTree};
use ic_nervous_system_common::MethodAuthzChange;
use ic_nns_common::{access_control::check_caller_is_root, pb::v1::CanisterAuthzInfo};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_protobuf::registry::{
    dc::v1::AddOrRemoveDataCentersProposalPayload,
    node_rewards::v2::UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_transport::{
    deserialize_atomic_mutate_request, deserialize_get_changes_since_request,
    deserialize_get_value_request,
    pb::v1::{
        registry_error::Code, CertifiedResponse, RegistryAtomicMutateResponse, RegistryDelta,
        RegistryError, RegistryGetChangesSinceRequest, RegistryGetChangesSinceResponse,
        RegistryGetLatestVersionResponse, RegistryGetValueResponse,
    },
    serialize_atomic_mutate_response, serialize_get_changes_since_response,
    serialize_get_value_response,
};
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as MAX_RESPONSE_SIZE;
use registry_canister::{
    certification::{current_version_tree, hash_tree_to_proto},
    common::LOG_PREFIX,
    init::RegistryCanisterInitPayload,
    mutations::{
        do_add_node_operator::AddNodeOperatorPayload,
        do_add_nodes_to_subnet::AddNodesToSubnetPayload,
        do_bless_replica_version::BlessReplicaVersionPayload,
        do_create_subnet::CreateSubnetPayload,
        do_delete_subnet::DeleteSubnetPayload,
        do_recover_subnet::RecoverSubnetPayload,
        do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload,
        do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
        do_update_node_operator_config_directly::UpdateNodeOperatorConfigDirectlyPayload,
        do_update_subnet::UpdateSubnetPayload,
        do_update_subnet_replica::UpdateSubnetReplicaVersionPayload,
        do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload,
        node_management::{
            do_remove_node_directly::RemoveNodeDirectlyPayload, do_remove_nodes::RemoveNodesPayload,
        },
        reroute_canister_range::RerouteCanisterRangePayload,
    },
    pb::v1::{NodeProvidersMonthlyXdrRewards, RegistryCanisterStableStorage},
    proto_on_wire::protobuf,
    registry::{EncodedVersion, Registry},
    registry_lifecycle,
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_protobuf::registry::node_operator::v1::RemoveNodeOperatorsPayload;
use registry_canister::mutations::do_set_firewall_config::SetFirewallConfigPayload;
use registry_canister::mutations::node_management::do_add_node::AddNodePayload;

// Makes expose_build_metadata! available.
#[macro_use]
extern crate ic_nervous_system_common;

static mut REGISTRY: Option<Registry> = None;

const MAX_VERSIONS_PER_QUERY: usize = 1000;
// The maximum size of deltas that the registry will attempt to send.
// We reserve ⅓ of the response buffer capacity for encoding overhead.
const MAX_REGISTRY_DELTAS_SIZE: usize = (MAX_RESPONSE_SIZE - MAX_RESPONSE_SIZE / 3) as usize;

fn registry() -> &'static Registry {
    registry_mut()
}

fn registry_mut() -> &'static mut Registry {
    unsafe {
        if let Some(g) = &mut REGISTRY {
            g
        } else {
            REGISTRY = Some(Registry::new());
            registry_mut()
        }
    }
}

fn check_caller_is_governance_and_log(method_name: &str) {
    let caller = dfn_core::api::caller();
    println!("{}call: {} from: {}", LOG_PREFIX, method_name, caller);
    assert_eq!(
        caller,
        GOVERNANCE_CANISTER_ID.into(),
        "{}Principal: {} is not authorized to call this method: {}",
        LOG_PREFIX,
        caller,
        method_name
    );
}

/// Initializes the registry.
///
/// The argument is expected to be a candid-encoded
/// `RegistryCanisterInitPayload`.
///
/// For convenience, content may be injected at init time through the
/// `RegistryCanisterInitPayload::mutations` field.
///
/// The contract is simply that those `RegistryAtomicMutateRequest` are
/// processed one at a time, in order, and if any fail, the canister
/// initialization traps. The caller is always authorized to make these
/// mutations, even if the `RegistryCanisterInitPayload::authz_info` field state
/// otherwise.
///
/// In other words, there is no difference in the result between using an init
/// payload or starting with an empty content and having an authorized user
/// making those mutations through the `atomic_mutate` method. However, there is
/// a difference with respect to intermediate state: using `canister_init`, the
/// intermediate state, such as the one with empty content, is never
/// visible through the public API.
#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();
    recertify_registry();

    let init_payload =
        Decode!(&arg_data(), RegistryCanisterInitPayload)
            .expect("The init argument for the registry canister must be a Candid-encoded RegistryCanisterInitPayload.");
    println!(
        "{}canister_init: Initializing with: {}",
        LOG_PREFIX, init_payload
    );
    let registry = registry_mut();

    init_payload
        .mutations
        .into_iter()
        .for_each(|mutation_request| {
            registry.maybe_apply_mutation_internal(mutation_request.mutations)
        });
    recertify_registry();
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}canister_pre_upgrade", LOG_PREFIX);
    let registry = registry();
    let mut serialized = Vec::new();
    let ss = RegistryCanisterStableStorage {
        registry: Some(registry.serializable_form()),
        pre_upgrade_version: Some(registry.latest_version()),
    };
    ss.encode(&mut serialized)
        .expect("Error serializing to stable.");
    stable::set(&serialized);
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_post_upgrade", LOG_PREFIX);
    // call stable_storage APIs and get registry instance in canister context
    let registry = registry_mut();
    let stable_storage = stable::get();
    // delegate real work to more testable function
    registry_lifecycle::canister_post_upgrade(registry, stable_storage.as_slice());
}

expose_build_metadata! {}

#[export_name = "canister_update update_authz"]
fn update_authz() {
    check_caller_is_root();
    over(candid_one, |_: Vec<MethodAuthzChange>| {
        println!(
            "{}update_authz was called. \
                 This does not do anything, since the registry canister no longer has any \
                 function whose access is controlled using this mechanism. \
                 TODO(NNS1-413): Remove this once we are sure that there are no callers.",
            LOG_PREFIX,
        );
    })
}

#[export_name = "canister_query current_authz"]
fn current_authz() {
    over(candid, |_: ()| {
        println!(
            "{}current_authz was called. \
                 This always returns the default value, since the registry canister's state no \
                 longer contains a CanisterAuthzInfo. \
                 TODO(NNS1-413): Remove this once we are sure that there are no callers.",
            LOG_PREFIX,
        );
        CanisterAuthzInfo::default()
    })
}

#[export_name = "canister_query get_changes_since"]
fn get_changes_since() {
    let response_pb = match deserialize_get_changes_since_request(arg_data()) {
        Ok(version) => {
            let registry = registry();

            let max_versions = registry
                .count_fitting_deltas(version, MAX_REGISTRY_DELTAS_SIZE)
                .min(MAX_VERSIONS_PER_QUERY);

            RegistryGetChangesSinceResponse {
                error: None,
                version: registry.latest_version(),
                deltas: registry.get_changes_since(version, Some(max_versions)),
            }
        }
        Err(error) => RegistryGetChangesSinceResponse {
            error: Some(RegistryError {
                code: Code::MalformedMessage as i32,
                reason: error.to_string(),
                key: Vec::<u8>::default(),
            }),
            version: 0,
            deltas: Vec::<RegistryDelta>::default(),
        },
    };
    let bytes =
        serialize_get_changes_since_response(response_pb).expect("Error serializing response");

    reply(&bytes);
}

#[export_name = "canister_query get_certified_changes_since"]
fn get_certified_changes_since() {
    over(
        protobuf,
        |req: RegistryGetChangesSinceRequest| -> CertifiedResponse {
            use ic_certified_map::{fork, labeled, labeled_hash};
            let latest_version = registry().latest_version();
            let from_version = EncodedVersion::from(req.version.saturating_add(1));

            let max_versions = registry()
                .count_fitting_deltas(req.version, MAX_REGISTRY_DELTAS_SIZE)
                .min(MAX_VERSIONS_PER_QUERY);

            let to_version = EncodedVersion::from(req.version.saturating_add(max_versions as u64));
            let delta_tree = registry()
                .changelog()
                .value_range(from_version.as_ref(), to_version.as_ref());

            let hash_tree = fork(
                current_version_tree(latest_version),
                if req.version < latest_version {
                    labeled(b"delta", delta_tree)
                } else {
                    HashTree::Pruned(labeled_hash(b"delta", &registry().changelog().root_hash()))
                },
            );

            certified_response(hash_tree)
        },
    )
}

#[export_name = "canister_query get_value"]
fn get_value() {
    let response_pb = match deserialize_get_value_request(arg_data()) {
        Ok((key, version_opt)) => {
            let registry = registry();
            let version = version_opt.unwrap_or_else(|| registry.latest_version());
            let result = registry.get(&key, version);
            match result {
                Some(value) => RegistryGetValueResponse {
                    error: None,
                    version: value.version,
                    value: value.value.clone(),
                },
                None => RegistryGetValueResponse {
                    error: Some(RegistryError {
                        code: Code::KeyNotPresent as i32,
                        key: key.clone(),
                        reason: String::default(),
                    }),
                    // If we get None, that means that either the key was never present
                    // or the previous value is a tombstone. Thus, the only correct value
                    // for version to return is the version at which we attempted the read
                    // and not 0. The reason is that if we attempt to insert/update a value
                    // or use it as a precondition, we can only ask that nothing has changed
                    // since the moment we did this read.
                    version,
                    value: Vec::<u8>::default(),
                },
            }
        }
        Err(error) => RegistryGetValueResponse {
            error: Some(RegistryError {
                code: Code::MalformedMessage as i32,
                key: Vec::<u8>::default(),
                reason: error.to_string(),
            }),
            version: 0,
            value: Vec::<u8>::default(),
        },
    };
    let bytes = serialize_get_value_response(response_pb).expect("Error serializing response");
    reply(&bytes);
}

#[export_name = "canister_query get_latest_version"]
fn get_latest_version() {
    over(protobuf, |_: Vec<u8>| RegistryGetLatestVersionResponse {
        version: registry().latest_version(),
    });
}

#[export_name = "canister_query get_certified_latest_version"]
fn get_certified_latest_version() {
    over(protobuf, |_: Vec<u8>| -> CertifiedResponse {
        use ic_certified_map::{fork, labeled_hash};
        let latest_version = registry().latest_version();
        let hash_tree = fork(
            current_version_tree(latest_version),
            HashTree::Pruned(labeled_hash(b"delta", &registry().changelog().root_hash())),
        );
        certified_response(hash_tree)
    });
}

#[export_name = "canister_update atomic_mutate"]
fn atomic_mutate() {
    let caller = dfn_core::api::caller();
    //
    // - The governance canister is always allowed to mutate the registry
    // - The root canister is also allowed, so that IDs of new NNS canisters can be
    //   recorded.
    assert!(
        caller == GOVERNANCE_CANISTER_ID.get() || caller == ROOT_CANISTER_ID.get(),
        "{}Principal {} is not authorized to call 'atomic_mutate'.",
        LOG_PREFIX,
        caller
    );
    println!("{}call 'atomic_mutate' from {}", LOG_PREFIX, caller);

    let response_pb = match deserialize_atomic_mutate_request(arg_data()) {
        Ok(request_pb) => {
            registry_mut().maybe_apply_mutation_internal(request_pb.mutations);
            RegistryAtomicMutateResponse {
                errors: vec![],
                version: registry().latest_version(),
            }
        }
        Err(error) => {
            println!(
                "{}Received a mutate call, but the request could not de deserialized due to: {}",
                LOG_PREFIX, error
            );
            let mut response_pb = RegistryAtomicMutateResponse::default();
            let error_pb = RegistryError {
                code: Code::MalformedMessage as i32,
                reason: error.to_string(),
                ..Default::default()
            };
            response_pb.errors.push(error_pb);
            response_pb
        }
    };

    recertify_registry();

    let bytes = serialize_atomic_mutate_response(response_pb).expect("Error serializing response");
    reply(&bytes)
}

#[export_name = "canister_update bless_replica_version"]
fn bless_replica_version() {
    check_caller_is_governance_and_log("bless_replica_version");
    over(candid_one, |payload: BlessReplicaVersionPayload| {
        bless_replica_version_(payload)
    });
}

#[candid_method(update, rename = "bless_replica_version")]
fn bless_replica_version_(payload: BlessReplicaVersionPayload) {
    registry_mut().do_bless_replica_version(payload);
    recertify_registry();
}

#[export_name = "canister_update update_subnet_replica_version"]
fn update_subnet_replica_version() {
    check_caller_is_governance_and_log("update_subnet_replica_version");
    over(candid_one, |payload: UpdateSubnetReplicaVersionPayload| {
        update_subnet_replica_version_(payload)
    });
}

#[candid_method(update, rename = "update_subnet_replica_version")]
fn update_subnet_replica_version_(payload: UpdateSubnetReplicaVersionPayload) {
    registry_mut().do_update_subnet_replica_version(payload);
    recertify_registry();
}

#[export_name = "canister_update add_node_operator"]
fn add_node_operator() {
    check_caller_is_governance_and_log("add_node_operator");
    over(candid_one, |payload: AddNodeOperatorPayload| {
        add_node_operator_(payload)
    });
}

#[candid_method(update, rename = "add_node_operator")]
fn add_node_operator_(payload: AddNodeOperatorPayload) {
    registry_mut().do_add_node_operator(payload);
    recertify_registry();
}

#[export_name = "canister_update create_subnet"]
fn create_subnet() {
    check_caller_is_governance_and_log("create_subnet");
    over_async(candid_one, |payload: CreateSubnetPayload| async move {
        create_subnet_(payload).await
    });
}

#[candid_method(update, rename = "create_subnet")]
async fn create_subnet_(payload: CreateSubnetPayload) {
    registry_mut().do_create_subnet(payload).await;
    recertify_registry();
}

#[export_name = "canister_update add_nodes_to_subnet"]
fn add_nodes_to_subnet() {
    check_caller_is_governance_and_log("add_nodes_to_subnet");
    over(candid_one, |payload: AddNodesToSubnetPayload| {
        add_nodes_to_subnet_(payload)
    });
}

#[candid_method(update, rename = "add_nodes_to_subnet")]
fn add_nodes_to_subnet_(payload: AddNodesToSubnetPayload) {
    registry_mut().do_add_nodes_to_subnet(payload);
    recertify_registry();
}

#[export_name = "canister_update delete_subnet"]
fn delete_subnet() {
    check_caller_is_governance_and_log("delete_subnet");
    over_async(candid_one, |payload: DeleteSubnetPayload| async move {
        delete_subnet_(payload).await
    });
}

#[candid_method(update, rename = "delete_subnet")]
async fn delete_subnet_(payload: DeleteSubnetPayload) {
    registry_mut().do_delete_subnet(payload).await;
    recertify_registry();
}

#[export_name = "canister_update recover_subnet"]
fn recover_subnet() {
    check_caller_is_governance_and_log("recover_subnet");
    over_async(candid_one, |payload: RecoverSubnetPayload| async move {
        recover_subnet_(payload).await
    });
}

#[candid_method(update, rename = "recover_subnet")]
async fn recover_subnet_(payload: RecoverSubnetPayload) {
    registry_mut().do_recover_subnet(payload).await;
    recertify_registry();
}

#[export_name = "canister_update remove_nodes_from_subnet"]
fn remove_nodes_from_subnet() {
    check_caller_is_governance_and_log("remove_nodes_from_subnet");
    over(candid_one, |payload: RemoveNodesFromSubnetPayload| {
        remove_nodes_from_subnet_(payload)
    });
}

#[candid_method(update, rename = "remove_nodes_from_subnet")]
fn remove_nodes_from_subnet_(payload: RemoveNodesFromSubnetPayload) {
    registry_mut().do_remove_nodes_from_subnet(payload);
    recertify_registry();
}

#[export_name = "canister_update remove_nodes"]
fn remove_nodes() {
    check_caller_is_governance_and_log("remove_nodes");
    over(candid_one, |payload: RemoveNodesPayload| {
        remove_nodes_(payload)
    });
}

#[candid_method(update, rename = "remove_nodes")]
fn remove_nodes_(payload: RemoveNodesPayload) {
    registry_mut().do_remove_nodes(payload);
    recertify_registry();
}

#[export_name = "canister_update update_node_operator_config"]
fn update_node_operator_config() {
    check_caller_is_governance_and_log("update_node_operator_config");
    over(candid_one, |payload: UpdateNodeOperatorConfigPayload| {
        update_node_operator_config_(payload)
    });
}

#[candid_method(update, rename = "update_node_operator_config")]
fn update_node_operator_config_(payload: UpdateNodeOperatorConfigPayload) {
    registry_mut().do_update_node_operator_config(payload);
    recertify_registry();
}

#[export_name = "canister_update update_node_operator_config_directly"]
fn update_node_operator_config_directly() {
    // This method can be called by anyone
    println!(
        "{}call: update_node_operator_config_directly from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over(
        candid_one,
        |payload: UpdateNodeOperatorConfigDirectlyPayload| {
            update_node_operator_config_directly_(payload)
        },
    );
}

#[candid_method(update, rename = "update_node_operator_config_directly")]
fn update_node_operator_config_directly_(payload: UpdateNodeOperatorConfigDirectlyPayload) {
    registry_mut().do_update_node_operator_config_directly(payload);
    recertify_registry();
}

#[export_name = "canister_update remove_node_operators"]
fn remove_node_operators() {
    check_caller_is_governance_and_log("remove_node_operators");
    over(candid_one, |payload: RemoveNodeOperatorsPayload| {
        remove_node_operators_(payload)
    });
}

#[candid_method(update, rename = "remove_node_operators")]
fn remove_node_operators_(payload: RemoveNodeOperatorsPayload) {
    registry_mut().do_remove_node_operators(payload);
    recertify_registry();
}

#[export_name = "canister_update update_subnet"]
fn update_subnet() {
    check_caller_is_governance_and_log("update_subnet");
    over(candid_one, |payload: UpdateSubnetPayload| {
        update_subnet_(payload)
    });
}

#[candid_method(update, rename = "update_subnet")]
fn update_subnet_(payload: UpdateSubnetPayload) {
    registry_mut().do_update_subnet(payload);
    recertify_registry();
}

#[export_name = "canister_update clear_provisional_whitelist"]
fn clear_provisional_whitelist() {
    check_caller_is_governance_and_log("clear_provisional_whitelist");
    over(candid, |_: ()| clear_provisional_whitelist_());
}

#[candid_method(update, rename = "clear_provisional_whitelist")]
fn clear_provisional_whitelist_() {
    registry_mut().do_clear_provisional_whitelist();
    recertify_registry();
}

#[export_name = "canister_update set_firewall_config"]
fn set_firewall_config() {
    check_caller_is_governance_and_log("set_firewall_config");
    over(candid_one, |payload: SetFirewallConfigPayload| {
        set_firewal_config_(payload)
    });
}

#[candid_method(update, rename = "set_firewall_config")]
fn set_firewal_config_(payload: SetFirewallConfigPayload) {
    registry_mut().do_set_firewall_config(payload);
    recertify_registry();
}

#[export_name = "canister_update update_node_rewards_table"]
fn update_node_rewards_table() {
    check_caller_is_governance_and_log("update_node_rewards_table");
    over(candid_one, update_node_rewards_table_);
}

#[candid_method(update, rename = "update_node_rewards_table")]
fn update_node_rewards_table_(payload: UpdateNodeRewardsTableProposalPayload) {
    registry_mut().do_update_node_rewards_table(payload);
    recertify_registry();
}

#[export_name = "canister_update add_or_remove_data_centers"]
fn add_or_remove_data_centers() {
    check_caller_is_governance_and_log("add_or_remove_data_centers");
    over(candid_one, add_or_remove_data_centers_);
}

#[candid_method(update, rename = "add_or_remove_data_centers")]
fn add_or_remove_data_centers_(payload: AddOrRemoveDataCentersProposalPayload) {
    registry_mut().do_add_or_remove_data_centers(payload);
    recertify_registry();
}

#[export_name = "canister_update update_unassigned_nodes_config"]
fn update_unassigned_nodes_config() {
    check_caller_is_governance_and_log("update_unassigned_nodes_config");
    over(candid_one, |payload: UpdateUnassignedNodesConfigPayload| {
        update_unassigned_nodes_config_(payload)
    });
}

#[candid_method(update, rename = "update_unassigned_nodes_config")]
fn update_unassigned_nodes_config_(payload: UpdateUnassignedNodesConfigPayload) {
    registry_mut().do_update_unassigned_nodes_config(payload);
    recertify_registry();
}

#[export_name = "canister_update reroute_canister_range"]
fn reroute_canister_range() {
    check_caller_is_governance_and_log("reroute_canister_range");
    over_may_reject(candid_one, |payload: RerouteCanisterRangePayload| {
        reroute_canister_range_(payload)
    });
}

#[candid_method(update, rename = "reroute_canister_range")]
fn reroute_canister_range_(payload: RerouteCanisterRangePayload) -> Result<(), String> {
    if let Err(msg) = registry_mut().reroute_canister_range(payload) {
        println!("{} Reject: {}", LOG_PREFIX, msg);
        return Err(msg);
    }
    recertify_registry();
    Ok(())
}

#[export_name = "canister_query get_node_providers_monthly_xdr_rewards"]
fn get_node_providers_monthly_xdr_rewards() {
    check_caller_is_governance_and_log("get_node_providers_monthly_xdr_rewards");
    over(
        candid_one,
        |()| -> Result<NodeProvidersMonthlyXdrRewards, String> {
            get_node_providers_monthly_xdr_rewards_()
        },
    )
}

#[candid_method(query, rename = "get_node_providers_monthly_xdr_rewards")]
fn get_node_providers_monthly_xdr_rewards_() -> Result<NodeProvidersMonthlyXdrRewards, String> {
    registry().get_node_providers_monthly_xdr_rewards()
}

#[export_name = "canister_update add_node"]
fn add_node() {
    // This method can be called by anyone
    // Note that for now, once a node record has been added, it MUST not be
    // modified, as P2P and Transport rely on this data to stay the same
    println!(
        "{}call: add_node from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over_may_reject(candid_one, add_node_);
}

#[candid_method(update, rename = "add_node")]
fn add_node_(payload: AddNodePayload) -> Result<NodeId, String> {
    let result = registry_mut().do_add_node(payload);
    recertify_registry();
    result
}

#[export_name = "canister_update remove_node_directly"]
fn remove_node_directly() {
    // This method can be called by anyone
    println!(
        "{}call: remove_node_directly from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over(candid_one, |payload: RemoveNodeDirectlyPayload| {
        remove_node_directly_(payload)
    });
}

#[candid_method(update, rename = "remove_node_directly")]
fn remove_node_directly_(payload: RemoveNodeDirectlyPayload) {
    registry_mut().do_remove_node_directly(payload);
    recertify_registry();
}

fn recertify_registry() {
    registry_canister::certification::recertify_registry(registry());
}

fn certified_response(tree: HashTree<'_>) -> CertifiedResponse {
    CertifiedResponse {
        hash_tree: Some(hash_tree_to_proto(tree)),
        certificate: data_certificate().unwrap(),
    }
}

// This makes this Candid service self-describing, so that for example Candid
// UI, but also other tools, can seamlessly integrate with it.
// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
// works.
//
// We include the .did file as committed, as means it is included verbatim in
// the .wasm; using `candid::export_service` here would involve unecessary
// runtime computation

#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn expose_candid() {
    over(candid, |_: ()| include_str!("registry.did").to_string())
}

// When run on native this prints the candid service definition of this
// canister, from the methods annotated with `candid_method` above.
//
// Note that `cargo test` calls `main`, and `export_service` (which defines
// `__export_service` in the current scope) needs to be called exactly once. So
// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
// to avoid calling `export_service`, which we need to call in the test below.
#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[test]
fn check_did_file() {
    let did = String::from_utf8(std::fs::read("canister/registry.did").unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did != expected {
        panic!(
            "Generated candid definition does not match canister/registry.did. \
            Run `cargo run --bin registry-canister > canister/registry.did` in \
            rs/registry/canister to update canister/registry.did."
        )
    }
}
