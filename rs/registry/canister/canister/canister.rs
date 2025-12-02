use candid::{Decode, candid_method};
use dfn_candid::{candid, candid_one};
use dfn_core::{
    api::{arg_data, data_certificate, reply, trap_with},
    over, over_async, stable,
};
use ic_base_types::{NodeId, PrincipalId};
use ic_certified_map::{AsHashTree, HashTree};
use ic_nervous_system_string::clamp_debug_len;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, MIGRATION_CANISTER_ID, ROOT_CANISTER_ID};
use ic_protobuf::registry::{
    dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord},
    node_operator::v1::NodeOperatorRecord,
    node_rewards::v2::UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_canister_api::{
    AddNodePayload, Chunk, GetChunkRequest, GetNodeProvidersMonthlyXdrRewardsRequest,
    UpdateNodeDirectlyPayload, UpdateNodeIPv4ConfigDirectlyPayload,
};
use ic_registry_transport::{
    deserialize_atomic_mutate_request, deserialize_get_changes_since_request,
    deserialize_get_value_request,
    pb::v1::{
        CertifiedResponse, HighCapacityRegistryGetChangesSinceResponse,
        HighCapacityRegistryGetValueResponse, HighCapacityRegistryValue,
        RegistryAtomicMutateResponse, RegistryError, RegistryGetChangesSinceRequest,
        RegistryGetLatestVersionResponse, high_capacity_registry_get_value_response,
        registry_error::Code,
    },
    serialize_atomic_mutate_response, serialize_get_changes_since_response,
    serialize_get_value_response,
};
use prost::Message;
use registry_canister::{
    certification::{current_version_tree, hash_tree_to_proto},
    common::LOG_PREFIX,
    init::RegistryCanisterInitPayload,
    mutations::{
        complete_canister_migration::CompleteCanisterMigrationPayload,
        do_add_api_boundary_nodes::AddApiBoundaryNodesPayload,
        do_add_node_operator::AddNodeOperatorPayload,
        do_add_nodes_to_subnet::AddNodesToSubnetPayload,
        do_change_subnet_membership::ChangeSubnetMembershipPayload,
        do_create_subnet::{CreateSubnetPayload, NewSubnet},
        do_deploy_guestos_to_all_subnet_nodes::DeployGuestosToAllSubnetNodesPayload,
        do_deploy_guestos_to_all_unassigned_nodes::DeployGuestosToAllUnassignedNodesPayload,
        do_recover_subnet::RecoverSubnetPayload,
        do_remove_api_boundary_nodes::RemoveApiBoundaryNodesPayload,
        do_remove_node_operators::RemoveNodeOperatorsPayload,
        do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload,
        do_revise_elected_replica_versions::ReviseElectedGuestosVersionsPayload,
        do_set_firewall_config::SetFirewallConfigPayload,
        do_set_subnet_operational_level::SetSubnetOperationalLevelPayload,
        do_swap_node_in_subnet_directly::SwapNodeInSubnetDirectlyPayload,
        do_update_api_boundary_nodes_version::{
            DeployGuestosToSomeApiBoundaryNodes, UpdateApiBoundaryNodesVersionPayload,
        },
        do_update_elected_hostos_versions::{
            ReviseElectedHostosVersionsPayload, UpdateElectedHostosVersionsPayload,
        },
        do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
        do_update_node_operator_config_directly::UpdateNodeOperatorConfigDirectlyPayload,
        do_update_nodes_hostos_version::{
            DeployHostosToSomeNodes, UpdateNodesHostosVersionPayload,
        },
        do_update_ssh_readonly_access_for_all_unassigned_nodes::UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
        do_update_subnet::UpdateSubnetPayload,
        do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload,
        firewall::{
            AddFirewallRulesPayload, RemoveFirewallRulesPayload, UpdateFirewallRulesPayload,
        },
        node_management::{
            do_remove_node_directly::RemoveNodeDirectlyPayload,
            do_remove_nodes::RemoveNodesPayload,
            do_update_node_domain_directly::UpdateNodeDomainDirectlyPayload,
        },
        prepare_canister_migration::PrepareCanisterMigrationPayload,
        reroute_canister_ranges::RerouteCanisterRangesPayload,
    },
    pb::v1::{
        ApiBoundaryNodeIdRecord, GetApiBoundaryNodeIdsRequest, GetSubnetForCanisterRequest,
        NodeProvidersMonthlyXdrRewards, RegistryCanisterStableStorage, SubnetForCanister,
    },
    proto_on_wire::protobuf,
    registry::{EncodedVersion, MAX_REGISTRY_DELTAS_SIZE, Registry},
    registry_lifecycle,
};
use std::ptr::addr_of_mut;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dfn_core::stable::stable64_read;
use ic_nervous_system_common::memory_manager_upgrade_storage::{load_protobuf, store_protobuf};
use registry_canister::mutations::do_migrate_canisters::{
    MigrateCanistersPayload, MigrateCanistersResponse,
};
use registry_canister::storage::with_upgrades_memory;

static mut REGISTRY: Option<Registry> = None;

const MAX_VERSIONS_PER_QUERY: usize = 1000;

fn registry() -> &'static Registry {
    registry_mut()
}

fn registry_mut() -> &'static mut Registry {
    unsafe {
        if let Some(g) = &mut *addr_of_mut!(REGISTRY) {
            g
        } else {
            REGISTRY = Some(Registry::new());
            registry_mut()
        }
    }
}

fn check_caller_is_governance_and_log(method_name: &str) {
    let caller = dfn_core::api::caller();
    println!("{LOG_PREFIX}call: {method_name} from: {caller}");
    assert_eq!(
        caller,
        GOVERNANCE_CANISTER_ID.into(),
        "{LOG_PREFIX}Principal: {caller} is not authorized to call this method: {method_name}"
    );
}

fn check_caller_is_canister_migration_orchestrator_and_log(method_name: &str) {
    let caller = dfn_core::api::caller();
    println!("{LOG_PREFIX}call: {method_name} from: {caller}");
    assert_eq!(
        caller,
        MIGRATION_CANISTER_ID.into(),
        "{LOG_PREFIX}Principal: {caller} is not authorized to call this method: {method_name}"
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
/// initialization traps.
///
/// In other words, there is no difference in the result between using an init
/// payload or starting with an empty content and having an authorized user
/// making those mutations through the `atomic_mutate` method. However, there is
/// a difference with respect to intermediate state: using `canister_init`, the
/// intermediate state, such as the one with empty content, is never
/// visible through the public API.
#[unsafe(export_name = "canister_init")]
fn canister_init() {
    dfn_core::printer::hook();
    recertify_registry();

    let init_payload = Decode!(&arg_data(), RegistryCanisterInitPayload).expect(
        "The init argument for the registry canister must be a Candid-encoded \
        RegistryCanisterInitPayload.",
    );
    println!(
        "{}canister_init: Initializing with: {}",
        LOG_PREFIX,
        clamp_debug_len(&init_payload, /* max_len = */ 2000)
    );
    let registry = registry_mut();

    init_payload
        .mutations
        .into_iter()
        .for_each(|mutation_request| {
            registry.maybe_apply_mutation_internal(mutation_request.mutations)
        });
    recertify_registry();

    #[cfg(feature = "test")]
    {
        use registry_canister::flags::temporary_overrides::{
            test_set_swapping_enabled_subnets, test_set_swapping_status,
            test_set_swapping_whitelisted_callers,
        };

        println!("{LOG_PREFIX}canister_init: Overriding swapping flags");
        println!(
            "{LOG_PREFIX}canister_intt: Swapping enabled: {:?}",
            init_payload.is_swapping_feature_enabled
        );
        test_set_swapping_status(init_payload.is_swapping_feature_enabled.unwrap_or_default());
        println!(
            "{LOG_PREFIX}canister_init: Swapping whietlisted callers: {:?}",
            init_payload.swapping_whitelisted_callers
        );
        test_set_swapping_whitelisted_callers(
            init_payload
                .swapping_whitelisted_callers
                .unwrap_or_default(),
        );
        println!(
            "{LOG_PREFIX}canister_init: Swapping enabled on subnets: {:?}",
            init_payload.swapping_enabled_subnets
        );
        test_set_swapping_enabled_subnets(
            init_payload.swapping_enabled_subnets.unwrap_or_default(),
        );
    }
}

#[unsafe(export_name = "canister_pre_upgrade")]
fn canister_pre_upgrade() {
    println!("{LOG_PREFIX}canister_pre_upgrade");
    let registry = registry();
    let ss = RegistryCanisterStableStorage {
        registry: Some(registry.serializable_form()),
        pre_upgrade_version: Some(registry.latest_version()),
    };
    with_upgrades_memory(|memory| store_protobuf(memory, &ss))
        .expect("Failed to encode protobuf pre-upgrade");
}

#[unsafe(export_name = "canister_post_upgrade")]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{LOG_PREFIX}canister_post_upgrade");
    // call stable_storage APIs and get registry instance in canister context
    // Look for MemoryManager magic bytes
    let mut magic_bytes = [0u8; 3];
    stable64_read(&mut magic_bytes, 0, 3);
    let mut mgr_version_byte = [0u8; 1];
    stable64_read(&mut mgr_version_byte, 3, 1);

    let registry_storage: RegistryCanisterStableStorage =
        if &magic_bytes == b"MGR" && mgr_version_byte[0] == 1 {
            with_upgrades_memory(load_protobuf).expect("Failed to decode protobuf post-upgrade")
        } else {
            let stable_storage = stable::get();
            RegistryCanisterStableStorage::decode(stable_storage.as_slice())
                .expect("Error decoding from stable.")
        };
    // delegate real work to more testable function

    let registry = registry_mut();
    registry_lifecycle::canister_post_upgrade(registry, registry_storage);
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

#[unsafe(export_name = "canister_query get_changes_since")]
fn get_changes_since() {
    fn main() -> Result<HighCapacityRegistryGetChangesSinceResponse, (Code, String)> {
        // Parse request.
        let request = deserialize_get_changes_since_request(arg_data())
            .map_err(|err| (Code::MalformedMessage, err.to_string()))?;
        let version = request;

        // All requirements met. Proceed with "real work".

        let registry = registry();

        let max_versions = registry
            .count_fitting_deltas(version, MAX_REGISTRY_DELTAS_SIZE)
            .min(MAX_VERSIONS_PER_QUERY);

        Ok(HighCapacityRegistryGetChangesSinceResponse {
            error: None,
            version: registry.latest_version(),
            deltas: registry.get_changes_since(version, Some(max_versions)),
        })
    }

    let response = main().unwrap_or_else(
        // Convert Err to HighCapacityRegistryGetChangesSinceResponse
        |(code, reason)| {
            let code = code as i32;

            HighCapacityRegistryGetChangesSinceResponse {
                error: Some(RegistryError {
                    code,
                    reason,
                    key: vec![],
                }),
                ..Default::default()
            }
        },
    );

    let response =
        serialize_get_changes_since_response(response).expect("Error serializing response");

    reply(&response);
}

#[unsafe(export_name = "canister_query get_certified_changes_since")]
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

#[unsafe(export_name = "canister_query get_value")]
fn get_value() {
    let response_pb = match deserialize_get_value_request(arg_data()) {
        Ok((key, version_opt)) => {
            let registry = registry();
            let version = version_opt.unwrap_or_else(|| registry.latest_version());
            let result: Option<HighCapacityRegistryValue> =
                registry.get_high_capacity(&key, version).cloned();

            match result {
                Some(result) => {
                    let HighCapacityRegistryValue {
                        version,
                        content,
                        timestamp_nanoseconds,
                    } = result;

                    let content = content.map(|content| {
                        high_capacity_registry_get_value_response::Content::try_from(content)
                            // Since get_high_capacity is supposed to NOT return a
                            // value whose content is deletion_marker, and since
                            // that is the only case where try_from fails, we deduce
                            // that this panic cannot occur.
                            .unwrap_or_else(|err| {
                                panic!("Unable to convert value to response type, because {err}",)
                            })
                    });

                    HighCapacityRegistryGetValueResponse {
                        version,
                        content,
                        timestamp_nanoseconds,

                        error: None,
                    }
                }

                None => HighCapacityRegistryGetValueResponse {
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
                    content: None,
                    timestamp_nanoseconds: 0,
                },
            }
        }
        Err(error) => HighCapacityRegistryGetValueResponse {
            error: Some(RegistryError {
                code: Code::MalformedMessage as i32,
                key: Vec::<u8>::default(),
                reason: error.to_string(),
            }),
            version: 0,
            content: None,
            timestamp_nanoseconds: 0,
        },
    };
    let bytes = serialize_get_value_response(response_pb).expect("Error serializing response");
    reply(&bytes);
}

#[unsafe(export_name = "canister_query get_latest_version")]
fn get_latest_version() {
    over(protobuf, |_: Vec<u8>| RegistryGetLatestVersionResponse {
        version: registry().latest_version(),
    });
}

#[unsafe(export_name = "canister_query get_certified_latest_version")]
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

#[unsafe(export_name = "canister_update atomic_mutate")]
fn atomic_mutate() {
    let caller = dfn_core::api::caller();
    //
    // - The governance canister is always allowed to mutate the registry
    // - The root canister is also allowed, so that IDs of new NNS canisters can be
    //   recorded.
    assert!(
        caller == GOVERNANCE_CANISTER_ID.get() || caller == ROOT_CANISTER_ID.get(),
        "{LOG_PREFIX}Principal {caller} is not authorized to call 'atomic_mutate'."
    );
    println!("{LOG_PREFIX}call 'atomic_mutate' from {caller}");

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
                "{LOG_PREFIX}Received a mutate call, but the request could not de deserialized due to: {error}"
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

#[unsafe(export_name = "canister_query get_chunk")]
fn get_chunk() {
    over(candid_one, get_chunk_);
}

#[candid_method(query, rename = "get_chunk")]
fn get_chunk_(request: GetChunkRequest) -> Result<Chunk, String> {
    registry().get_chunk(request)
}

/// Modifies records with keys of the form "daniel_wong_{}".
///
/// Returns new version number.
///
/// Caller must be GOVERNANCE_CANISTER_ID.
///
/// Used in integration test(s) for large records.
///
/// This is not in release builds.
///
/// There are a couple of pieces of functionality here that cannot otherwise
/// easily be accomplished:
///
///     1. Produce large record(s).
///     2. Chunking is ALWAYS enabled.
#[cfg(feature = "test")]
#[unsafe(export_name = "canister_update mutate_test_high_capacity_records")]
fn mutate_test_high_capacity_records() {
    // Since these should only be used in tests, we do not put these at the top of the file.
    use ic_registry_canister_api::mutate_test_high_capacity_records::Request;

    over(candid_one, |request: Request| -> /* version */ u64 {
        check_caller_is_governance_and_log("mutate_test_high_capacity_records");
        let registry = registry_mut();
        registry.maybe_apply_mutation_internal(vec![request.into_mutation()]);
        recertify_registry();
        registry.latest_version()
    });
}

#[cfg(feature = "test")]
#[unsafe(export_name = "canister_update apply_mutations_for_test")]
fn apply_mutations_for_test() {
    over(candid_one, |mutations| {
        println!("Came into the apply mutations for test");
        let registry = registry_mut();
        registry.apply_mutations_for_test(mutations);
        recertify_registry();
    });
}

#[unsafe(export_name = "canister_update revise_elected_guestos_versions")]
fn revise_elected_guestos_versions() {
    check_caller_is_governance_and_log("revise_elected_guestos_versions");
    over(candid_one, revise_elected_guestos_versions_);
}

#[candid_method(update, rename = "revise_elected_guestos_versions")]
fn revise_elected_guestos_versions_(payload: ReviseElectedGuestosVersionsPayload) {
    registry_mut().do_revise_elected_guestos_versions(payload);
    recertify_registry();
}

// TODO[NNS1-3000]: Remove this endpoint once mainnet NNS Governance starts calling the new
// TODO[NNS1-3000]: `revise_elected_guestos_versions` endpoint.
#[unsafe(export_name = "canister_update revise_elected_replica_versions")]
fn revise_elected_replica_versions() {
    check_caller_is_governance_and_log("revise_elected_replica_versions");
    over(candid_one, revise_elected_replica_versions_);
}

#[candid_method(update, rename = "revise_elected_replica_versions")]
fn revise_elected_replica_versions_(payload: ReviseElectedGuestosVersionsPayload) {
    registry_mut().do_revise_elected_guestos_versions(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update deploy_guestos_to_all_subnet_nodes")]
fn deploy_guestos_to_all_subnet_nodes() {
    check_caller_is_governance_and_log("deploy_guestos_to_all_subnet_nodes");
    over(candid_one, deploy_guestos_to_all_subnet_nodes_);
}

#[candid_method(update, rename = "deploy_guestos_to_all_subnet_nodes")]
fn deploy_guestos_to_all_subnet_nodes_(payload: DeployGuestosToAllSubnetNodesPayload) {
    registry_mut().do_deploy_guestos_to_all_subnet_nodes(payload);
    recertify_registry();
}

// TODO[NNS1-3000]: Remove this endpoint once mainnet NNS Governance starts calling the new
// TODO[NNS1-3000]: `revise_elected_hostos_versions` endpoint.
#[unsafe(export_name = "canister_update update_elected_hostos_versions")]
fn update_elected_hostos_versions() {
    check_caller_is_governance_and_log("update_elected_hostos_versions");
    over(candid_one, update_elected_hostos_versions_);
}

// TODO[NNS1-3000]: Remove this endpoint once mainnet NNS Governance starts calling the new
// TODO[NNS1-3000]: `revise_elected_hostos_versions` endpoint.
#[candid_method(update, rename = "update_elected_hostos_versions")]
fn update_elected_hostos_versions_(payload: UpdateElectedHostosVersionsPayload) {
    registry_mut().do_update_elected_hostos_versions(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update revise_elected_hostos_versions")]
fn revise_elected_hostos_versions() {
    check_caller_is_governance_and_log("revise_elected_hostos_versions");
    over(candid_one, revise_elected_hostos_versions_);
}

#[candid_method(update, rename = "revise_elected_hostos_versions")]
fn revise_elected_hostos_versions_(payload: ReviseElectedHostosVersionsPayload) {
    registry_mut().do_revise_elected_hostos_versions(payload);
    recertify_registry();
}

// TODO[NNS1-3000]: Remove this endpoint once mainnet NNS Governance starts calling the new
// TODO[NNS1-3000]: `deploy_hostos_to_some_nodes` endpoint.
#[unsafe(export_name = "canister_update update_nodes_hostos_version")]
fn update_nodes_hostos_version() {
    check_caller_is_governance_and_log("update_nodes_hostos_version");
    over(candid_one, |payload: UpdateNodesHostosVersionPayload| {
        update_nodes_hostos_version_(payload)
    });
}

#[candid_method(update, rename = "update_nodes_hostos_version")]
fn update_nodes_hostos_version_(payload: UpdateNodesHostosVersionPayload) {
    registry_mut().do_update_nodes_hostos_version(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update deploy_hostos_to_some_nodes")]
fn deploy_hostos_to_some_nodes() {
    check_caller_is_governance_and_log("deploy_hostos_to_some_nodes");
    over(candid_one, deploy_hostos_to_some_nodes_);
}

#[candid_method(update, rename = "deploy_hostos_to_some_nodes")]
fn deploy_hostos_to_some_nodes_(payload: DeployHostosToSomeNodes) {
    registry_mut().do_deploy_hostos_to_some_nodes(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update add_node_operator")]
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

#[unsafe(export_name = "canister_update create_subnet")]
fn create_subnet() {
    check_caller_is_governance_and_log("create_subnet");
    over_async(candid_one, |payload: CreateSubnetPayload| async move {
        create_subnet_(payload).await
    });
}

/// Currently, this does not return Err, but for the sake of consistency the
/// return type is Result. Currently, if the operation cannot be completed, this
/// panics instead of returning Err (ensuring any partial changes do not get
/// committed).
#[candid_method(update, rename = "create_subnet")]
async fn create_subnet_(payload: CreateSubnetPayload) -> Result<NewSubnet, String> {
    let new_subnet = registry_mut().do_create_subnet(payload).await;
    recertify_registry();
    Ok(new_subnet)
}

#[unsafe(export_name = "canister_update add_nodes_to_subnet")]
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

#[unsafe(export_name = "canister_update recover_subnet")]
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

#[unsafe(export_name = "canister_update remove_nodes_from_subnet")]
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

#[unsafe(export_name = "canister_update change_subnet_membership")]
fn change_subnet_membership() {
    check_caller_is_governance_and_log("change_subnet_membership");
    over(candid_one, |payload: ChangeSubnetMembershipPayload| {
        change_subnet_membership_(payload)
    });
}

#[candid_method(update, rename = "change_subnet_membership")]
fn change_subnet_membership_(payload: ChangeSubnetMembershipPayload) {
    registry_mut().do_change_subnet_membership(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update add_api_boundary_nodes")]
fn add_api_boundary_nodes() {
    check_caller_is_governance_and_log("add_api_boundary_nodes");
    over(candid_one, |payload: AddApiBoundaryNodesPayload| {
        add_api_boundary_nodes_(payload)
    });
}

#[candid_method(update, rename = "add_api_boundary_nodes")]
fn add_api_boundary_nodes_(payload: AddApiBoundaryNodesPayload) {
    registry_mut().do_add_api_boundary_nodes(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update remove_api_boundary_nodes")]
fn remove_api_boundary_nodes() {
    check_caller_is_governance_and_log("remove_api_boundary_nodes");
    over(candid_one, |payload: RemoveApiBoundaryNodesPayload| {
        remove_api_boundary_nodes_(payload)
    });
}

#[candid_method(update, rename = "remove_api_boundary_nodes")]
fn remove_api_boundary_nodes_(payload: RemoveApiBoundaryNodesPayload) {
    registry_mut().do_remove_api_boundary_nodes(payload);
    recertify_registry();
}

// TODO[NNS1-3000]: Remove this endpoint once mainnet NNS Governance starts calling the new
// TODO[NNS1-3000]: `deploy_guestos_to_some_api_boundary_nodes` endpoint.
#[unsafe(export_name = "canister_update update_api_boundary_nodes_version")]
fn update_api_boundary_nodes_version() {
    check_caller_is_governance_and_log("update_api_boundary_nodes_version");
    over(candid_one, update_api_boundary_nodes_version_);
}

#[candid_method(update, rename = "update_api_boundary_nodes_version")]
fn update_api_boundary_nodes_version_(payload: UpdateApiBoundaryNodesVersionPayload) {
    registry_mut().do_update_api_boundary_nodes_version(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update deploy_guestos_to_some_api_boundary_nodes")]
fn deploy_guestos_to_some_api_boundary_nodes() {
    check_caller_is_governance_and_log("deploy_guestos_to_some_api_boundary_nodes");
    over(candid_one, deploy_guestos_to_some_api_boundary_nodes_);
}

#[candid_method(update, rename = "deploy_guestos_to_some_api_boundary_nodes")]
fn deploy_guestos_to_some_api_boundary_nodes_(payload: DeployGuestosToSomeApiBoundaryNodes) {
    registry_mut().do_deploy_guestos_to_some_api_boundary_nodes(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update remove_nodes")]
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

#[unsafe(export_name = "canister_update update_node_operator_config")]
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

#[unsafe(export_name = "canister_update update_node_operator_config_directly")]
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

#[unsafe(export_name = "canister_update swap_node_in_subnet_directly")]
fn swap_node_in_subnet_directly() {
    over(candid_one, |payload: SwapNodeInSubnetDirectlyPayload| {
        swap_node_in_subnet_directly_(payload)
    });
}

#[candid_method(update, rename = "swap_node_in_subnet_directly")]
fn swap_node_in_subnet_directly_(payload: SwapNodeInSubnetDirectlyPayload) {
    registry_mut().do_swap_node_in_subnet_directly(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update remove_node_operators")]
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

#[unsafe(export_name = "canister_update update_subnet")]
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

#[unsafe(export_name = "canister_update clear_provisional_whitelist")]
fn clear_provisional_whitelist() {
    check_caller_is_governance_and_log("clear_provisional_whitelist");
    over(candid, |_: ()| clear_provisional_whitelist_());
}

#[candid_method(update, rename = "clear_provisional_whitelist")]
fn clear_provisional_whitelist_() {
    registry_mut().do_clear_provisional_whitelist();
    recertify_registry();
}

#[unsafe(export_name = "canister_update set_firewall_config")]
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

#[unsafe(export_name = "canister_update add_firewall_rules")]
fn add_firewall_rules() {
    check_caller_is_governance_and_log("add_firewall_rules");
    over(candid_one, |payload: AddFirewallRulesPayload| {
        add_firewall_rules_(payload)
    });
}

#[candid_method(update, rename = "add_firewall_rules")]
fn add_firewall_rules_(payload: AddFirewallRulesPayload) {
    registry_mut().do_add_firewall_rules(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update remove_firewall_rules")]
fn remove_firewall_rules() {
    check_caller_is_governance_and_log("remove_firewall_rules");
    over(candid_one, |payload: RemoveFirewallRulesPayload| {
        remove_firewall_rules_(payload)
    });
}

#[candid_method(update, rename = "remove_firewall_rules")]
fn remove_firewall_rules_(payload: RemoveFirewallRulesPayload) {
    registry_mut().do_remove_firewall_rules(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update update_firewall_rules")]
fn update_firewall_rules() {
    check_caller_is_governance_and_log("update_firewall_rules");
    over(candid_one, |payload: UpdateFirewallRulesPayload| {
        update_firewall_rules_(payload)
    });
}

#[candid_method(update, rename = "update_firewall_rules")]
fn update_firewall_rules_(payload: UpdateFirewallRulesPayload) {
    registry_mut().do_update_firewall_rules(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update update_node_rewards_table")]
fn update_node_rewards_table() {
    check_caller_is_governance_and_log("update_node_rewards_table");
    over(candid_one, update_node_rewards_table_);
}

#[candid_method(update, rename = "update_node_rewards_table")]
fn update_node_rewards_table_(payload: UpdateNodeRewardsTableProposalPayload) {
    registry_mut().do_update_node_rewards_table(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update add_or_remove_data_centers")]
fn add_or_remove_data_centers() {
    check_caller_is_governance_and_log("add_or_remove_data_centers");
    over(candid_one, add_or_remove_data_centers_);
}

#[candid_method(update, rename = "add_or_remove_data_centers")]
fn add_or_remove_data_centers_(payload: AddOrRemoveDataCentersProposalPayload) {
    registry_mut().do_add_or_remove_data_centers(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update update_unassigned_nodes_config")]
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

#[unsafe(export_name = "canister_update deploy_guestos_to_all_unassigned_nodes")]
fn deploy_guestos_to_all_unassigned_nodes() {
    check_caller_is_governance_and_log("deploy_guestos_to_all_unassigned_nodes");
    over(
        candid_one,
        |payload: DeployGuestosToAllUnassignedNodesPayload| {
            deploy_guestos_to_all_unassigned_nodes_(payload)
        },
    );
}

#[candid_method(update, rename = "deploy_guestos_to_all_unassigned_nodes")]
fn deploy_guestos_to_all_unassigned_nodes_(payload: DeployGuestosToAllUnassignedNodesPayload) {
    registry_mut().do_deploy_guestos_to_all_unassigned_nodes(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update update_ssh_readonly_access_for_all_unassigned_nodes")]
fn update_ssh_readonly_access_for_all_unassigned_nodes() {
    check_caller_is_governance_and_log("update_ssh_readonly_access_for_all_unassigned_nodes");
    over(
        candid_one,
        |payload: UpdateSshReadOnlyAccessForAllUnassignedNodesPayload| {
            update_ssh_readonly_access_for_all_unassigned_nodes_(payload)
        },
    );
}

#[candid_method(update, rename = "update_ssh_readonly_access_for_all_unassigned_nodes")]
fn update_ssh_readonly_access_for_all_unassigned_nodes_(
    payload: UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
) {
    registry_mut().do_update_ssh_readonly_access_for_all_unassigned_nodes(payload);
    recertify_registry();
}

#[unsafe(export_name = "canister_update prepare_canister_migration")]
fn prepare_canister_migration() {
    check_caller_is_governance_and_log("prepare_canister_migration");
    over(candid_one, prepare_canister_migration_);
}

#[candid_method(update, rename = "prepare_canister_migration")]
fn prepare_canister_migration_(payload: PrepareCanisterMigrationPayload) {
    registry_mut()
        .prepare_canister_migration(payload)
        .unwrap_or_else(|error_message| {
            trap_with(&format!(
                "{LOG_PREFIX} Prepare canister migration failed: {error_message}"
            ))
        });
    recertify_registry();
}

#[unsafe(export_name = "canister_update reroute_canister_ranges")]
fn reroute_canister_ranges() {
    check_caller_is_governance_and_log("reroute_canister_ranges");
    over(candid_one, reroute_canister_ranges_);
}

#[candid_method(update, rename = "reroute_canister_ranges")]
fn reroute_canister_ranges_(payload: RerouteCanisterRangesPayload) {
    registry_mut()
        .reroute_canister_ranges(payload)
        .unwrap_or_else(|error_message| {
            trap_with(&format!(
                "{LOG_PREFIX} Reroute canister ranges failed: {error_message}"
            ))
        });
    recertify_registry();
}

#[unsafe(export_name = "canister_update complete_canister_migration")]
fn complete_canister_migration() {
    check_caller_is_governance_and_log("complete_canister_migration");
    over(candid_one, complete_canister_migration_);
}

#[candid_method(update, rename = "complete_canister_migration")]
fn complete_canister_migration_(payload: CompleteCanisterMigrationPayload) {
    registry_mut()
        .complete_canister_migration(payload)
        .unwrap_or_else(|error_message| {
            trap_with(&format!(
                "{LOG_PREFIX} Complete canister migration failed: {error_message}"
            ))
        });
    recertify_registry();
}

#[unsafe(export_name = "canister_update migrate_canisters")]
fn migrate_canisters() {
    check_caller_is_canister_migration_orchestrator_and_log("migrate_canisters");
    over(candid_one, migrate_canisters_);
}

#[candid_method(update, rename = "migrate_canisters")]
fn migrate_canisters_(payload: MigrateCanistersPayload) -> MigrateCanistersResponse {
    let res = registry_mut().do_migrate_canisters(payload);
    recertify_registry();
    res
}

#[unsafe(export_name = "canister_query get_node_providers_monthly_xdr_rewards")]
fn get_node_providers_monthly_xdr_rewards() {
    check_caller_is_governance_and_log("get_node_providers_monthly_xdr_rewards");
    over(
        candid_one,
        |request: Option<GetNodeProvidersMonthlyXdrRewardsRequest>| -> Result<NodeProvidersMonthlyXdrRewards, String> {
            get_node_providers_monthly_xdr_rewards_(request)
        },
    )
}

#[candid_method(query, rename = "get_node_providers_monthly_xdr_rewards")]
fn get_node_providers_monthly_xdr_rewards_(
    arg: Option<GetNodeProvidersMonthlyXdrRewardsRequest>,
) -> Result<NodeProvidersMonthlyXdrRewards, String> {
    registry().get_node_providers_monthly_xdr_rewards(arg.unwrap_or_default())
}

#[unsafe(export_name = "canister_query get_api_boundary_node_ids")]
fn get_api_boundary_node_ids() {
    over(
        candid_one,
        |arg: GetApiBoundaryNodeIdsRequest| -> Result<Vec<ApiBoundaryNodeIdRecord>, String> {
            get_api_boundary_node_ids_(arg)
        },
    )
}

#[candid_method(query, rename = "get_api_boundary_node_ids")]
fn get_api_boundary_node_ids_(
    _arg: GetApiBoundaryNodeIdsRequest,
) -> Result<Vec<ApiBoundaryNodeIdRecord>, String> {
    let ids = registry().get_api_boundary_node_ids()?;
    let ids = ids
        .iter()
        .map(|k| ApiBoundaryNodeIdRecord { id: Some(k.get()) })
        .collect();
    Ok(ids)
}

#[unsafe(export_name = "canister_query get_node_operators_and_dcs_of_node_provider")]
fn get_node_operators_and_dcs_of_node_provider() {
    over(
        candid_one,
        |node_provider: PrincipalId| -> Result<Vec<(DataCenterRecord, NodeOperatorRecord)>, String> {
            get_node_operators_and_dcs_of_node_provider_(node_provider)
        },
    )
}

#[candid_method(query, rename = "get_node_operators_and_dcs_of_node_provider")]
fn get_node_operators_and_dcs_of_node_provider_(
    node_provider: PrincipalId,
) -> Result<Vec<(DataCenterRecord, NodeOperatorRecord)>, String> {
    registry().get_node_operators_and_dcs_of_node_provider(node_provider)
}

#[unsafe(export_name = "canister_query get_subnet_for_canister")]
fn get_subnet_for_canister() {
    over(candid_one, get_subnet_for_canister_)
}

#[candid_method(query, rename = "get_subnet_for_canister")]
fn get_subnet_for_canister_(arg: GetSubnetForCanisterRequest) -> Result<SubnetForCanister, String> {
    let Some(principal) = arg.principal else {
        return Err("No principal supplied".to_string());
    };

    registry()
        .get_subnet_for_canister(&principal)
        .map_err(|e| e.to_string())
}

#[unsafe(export_name = "canister_update add_node")]
fn add_node() {
    // This method can be called by anyone
    // Note that for now, once a node record has been added, it MUST not be
    // modified, as P2P and Transport rely on this data to stay the same
    println!(
        "{}call: add_node from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over(candid_one, add_node_);
}

#[candid_method(update, rename = "add_node")]
fn add_node_(payload: AddNodePayload) -> NodeId {
    let node_id = registry_mut()
        .do_add_node(payload)
        .unwrap_or_else(|error_message| {
            let msg = format!("{LOG_PREFIX} Add node failed: {error_message}");
            // TODO(NNS1-4290): Delete once we figure why it seems like clients
            // are throwing this away.
            println!("{}", msg);
            trap_with(&msg);
        });

    recertify_registry();
    node_id
}

#[unsafe(export_name = "canister_update update_node_directly")]
fn update_node_directly() {
    // This method can be called by anyone
    println!(
        "{}call: update_node_directly from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over(candid_one, update_node_directly_);
}

#[candid_method(update, rename = "update_node_directly")]
fn update_node_directly_(payload: UpdateNodeDirectlyPayload) {
    registry_mut()
        .do_update_node_directly(payload)
        .unwrap_or_else(|error_message| {
            trap_with(&format!(
                "{LOG_PREFIX} Update node directly failed: {error_message}"
            ))
        });
    recertify_registry();
}

#[candid_method(update, rename = "update_node_domain_directly")]
fn update_node_domain_directly_(payload: UpdateNodeDomainDirectlyPayload) -> Result<(), String> {
    registry_mut().do_update_node_domain_directly(payload);
    recertify_registry();
    Ok(())
}

#[unsafe(export_name = "canister_update update_node_domain_directly")]
fn update_node_domain_directly() {
    // This method can be called by anyone
    println!(
        "{}call: update_node_domain_directly from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over(candid_one, |payload: UpdateNodeDomainDirectlyPayload| {
        update_node_domain_directly_(payload)
    });
}

#[unsafe(export_name = "canister_update update_node_ipv4_config_directly")]
fn update_node_ipv4_config_directly() {
    // This method can be called by anyone
    println!(
        "{}call: update_node_ipv4_config_directly from: {}",
        LOG_PREFIX,
        dfn_core::api::caller()
    );
    over(candid_one, update_node_ipv4_config_directly_);
}

#[candid_method(update, rename = "update_node_ipv4_config_directly")]
fn update_node_ipv4_config_directly_(
    payload: UpdateNodeIPv4ConfigDirectlyPayload,
) -> Result<(), String> {
    registry_mut().do_update_node_ipv4_config_directly(payload);
    recertify_registry();
    Ok(())
}

#[unsafe(export_name = "canister_update remove_node_directly")]
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

#[unsafe(export_name = "canister_update set_subnet_operational_level")]
fn set_subnet_operational_level() {
    check_caller_is_governance_and_log("set_subnet_operational_level");
    over(candid_one, set_subnet_operational_level_);
}

#[candid_method(update, rename = "set_subnet_operational_level")]
fn set_subnet_operational_level_(payload: SetSubnetOperationalLevelPayload) {
    registry_mut().do_set_subnet_operational_level(payload);
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

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "registry_stable_memory_size_bytes",
        ic_nervous_system_common::stable_memory_size_bytes() as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "registry_total_memory_size_bytes",
        ic_nervous_system_common::total_memory_size_bytes() as f64,
        "Size of the total memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "registry_latest_version",
        registry().latest_version() as f64,
        "The current latest version of the registry.",
    )?;

    Ok(())
}

#[unsafe(export_name = "canister_query http_request")]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
