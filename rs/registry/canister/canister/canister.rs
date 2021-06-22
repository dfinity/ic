use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use prost::Message;

use candid::Decode;
use dfn_candid::{candid, candid_one};
use dfn_core::{
    api::{arg_data, data_certificate, reply, set_certified_data},
    over, over_async, over_may_reject, stable,
};
use ic_crypto_tree_hash::{LabeledTree, WitnessGenerator, WitnessGeneratorImpl};
use ic_nns_common::{
    access_control::{
        check_caller_authz_and_log, check_caller_is_root, current_canister_authz,
        init_canister_authz, update_methods_authz,
    },
    pb::v1::CanisterAuthzInfo,
    types::MethodAuthzChange,
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
use registry_canister::{
    common::LOG_PREFIX,
    init::RegistryCanisterInitPayload,
    mutations::{
        do_add_node::AddNodePayload, do_add_node_operator::AddNodeOperatorPayload,
        do_add_nodes_to_subnet::AddNodesToSubnetPayload,
        do_bless_replica_version::BlessReplicaVersionPayload,
        do_create_subnet::CreateSubnetPayload, do_recover_subnet::RecoverSubnetPayload,
        do_remove_node_directly::RemoveNodeDirectlyPayload, do_remove_nodes::RemoveNodesPayload,
        do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload,
        do_update_icp_xdr_conversion_rate::UpdateIcpXdrConversionRatePayload,
        do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
        do_update_subnet::UpdateSubnetPayload,
        do_update_subnet_replica::UpdateSubnetReplicaVersionPayload,
    },
    pb::v1::RegistryCanisterStableStorage,
    proto_on_wire::protobuf,
    registry::Registry,
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use registry_canister::mutations::do_set_firewall_config::SetFirewallConfigPayload;

fn main() {}

static mut REGISTRY: Option<Registry> = None;
static mut WITNESS_GENERATOR: Option<WitnessGeneratorImpl> = None;

const MAX_VERSIONS_PER_QUERY: usize = 1000;

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

fn witness_generator() -> &'static WitnessGeneratorImpl {
    witness_generator_mut()
}

fn witness_generator_mut() -> &'static mut WitnessGeneratorImpl {
    unsafe {
        if let Some(g) = &mut WITNESS_GENERATOR {
            g
        } else {
            WITNESS_GENERATOR = Some(registry_canister::certification::rebuild_tree(
                registry_mut(),
            ));
            witness_generator_mut()
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
    init_canister_authz(init_payload.authz_info);

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
    let registry = registry_mut();
    let mut serialized = Vec::new();
    let ss = RegistryCanisterStableStorage {
        authz: Some(current_canister_authz()),
        registry: Some(registry.serializable_form()),
    };
    ss.encode(&mut serialized)
        .expect("Error serializing to stable.");
    stable::set(&serialized);
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_post_upgrade", LOG_PREFIX);
    // Purposefully fail the upgrade if we can't find authz information.
    // Best to have a broken canister, which we can reinstall, than a
    // canister without authz information.
    let ss = RegistryCanisterStableStorage::decode(stable::get().as_slice())
        .expect("Error decoding from stable.");
    init_canister_authz(ss.authz.expect("Canister must have authz info in stable"));
    let registry = registry_mut();
    registry.from_serializable_form(ss.registry.expect("Error decoding from stable"));

    registry.check_global_invariants(&[]);
    recertify_registry();
}

#[export_name = "canister_update update_authz"]
fn update_authz() {
    check_caller_is_root();
    over(
        candid_one,
        |methods_authz_change: Vec<MethodAuthzChange>| {
            update_methods_authz(methods_authz_change, LOG_PREFIX);
        },
    );
}

#[export_name = "canister_query current_authz"]
fn current_authz() {
    over(candid, |_: ()| -> CanisterAuthzInfo {
        current_canister_authz()
    });
}

#[export_name = "canister_query get_changes_since"]
fn get_changes_since() {
    let response_pb = match deserialize_get_changes_since_request(arg_data()) {
        Ok(version) => {
            let registry = registry();
            RegistryGetChangesSinceResponse {
                error: None,
                version: registry.latest_version(),
                deltas: registry.get_changes_since(version),
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
fn get_changes_since_certified() {
    over(protobuf, |req: RegistryGetChangesSinceRequest| {
        use registry_canister::certification::{build_deltas_tree, num_leaf, singleton};

        let since_version = req.version;
        let registry = registry();
        let latest_version = registry.latest_version();
        let deltas = registry
            .changelog()
            .iter()
            .skip_while(|(v, _)| *v <= since_version)
            .take(MAX_VERSIONS_PER_QUERY);

        let data_tree = if latest_version <= since_version {
            singleton("current_version", num_leaf(latest_version))
        } else {
            build_deltas_tree(latest_version, deltas)
        };

        certified_response(&data_tree)
    })
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
                code: Code::KeyNotPresent as i32,
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
fn get_latest_version_certified() {
    use registry_canister::certification::{num_leaf, singleton};

    over(protobuf, |_: Vec<u8>| {
        let latest_version = registry().latest_version();
        let data_tree = singleton("current_version", num_leaf(latest_version));
        certified_response(&data_tree)
    });
}

#[export_name = "canister_update atomic_mutate"]
fn atomic_mutate() {
    // This method requires authz as it should only be called in non-prod
    // environments
    check_caller_authz_and_log("atomic_mutate", LOG_PREFIX);

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
            let mut error_pb = RegistryError::default();
            error_pb.code = Code::MalformedMessage as i32;
            error_pb.reason = error.to_string();
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
        registry_mut().do_bless_replica_version(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update update_subnet_replica_version"]
fn update_subnet_replica_version() {
    check_caller_is_governance_and_log("update_subnet_replica_version");
    over(candid_one, |payload: UpdateSubnetReplicaVersionPayload| {
        registry_mut().do_update_subnet_replica_version(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update update_icp_xdr_conversion_rate"]
fn update_icp_xdr_conversion_rate() {
    check_caller_is_governance_and_log("update_icp_xdr_conversion_rate");
    over(candid_one, |payload: UpdateIcpXdrConversionRatePayload| {
        registry_mut().do_update_icp_xdr_conversion_rate(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update add_node"]
fn add_node() {
    // This method can be called by anyone
    println!(
        "{}call: {} from: {}",
        LOG_PREFIX,
        "add_node".to_string(),
        dfn_core::api::caller()
    );
    over_may_reject(candid_one, |payload: AddNodePayload| {
        let result = registry_mut().do_add_node(payload);
        recertify_registry();
        result
    });
}

#[export_name = "canister_update add_node_operator"]
fn add_node_operator() {
    check_caller_is_governance_and_log("add_node_operator");
    over(candid_one, |payload: AddNodeOperatorPayload| {
        registry_mut().do_add_node_operator(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update create_subnet"]
fn create_subnet() {
    check_caller_is_governance_and_log("create_subnet");
    over_async(candid_one, |payload: CreateSubnetPayload| async move {
        registry_mut().do_create_subnet(payload).await;
        recertify_registry();
    });
}

#[export_name = "canister_update add_nodes_to_subnet"]
fn add_nodes_to_subnet() {
    check_caller_is_governance_and_log("add_nodes_to_subnet");
    over(candid_one, |payload: AddNodesToSubnetPayload| {
        registry_mut().do_add_nodes_to_subnet(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update recover_subnet"]
fn recover_subnet() {
    check_caller_is_governance_and_log("recover_subnet");
    over_async(candid_one, |payload: RecoverSubnetPayload| async move {
        registry_mut().do_recover_subnet(payload).await;
        recertify_registry();
    });
}

#[export_name = "canister_update remove_nodes_from_subnet"]
fn remove_nodes_from_subnet() {
    check_caller_is_governance_and_log("remove_nodes_from_subnet");
    over(candid_one, |payload: RemoveNodesFromSubnetPayload| {
        registry_mut().do_remove_nodes_from_subnet(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update remove_nodes"]
fn remove_nodes() {
    check_caller_is_governance_and_log("remove_nodes");
    over(candid_one, |payload: RemoveNodesPayload| {
        registry_mut().do_remove_nodes(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update remove_node_directly"]
fn remove_node_directly() {
    // This method can be called by anyone
    println!(
        "{}call: {} from: {}",
        LOG_PREFIX,
        "remove_node_directly".to_string(),
        dfn_core::api::caller()
    );
    over(candid_one, |payload: RemoveNodeDirectlyPayload| {
        registry_mut().do_remove_node_directly(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update update_node_operator_config"]
fn update_node_operator_config() {
    check_caller_is_governance_and_log("update_node_operator_config");
    over(candid_one, |payload: UpdateNodeOperatorConfigPayload| {
        registry_mut().do_update_node_operator_config(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update update_subnet"]
fn update_subnet() {
    check_caller_is_governance_and_log("update_subnet");
    over(candid_one, |payload: UpdateSubnetPayload| {
        registry_mut().do_update_subnet(payload);
        recertify_registry();
    });
}

#[export_name = "canister_update clear_provisional_whitelist"]
fn clear_provisional_whitelist() {
    check_caller_is_governance_and_log("clear_provisional_whitelist");
    over(candid, |_: ()| {
        registry_mut().do_clear_provisional_whitelist();
        recertify_registry();
    });
}

#[export_name = "canister_update set_firewall_config"]
fn set_firewall_config() {
    check_caller_is_governance_and_log("set_firewall_config");
    over(candid_one, |payload: SetFirewallConfigPayload| {
        registry_mut().do_set_firewall_config(payload);
        recertify_registry();
    });
}

fn recertify_registry() {
    let witness_generator = witness_generator_mut();
    *witness_generator = registry_canister::certification::rebuild_tree(&*registry());
    set_certified_data(&witness_generator.hash_tree().digest().0[..]);
}

fn certified_response(data_tree: &LabeledTree<Vec<u8>>) -> CertifiedResponse {
    let hash_tree = witness_generator()
        .mixed_hash_tree(&data_tree)
        .expect("failed to produce a hash tree");

    CertifiedResponse {
        hash_tree: Some(hash_tree.into()),
        certificate: data_certificate().unwrap(),
    }
}
