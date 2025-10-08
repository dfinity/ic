use std::collections::BTreeMap;

use common::test_helpers::install_registry_canister_with_payload_builder;
use ic_base_types::PrincipalId;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::swap_node_in_subnet_directly;
use ic_nns_test_utils::registry::{
    create_subnet_threshold_signing_pubkey_and_cup_mutations,
    invariant_compliant_mutation_as_atomic_req,
};
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord, SubnetType},
};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_transport::{
    pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
    upsert,
};
use ic_types::{NodeId, ReplicaVersion, SubnetId};
use pocket_ic::PocketIcBuilder;
use prost::Message;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_swap_node_in_subnet_directly::{SwapError, SwapNodeInSubnetDirectlyPayload},
        node_management::{
            common::make_add_node_registry_mutations, do_add_node::connection_endpoint_from_string,
        },
    },
};

use crate::common::test_helpers::install_registry_canister;
mod common;

// This test ensures that we are not enabling this feature on any network until it
// is fully implemented.
//
// TODO(DRE-551): adapt the logic of the test to not fail if the feature is enabled.
#[tokio::test]
async fn ensure_feature_is_turned_off() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    install_registry_canister(&pocket_ic).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(PrincipalId::new_node_test_id(2)),
        },
        PrincipalId::new_user_test_id(1),
    )
    .await;

    assert!(response.is_err_and(|err| {
        err.reject_message
            .contains(&format!("{}", SwapError::FeatureDisabled))
    }))
}
struct NodeInformation {
    subnet_id: Option<SubnetId>,
    operator: PrincipalId,
}

fn get_mutations_and_node_ids(
    node_information: &[NodeInformation],
) -> (Vec<RegistryMutation>, Vec<NodeId>) {
    let mut mutations = invariant_compliant_mutation_as_atomic_req(0).mutations;
    let mut subnets = BTreeMap::new();

    let mut nodes = vec![];

    for (ind, node) in node_information.iter().enumerate() {
        let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
        let valid_keys = generate_node_keys_once(&config, None).unwrap();
        if let Some(subnet) = node.subnet_id {
            subnets
                .entry(subnet)
                .or_insert(vec![])
                .push(valid_keys.clone());
        }
        nodes.push(valid_keys.node_id());

        mutations.extend(make_add_node_registry_mutations(
            valid_keys.node_id(),
            NodeRecord {
                node_operator_id: node.operator.to_vec(),
                xnet: Some(connection_endpoint_from_string(&format!(
                    "192.168.{ind}.1:1234"
                ))),
                http: Some(connection_endpoint_from_string(&format!(
                    "192.168.{ind}.1:1235"
                ))),
                ..Default::default()
            },
            valid_keys,
        ));
    }

    for (subnet, valid_keys) in &subnets {
        mutations.push(upsert(
            make_subnet_record_key(*subnet),
            SubnetRecord {
                membership: valid_keys
                    .iter()
                    .map(|vk| vk.node_id().get().to_vec())
                    .collect(),
                replica_version_id: ReplicaVersion::default().to_string(),
                subnet_type: SubnetType::System as i32,
                ..Default::default()
            }
            .encode_to_vec(),
        ));

        let mut receiver_keys = BTreeMap::new();
        for key in valid_keys {
            receiver_keys.insert(key.node_id(), key.dkg_dealing_encryption_key().clone());
        }
        let threshold_pk_and_cup_mutations =
            create_subnet_threshold_signing_pubkey_and_cup_mutations(*subnet, &receiver_keys);
        mutations.extend(threshold_pk_and_cup_mutations);
    }

    mutations.push(upsert(
        make_subnet_list_record_key(),
        SubnetListRecord {
            subnets: subnets.keys().map(|k| k.get().to_vec()).collect(),
        }
        .encode_to_vec(),
    ));

    (mutations, nodes)
}

#[tokio::test]
async fn caller_not_whitelisted() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
    let operator_id = PrincipalId::new_user_test_id(1);

    let (mutations, nodes) = get_mutations_and_node_ids(&[
        // Old node id
        NodeInformation {
            subnet_id: Some(subnet_id),
            operator: operator_id,
        },
        // New node id
        NodeInformation {
            subnet_id: None,
            operator: operator_id,
        },
    ]);

    let old_node_id = nodes[0];
    let new_node_id = nodes[1];

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });
    builder.enable_swapping_feature_globally();
    builder.enable_swapping_feature_for_subnet(subnet_id);

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(new_node_id.get()),
            old_node_id: Some(old_node_id.get()),
        },
        operator_id,
    )
    .await;

    let expected_err = SwapError::FeatureDisabledForCaller {
        caller: operator_id,
    };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    )
}

#[tokio::test]
async fn subnet_not_whitelisted() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
    let operator_id = PrincipalId::new_user_test_id(1);

    let (mutations, nodes) = get_mutations_and_node_ids(&[
        // Old node id
        NodeInformation {
            subnet_id: Some(subnet_id),
            operator: operator_id,
        },
        // New node id
        NodeInformation {
            subnet_id: None,
            operator: operator_id,
        },
    ]);

    let old_node_id = nodes[0];
    let new_node_id = nodes[1];

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });

    builder.enable_swapping_feature_globally();
    builder.whitelist_swapping_feature_caller(operator_id);

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(new_node_id.get()),
            old_node_id: Some(old_node_id.get()),
        },
        operator_id,
    )
    .await;

    let expected_err = SwapError::FeatureDisabledOnSubnet { subnet_id };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    )
}

#[tokio::test]
async fn e2e_valid_swap() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
    let operator_id = PrincipalId::new_user_test_id(1);

    let (mutations, nodes) = get_mutations_and_node_ids(&[
        // Old node id
        NodeInformation {
            subnet_id: Some(subnet_id),
            operator: operator_id,
        },
        // New node id
        NodeInformation {
            subnet_id: None,
            operator: operator_id,
        },
    ]);

    let old_node_id = nodes[0];
    let new_node_id = nodes[1];

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });

    builder.enable_swapping_feature_globally();
    builder.whitelist_swapping_feature_caller(operator_id);
    builder.enable_swapping_feature_for_subnet(subnet_id);

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(new_node_id.get()),
            old_node_id: Some(old_node_id.get()),
        },
        operator_id,
    )
    .await;

    assert!(response.is_ok(), "Expected ok but got {response:?}")
}
