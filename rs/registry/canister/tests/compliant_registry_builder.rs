use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::get_value;
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::pb::v1::HighCapacityRegistryGetValueResponse;
use ic_types::{NodeId, PrincipalId, SubnetId};
use pocket_ic::PocketIcBuilder;
use test_registry_builder::builder::CompliantRegistryMutationsBuilder;

use crate::common::{
    test_helpers::install_registry_canister_with_payload_builder, IntoInitPayload,
};

mod common;

fn unwrap_content<C: prost::Message + Default>(
    response: HighCapacityRegistryGetValueResponse,
) -> C {
    let content = match response.content.unwrap() {
        ic_registry_transport::pb::v1::high_capacity_registry_get_value_response::Content::Value(items) => items,
        ic_registry_transport::pb::v1::high_capacity_registry_get_value_response::Content::LargeValueChunkKeys(_) => panic!("Didn't expect to receive large value chunk keys"),
    };

    C::decode(content.as_slice()).unwrap()
}

#[tokio::test]
async fn ensure_compliant_registry() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let compliant_registry_mutations = CompliantRegistryMutationsBuilder::default()
        .with_operator("operator", "dc", "provider")
        .with_node("node", "operator", Some("subnet"))
        .build();

    let init_payload = compliant_registry_mutations.into_payload();
    install_registry_canister_with_payload_builder(&pocket_ic, init_payload, false).await;

    // Ensure that the there are two sunbets NNS and the one we added
    let response = get_value(&pocket_ic, make_subnet_list_record_key(), None)
        .await
        .unwrap();

    let subnet_list: SubnetListRecord = unwrap_content(response);

    assert_eq!(
        subnet_list.subnets.len(),
        2,
        "Expected to have two subnets in compliant registry, instead got {}",
        subnet_list.subnets.len(),
    );

    // Ensure that one of those subnets is the one we configured
    let configured_subnet_id = compliant_registry_mutations.subnet_id("subnet");

    let subnets: Vec<_> = subnet_list
        .subnets
        .into_iter()
        .map(|key| SubnetId::new(PrincipalId::try_from(key).unwrap()))
        .collect();

    assert!(
        subnets.iter().any(|s| *s == configured_subnet_id),
        "Expected to find {configured_subnet_id} in {subnets:?}"
    );

    // Ensure that the configured operator is there
    let configured_operator = compliant_registry_mutations.operator("operator");
    let response = get_value(
        &pocket_ic,
        make_node_operator_record_key(configured_operator.id),
        None,
    )
    .await
    .unwrap();

    let operator: NodeOperatorRecord = unwrap_content(response);

    assert_eq!(
        configured_operator.dc_id, operator.dc_id,
        "Expected configured node operator to have {} but got {}",
        configured_operator.dc_id, operator.dc_id
    );

    let provider = PrincipalId::try_from(operator.node_provider_principal_id).unwrap();
    assert_eq!(
        configured_operator.provider, provider,
        "Expected configured node operator to be related to provider {provider} but got {}",
        configured_operator.provider
    );

    // Ensure that the node is configured properly
    let configured_node = compliant_registry_mutations.node("node");

    let response = get_value(&pocket_ic, make_node_record_key(configured_node.id), None)
        .await
        .unwrap();

    let node_record: NodeRecord = unwrap_content(response);
    let node_operator_from_rec = PrincipalId::try_from(node_record.node_operator_id).unwrap();

    assert_eq!(
        configured_node.operator, node_operator_from_rec,
        "Expected configured operator for a node to be {} but got {node_operator_from_rec}",
        configured_node.operator
    );

    // Ensure that the node is in the correct subnet
    let subnet_id = compliant_registry_mutations.subnet_id("subnet");

    let response = get_value(&pocket_ic, make_subnet_record_key(subnet_id), None)
        .await
        .unwrap();

    let subnet_record: SubnetRecord = unwrap_content(response);

    let nodes_from_subnet: Vec<_> = subnet_record
        .membership
        .iter()
        .map(|n| NodeId::new(PrincipalId::try_from(n).unwrap()))
        .collect();

    assert!(
        nodes_from_subnet.len() == 1,
        "Expected only one node in configured subnet but got {}",
        nodes_from_subnet.len()
    );

    let node_id_from_subnet = nodes_from_subnet.first().unwrap();
    assert_eq!(
        configured_node.id, *node_id_from_subnet,
        "Expected to find {} id in subnet {subnet_id} but found {node_id_from_subnet}",
        configured_node.id
    );
}
