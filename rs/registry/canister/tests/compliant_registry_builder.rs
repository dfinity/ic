use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::get_value;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::make_subnet_list_record_key;
use ic_registry_transport::pb::v1::HighCapacityRegistryGetValueResponse;
use ic_types::{PrincipalId, SubnetId};
use pocket_ic::PocketIcBuilder;
use registry_canister::init::RegistryCanisterInitPayload;
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
}
