use crate::builder::CompliantRegistryMutationsBuilder;

#[test]
fn creating_node_operator_creates_dc_and_np() {
    let builder =
        CompliantRegistryMutationsBuilder::default().with_operator("operator", "dc", "provider");

    let mutations = builder.build();

    mutations.provider_id("provider");
    assert!(mutations.dcs().contains("dc"), "Expected compliatn registry to contain data center `dc` but it didnt. The list of found data center ids: {:?}", mutations.dcs())
}

#[test]
#[should_panic]
fn operator_defition_missing() {
    CompliantRegistryMutationsBuilder::default()
        .with_node("operator", "node", None)
        .build();
}

#[test]
fn adding_node_should_add_subnet() {
    let mutations = CompliantRegistryMutationsBuilder::default()
        .with_operator("operator", "dc", "provider")
        .with_node("operator", "node", Some("subnet"))
        .build();

    // Will panic internally if it doesn't exist
    let _subnet = mutations.subnet_id("subnet");
    let operator = mutations.operator("operator");
    let node = mutations.node("node");

    assert_eq!(
        node.operator, operator.id,
        "Expected node to be related to the operator, but it isn't"
    )
}
