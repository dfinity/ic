use candid::{Decode, Encode};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_test_utils::registry::{
    invariant_compliant_mutation_as_atomic_req, prepare_add_node_payload,
};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_state_machine_tests::StateMachineBuilder;
use ic_types::NodeId;
use registry_canister::mutations::node_management::do_remove_node_directly::RemoveNodeDirectlyPayload;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_add_node_operator::AddNodeOperatorPayload,
};

/// StateMachine test that verifies rate limiting works correctly for node operator operations
#[test]
fn test_rate_limiting_state_machine() {
    let env = StateMachineBuilder::new().with_current_time().build();

    // Set up registry canister with initial data
    let init_payload = RegistryCanisterInitPayloadBuilder::new()
        .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
        .build();

    let registry_canister_id = env
        .install_canister(
            ic_nns_test_utils::common::build_registry_wasm().bytes(),
            Encode!(&init_payload).unwrap(),
            None,
        )
        .unwrap();

    let node_operator = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let node_provider = *TEST_NEURON_1_OWNER_PRINCIPAL;

    // Add node operator directly to registry
    let add_node_operator_payload = AddNodeOperatorPayload {
        node_operator_principal_id: Some(node_operator),
        node_provider_principal_id: Some(node_provider),
        node_allowance: 0,
        dc_id: "test_dc".to_string(),
        rewardable_nodes: std::collections::BTreeMap::from([("type1".to_string(), 1)]),
        ipv6: None,
        max_rewardable_nodes: Some(std::collections::BTreeMap::from([(
            "type1".to_string(),
            10,
        )])),
    };

    // Add node operator directly
    env.execute_ingress_as(
        GOVERNANCE_CANISTER_ID.get(),
        registry_canister_id,
        "add_node_operator",
        Encode!(&add_node_operator_payload).unwrap(),
    )
    .unwrap();

    // Starting at 1 since the `invariant_compliant_mutation_as_atomic_req` to setup the registry
    // initializes a node with the same IP address as `prepare_add_node_payload(0)`.
    let mut next_add_node_payload_id = 1;
    let mut next_add_node_payload = || {
        let (payload, _) =
            prepare_add_node_payload(next_add_node_payload_id, NodeRewardType::Type1);
        next_add_node_payload_id += 1;
        payload
    };

    for _ in 0..70 {
        // Create a simple add_node payload for testing with unique IP addresses
        let add_node_payload = next_add_node_payload(); // Use unique IDs

        let node_id: NodeId = env
            .execute_ingress_as(
                node_operator,
                registry_canister_id,
                "add_node",
                Encode!(&add_node_payload).unwrap(),
            )
            .map(|result| Decode!(&result.bytes(), NodeId).unwrap())
            .unwrap();

        let remove_node_payload = RemoveNodeDirectlyPayload { node_id };

        env.execute_ingress_as(
            node_operator,
            registry_canister_id,
            "remove_node_directly",
            Encode!(&remove_node_payload).unwrap(),
        )
        .unwrap();
    }

    let add_node_payload = next_add_node_payload();
    let error = env
        .execute_ingress_as(
            node_operator,
            registry_canister_id,
            "add_node",
            Encode!(&add_node_payload).unwrap(),
        )
        .map(|result| Decode!(&result.bytes(), NodeId).unwrap())
        .unwrap_err();

    assert!(error.description().contains("Rate Limit Capacity exceeded"));
}
