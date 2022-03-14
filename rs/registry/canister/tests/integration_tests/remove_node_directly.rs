use dfn_candid::candid;
use ic_base_types::{PrincipalId, SubnetId};
use ic_canister_client::Sender;
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_keys::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, set_up_registry_canister},
    registry::{get_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::pb::v1::{
    registry_mutation, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_types::p2p::build_default_gossip_config;
use ic_types::NodeId;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_add_node::{connection_endpoint_from_string, flow_endpoint_from_string},
        do_remove_node_directly::RemoveNodeDirectlyPayload,
    },
};

const TEST_NODE_ALLOWANCE: u64 = 5;

#[test]
fn node_is_removed_on_receiving_the_request() {
    local_test_on_nns_subnet(|runtime| async move {
        let test_node_record = NodeRecord {
            node_operator_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string(
                &("128.0.0.1:1234".to_string()),
            )),
            http: Some(connection_endpoint_from_string(
                &("128.0.0.1:1234".to_string()),
            )),
            p2p_flow_endpoints: vec!["123,128.0.0.1:10000"]
                .iter()
                .map(|x| flow_endpoint_from_string(x))
                .collect(),
            ..Default::default()
        };
        let (node_id, mutation) = init_mutation(&test_node_record);
        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(mutation)
                .build(),
        )
        .await;

        // Ensure there is a value for the node
        let node_record =
            get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
        assert_eq!(node_record, test_node_record);

        let response: Result<(), String> = registry
            .update_from_sender(
                "remove_node_directly",
                candid,
                (prepare_payload(node_id),),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // Ensure the value for the node was removed
        let node_record =
            get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
        assert_eq!(node_record, NodeRecord::default());

        // Ensure the node operator's allowance is incremented correctly
        let node_operator_record = get_value::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: TEST_NODE_ALLOWANCE + 1,
                ..Default::default()
            }
        );

        Ok(())
    });
}

#[test]
fn node_cannot_be_removed_by_non_node_operator() {
    local_test_on_nns_subnet(|runtime| async move {
        let test_node_record = NodeRecord {
            node_operator_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string(
                &("128.0.0.1:1234".to_string()),
            )),
            http: Some(connection_endpoint_from_string(
                &("128.0.0.1:1234".to_string()),
            )),
            p2p_flow_endpoints: vec!["123,128.0.0.1:10000"]
                .iter()
                .map(|x| flow_endpoint_from_string(x))
                .collect(),
            ..Default::default()
        };
        let (node_id, mutation) = init_mutation(&test_node_record);
        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(mutation)
                .build(),
        )
        .await;

        // Anonymous call fails
        let response: Result<(), String> = registry
            .update_("remove_node_directly", candid, (prepare_payload(node_id),))
            .await;
        assert!(response.is_err());

        Ok(())
    });
}

#[test]
fn node_cannot_be_removed_if_in_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        let test_node_record = NodeRecord {
            node_operator_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string(
                &("128.0.0.1:1234".to_string()),
            )),
            http: Some(connection_endpoint_from_string(
                &("128.0.0.1:1234".to_string()),
            )),
            p2p_flow_endpoints: vec!["123,128.0.0.1:10000"]
                .iter()
                .map(|x| flow_endpoint_from_string(x))
                .collect(),
            ..Default::default()
        };
        let (node_id, mutation) = init_mutation(&test_node_record);
        // Any Principal can be used here
        let test_subnet_id = SubnetId::from(*TEST_NEURON_1_OWNER_PRINCIPAL);
        let test_subnet_record = SubnetRecord {
            membership: vec![node_id.get().to_vec()],
            replica_version_id: "version_42".to_string(),
            unit_delay_millis: 600,
            gossip_config: Some(build_default_gossip_config()),
            ..Default::default()
        };
        let test_subnet_list_record = SubnetListRecord {
            subnets: vec![
                SubnetId::from(PrincipalId::new_subnet_test_id(999))
                    .get()
                    .to_vec(),
                test_subnet_id.get().to_vec(),
            ],
        };
        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(mutation)
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        // Insert Subnet record
                        RegistryMutation {
                            mutation_type: registry_mutation::Type::Insert as i32,
                            key: make_subnet_record_key(test_subnet_id).as_bytes().to_vec(),
                            value: encode_or_panic(&test_subnet_record),
                        },
                        // Overwrite Subnet List
                        RegistryMutation {
                            mutation_type: registry_mutation::Type::Update as i32,
                            key: make_subnet_list_record_key().as_bytes().to_vec(),
                            value: encode_or_panic(&test_subnet_list_record),
                        },
                    ],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Call fails as the node is still in a subnet
        let response: Result<(), String> = registry
            .update_from_sender(
                "remove_node_directly",
                candid,
                (prepare_payload(node_id),),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_err());

        // Ensure the node operator's allowance is not incremented
        let node_operator_record = get_value::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: TEST_NODE_ALLOWANCE,
                ..Default::default()
            }
        );

        Ok(())
    });
}

fn init_mutation(node_record: &NodeRecord) -> (NodeId, RegistryAtomicMutateRequest) {
    let temp_dir = temp_dir();
    let (_, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());

    (
        node_id,
        RegistryAtomicMutateRequest {
            mutations: vec![
                // Insert the Node record
                RegistryMutation {
                    mutation_type: registry_mutation::Type::Insert as i32,
                    key: make_node_record_key(node_id).as_bytes().to_vec(),
                    value: encode_or_panic(node_record),
                },
                // Insert the Node's NO
                RegistryMutation {
                    mutation_type: registry_mutation::Type::Insert as i32,
                    key: make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL)
                        .as_bytes()
                        .to_vec(),
                    value: encode_or_panic(&NodeOperatorRecord {
                        node_allowance: TEST_NODE_ALLOWANCE,
                        ..Default::default()
                    }),
                },
            ],
            preconditions: vec![],
        },
    )
}

fn prepare_payload(node_id: NodeId) -> RemoveNodeDirectlyPayload {
    RemoveNodeDirectlyPayload { node_id }
}
