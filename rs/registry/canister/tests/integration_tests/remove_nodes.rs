use std::convert::TryFrom;

use candid::Encode;
use dfn_candid::candid;

use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, prepare_registry, TEST_ID},
};
use ic_protobuf::registry::{
    node::v1::{connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord},
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::SubnetRecord,
};
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_record_key,
};
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_test_utilities::types::ids::{node_test_id, user_test_id};
use ic_types::NodeId;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::node_management::do_remove_nodes::RemoveNodesPayload;

const NUM_NODES: u8 = 4;
const NO_ID: u64 = 990;

#[test]
fn remove_nodes_with_duplicate_endpoints_succeeds() {
    local_test_on_nns_subnet(|runtime| async move {
        let node_operator = NodeOperatorRecord {
            node_allowance: 2,
            ..Default::default()
        };
        let node_operator2 = NodeOperatorRecord {
            node_allowance: 5,
            ..Default::default()
        };
        let connection_endpoint = ConnectionEndpoint {
            ip_addr: "129.0.0.1".to_string(),
            port: 12345,
            protocol: Protocol::Http1 as i32,
        };
        let node1 = NodeRecord {
            node_operator_id: user_test_id(NO_ID).get().to_vec(),
            xnet: Some(connection_endpoint.clone()),
            http: Some(connection_endpoint.clone()),
            ..Default::default()
        };
        let node2 = NodeRecord {
            node_operator_id: user_test_id(NO_ID).get().to_vec(),
            xnet: Some(connection_endpoint.clone()),
            http: Some(connection_endpoint.clone()),
            ..Default::default()
        };
        let (init_mutation, _, mut nodes_to_remove, _) = prepare_registry(1, NUM_NODES.into());
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(init_mutation)
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        insert(
                            make_node_operator_record_key(user_test_id(NO_ID).get())
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&node_operator),
                        ),
                        insert(
                            make_node_operator_record_key(user_test_id(TEST_ID).get())
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&node_operator2),
                        ),
                        insert(
                            make_node_record_key(node_test_id(NO_ID))
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&node1),
                        ),
                        insert(
                            make_node_record_key(node_test_id(NO_ID + 1))
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&node2),
                        ),
                    ],

                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        nodes_to_remove.push(node_test_id(NO_ID));
        nodes_to_remove.push(node_test_id(NO_ID + 1));

        // Ensure there is a value for each of the nodes
        for node_id in nodes_to_remove.clone() {
            let node_record =
                get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
            assert_ne!(node_record, NodeRecord::default());
        }

        // Install the universal canister in place of the proposals canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "remove_nodes",
                Encode!(&prepare_payload(nodes_to_remove.clone())).unwrap()
            )
            .await
        );

        // Ensure there is no value for the each of the nodes
        for node_id in nodes_to_remove {
            let node_record =
                get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
            assert_eq!(node_record, NodeRecord::default());
        }

        // Ensure the node operator's allowance is incremented correctly (starts off as
        // 2, and should have 3 added)
        let node_operator_record = get_value::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(user_test_id(NO_ID).get()).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: 4,
                ..Default::default()
            }
        );

        Ok(())
    });
}

#[test]
fn remove_nodes_succeeds() {
    local_test_on_nns_subnet(|runtime| async move {
        let node_operator = NodeOperatorRecord {
            node_allowance: 2,
            ..Default::default()
        };
        let node_operator2 = NodeOperatorRecord {
            node_allowance: 5,
            ..Default::default()
        };
        let connection_endpoint = ConnectionEndpoint {
            ip_addr: "129.0.0.1".to_string(),
            port: 12345,
            protocol: Protocol::Http1 as i32,
        };
        let node = NodeRecord {
            node_operator_id: user_test_id(NO_ID).get().to_vec(),
            xnet: Some(connection_endpoint.clone()),
            http: Some(connection_endpoint),
            ..Default::default()
        };
        let (init_mutation, _, mut nodes_to_remove, _) = prepare_registry(1, NUM_NODES.into());

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(init_mutation)
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        insert(
                            make_node_operator_record_key(user_test_id(NO_ID).get())
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&node_operator),
                        ),
                        insert(
                            make_node_operator_record_key(user_test_id(TEST_ID).get())
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&node_operator2),
                        ),
                        insert(
                            make_node_record_key(node_test_id(NO_ID))
                                .as_bytes()
                                .to_vec(),
                            encode_or_panic(&node),
                        ),
                    ],

                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        nodes_to_remove.push(node_test_id(NO_ID));

        // Ensure there is a value for each of the nodes
        for node_id in nodes_to_remove.clone() {
            let node_record =
                get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
            assert_ne!(node_record, NodeRecord::default());
        }

        // Install the universal canister in place of the proposals canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "remove_nodes",
                Encode!(&prepare_payload(nodes_to_remove.clone())).unwrap()
            )
            .await
        );

        // Ensure there is no value for the each of the nodes
        for node_id in nodes_to_remove {
            let node_record =
                get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
            assert_eq!(node_record, NodeRecord::default());
        }

        // Ensure the node operator's allowance is incremented correctly (starts off as
        // 5, and should have 4 added)
        let node_operator_record = get_value::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(user_test_id(TEST_ID).get()).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: 9,
                ..Default::default()
            }
        );

        // Ensure the node operator's allowance is incremented correctly (starts off as
        // 2, and should have 1 added)
        let node_operator_record = get_value::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(user_test_id(NO_ID).get()).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: 3,
                ..Default::default()
            }
        );

        Ok(())
    });
}

#[test]
fn remove_nodes_fails_with_non_governance_caller() {
    local_test_on_nns_subnet(|runtime| async move {
        let (init_mutation, _, nodes_to_remove, _) = prepare_registry(1, NUM_NODES.into());
        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(init_mutation)
                .build(),
        )
        .await;

        // Anonymous call fails
        let response: Result<(), String> = registry
            .update_(
                "remove_nodes",
                candid,
                (prepare_payload(nodes_to_remove.clone()),),
            )
            .await;
        assert!(response.is_err());

        // Ensure there is still a value for each of the nodes
        for node_id in nodes_to_remove.clone() {
            let node_record =
                get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
            assert_ne!(node_record, NodeRecord::default());
        }

        // Non-governance user call fails
        let response: Result<(), String> = registry
            .update_from_sender(
                "remove_nodes",
                candid,
                (prepare_payload(nodes_to_remove.clone()),),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_err());

        // Ensure there is still a value for each of the nodes
        for node_id in nodes_to_remove.clone() {
            let node_record =
                get_value::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes()).await;
            assert_ne!(node_record, NodeRecord::default());
        }

        Ok(())
    });
}

#[test]
fn nodes_cannot_be_removed_if_any_in_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        let (mut init_mutation, subnet_id, mut nodes_to_remove, _) =
            prepare_registry(NUM_NODES.into(), 1);

        let node_operator = NodeOperatorRecord {
            node_allowance: 5,
            ..Default::default()
        };

        init_mutation.mutations.push(insert(
            make_node_operator_record_key(user_test_id(TEST_ID).get())
                .as_bytes()
                .to_vec(),
            encode_or_panic(&node_operator),
        ));

        // Prepare the registry with a single node and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(init_mutation)
                .build(),
        )
        .await;

        // Install the universal canister in place of the proposals canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // Add the assigned nodes to the list of nodes to be removed
        let subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                .await;
        nodes_to_remove.append(
            &mut subnet_record
                .membership
                .into_iter()
                .map(|node_vec| NodeId::from(PrincipalId::try_from(node_vec).unwrap()))
                .collect::<Vec<NodeId>>(),
        );

        // Call fails as some nodes are still in a subnet
        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "remove_nodes",
                Encode!(&prepare_payload(nodes_to_remove)).unwrap()
            )
            .await
        );

        // Ensure the node operator's allowance is not incremented
        let node_operator_record = get_value::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(user_test_id(TEST_ID).get()).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: 5,
                ..Default::default()
            }
        );

        Ok(())
    });
}

fn prepare_payload(node_ids: Vec<NodeId>) -> RemoveNodesPayload {
    RemoveNodesPayload { node_ids }
}
