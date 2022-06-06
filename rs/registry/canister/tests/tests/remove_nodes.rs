use std::convert::TryFrom;

use candid::Encode;
use dfn_candid::candid;

use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::registry::{
    get_committee_signing_key, get_dkg_dealing_key, get_idkg_dealing_encryption_key,
    get_node_operator_record, get_node_record, get_node_signing_key, get_transport_tls_certificate,
};
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value_or_panic, prepare_registry, TEST_ID},
};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::{
    node::v1::{connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord},
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::SubnetRecord,
};
use ic_registry_keys::{
    make_crypto_node_key, make_node_operator_record_key, make_node_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_test_utilities::types::ids::{node_test_id, user_test_id};
use ic_types::crypto::KeyPurpose;
use ic_types::NodeId;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::node_management::common::make_add_node_registry_mutations;
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
                            make_node_operator_record_key(user_test_id(NO_ID).get()).as_bytes(),
                            encode_or_panic(&node_operator),
                        ),
                        insert(
                            make_node_operator_record_key(user_test_id(TEST_ID).get()).as_bytes(),
                            encode_or_panic(&node_operator2),
                        ),
                        insert(
                            make_node_record_key(node_test_id(NO_ID)).as_bytes(),
                            encode_or_panic(&node1),
                        ),
                        insert(
                            make_node_record_key(node_test_id(NO_ID + 1)).as_bytes(),
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
            let node_record = get_node_record(&registry, node_id).await;
            assert!(node_record.is_some());
        }

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
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
            let node_record = get_node_record(&registry, node_id).await;
            assert!(node_record.is_none());
        }

        // Ensure the node operator's allowance is incremented correctly (starts off as
        // 2, and should have 3 added)
        let node_operator_record = get_node_operator_record(&registry, user_test_id(NO_ID).get())
            .await
            .unwrap();
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
fn remove_nodes_succeeds_with_missing_encryption_keys_in_registry() {
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

        let node_dkg_key = PublicKey {
            version: 0,
            algorithm: 0,
            key_value: vec![1, 2, 3, 4],
            proof_data: None,
        };

        let (init_mutation, _, mut nodes_to_remove, _) = prepare_registry(1, NUM_NODES.into());

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(init_mutation)
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        insert(
                            make_node_operator_record_key(user_test_id(NO_ID).get()).as_bytes(),
                            encode_or_panic(&node_operator),
                        ),
                        insert(
                            make_node_operator_record_key(user_test_id(TEST_ID).get()).as_bytes(),
                            encode_or_panic(&node_operator2),
                        ),
                        insert(
                            make_node_record_key(node_test_id(NO_ID)).as_bytes(),
                            encode_or_panic(&node),
                        ),
                        insert(
                            make_crypto_node_key(
                                node_test_id(NO_ID),
                                KeyPurpose::DkgDealingEncryption,
                            ),
                            encode_or_panic(&node_dkg_key),
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
            let node_record = get_node_record(&registry, node_id).await;
            let node_signing_key = get_node_signing_key(&registry, node_id).await;
            let committee_signing_key = get_committee_signing_key(&registry, node_id).await;
            let dkg_dealing_key = get_dkg_dealing_key(&registry, node_id).await;
            let transport_tls_cert = get_transport_tls_certificate(&registry, node_id).await;
            let idkg_dealing_encryption_key =
                get_idkg_dealing_encryption_key(&registry, node_id).await;
            assert!(node_record.is_some());
            assert!(dkg_dealing_key.is_some());
            // Ensure some keys are missing to make sure we can delete nodes that do not yet have idkg (or other) key set
            assert!(node_signing_key.is_none());
            assert!(committee_signing_key.is_none());
            assert!(transport_tls_cert.is_none());
            assert!(idkg_dealing_encryption_key.is_none());
        }

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
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
            let node_record = get_node_record(&registry, node_id).await;
            assert!(node_record.is_none());
        }

        // Ensure the node operator's allowance is incremented correctly (starts off as
        // 5, and should have 4 added)
        let node_operator_record = get_node_operator_record(&registry, user_test_id(TEST_ID).get())
            .await
            .unwrap();
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_allowance: 9,
                ..Default::default()
            }
        );

        // Ensure the node operator's allowance is incremented correctly (starts off as
        // 2, and should have 1 added)
        let node_operator_record = get_node_operator_record(&registry, user_test_id(NO_ID).get())
            .await
            .unwrap();
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
fn remove_nodes_removes_all_keys() {
    local_test_on_nns_subnet(|runtime| async move {
        let node_operator = NodeOperatorRecord {
            node_allowance: 2,
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
        let (init_mutation, _, _, _) = prepare_registry(1, NUM_NODES.into());
        let mut nodes_to_remove = vec![];

        let (keys, node_id) = get_node_keys_or_generate_if_missing(temp_dir().path());
        let valid_keys = ValidNodePublicKeys::try_from(&keys, node_id).unwrap();

        // Add the node along with keys and certs
        let mut mutations = make_add_node_registry_mutations(node_id, node, valid_keys);
        // Add node operator records
        mutations.push(insert(
            make_node_operator_record_key(user_test_id(NO_ID).get()).as_bytes(),
            encode_or_panic(&node_operator),
        ));

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(init_mutation)
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations,
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        nodes_to_remove.push(node_id);

        // Ensure there is a value for each of the nodes and encryption keys
        for node_id in nodes_to_remove.clone() {
            let node_record = get_node_record(&registry, node_id).await;
            let node_signing_key = get_node_signing_key(&registry, node_id).await;
            let committee_signing_key = get_committee_signing_key(&registry, node_id).await;
            let dkg_dealing_key = get_dkg_dealing_key(&registry, node_id).await;
            let transport_tls_cert = get_transport_tls_certificate(&registry, node_id).await;
            let idkg_dealing_encryption_key =
                get_idkg_dealing_encryption_key(&registry, node_id).await;
            assert!(node_record.is_some());
            assert!(node_signing_key.is_some());
            assert!(committee_signing_key.is_some());
            assert!(dkg_dealing_key.is_some());
            assert!(transport_tls_cert.is_some());
            assert!(idkg_dealing_encryption_key.is_some());
        }

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
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

        // Ensure there is no value for the each of the nodes and encryption keys
        for node_id in nodes_to_remove {
            let node_record = get_node_record(&registry, node_id).await;
            let node_signing_key = get_node_signing_key(&registry, node_id).await;
            let committee_signing_key = get_committee_signing_key(&registry, node_id).await;
            let dkg_dealing_key = get_dkg_dealing_key(&registry, node_id).await;
            let transport_tls_cert = get_transport_tls_certificate(&registry, node_id).await;
            let idkg_dealing_encryption_key =
                get_idkg_dealing_encryption_key(&registry, node_id).await;
            assert!(node_record.is_none());
            assert!(node_signing_key.is_none());
            assert!(committee_signing_key.is_none());
            assert!(dkg_dealing_key.is_none());
            assert!(transport_tls_cert.is_none());
            assert!(idkg_dealing_encryption_key.is_none());
        }

        // Ensure the node operator's allowance is incremented correctly (starts off as
        // 2, and should have 1 added)
        let node_operator_record = get_node_operator_record(&registry, user_test_id(NO_ID).get())
            .await
            .unwrap();
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
            let node_record = get_node_record(&registry, node_id).await;
            assert!(node_record.is_some());
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
            let node_record = get_node_record(&registry, node_id).await;
            assert!(node_record.is_some());
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
            make_node_operator_record_key(user_test_id(TEST_ID).get()).as_bytes(),
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

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // Add the assigned nodes to the list of nodes to be removed
        let subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
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
        let node_operator_record = get_node_operator_record(&registry, user_test_id(TEST_ID).get())
            .await
            .unwrap();
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
